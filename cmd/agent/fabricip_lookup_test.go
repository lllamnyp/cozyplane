package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type observedFabricIndexer struct {
	cache.Indexer
	lists, indexed, rows int
}

func TestFabricLookupIndexesFollowCurrentObjects(t *testing.T) {
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, fabricClaimIndexers())}
	v6 := lookupClaim("fd00::42", "wanted", "sandbox", "eth0")
	v4 := lookupClaim("192.0.2.12", "wanted", "sandbox", "eth0")
	for _, claim := range []*localv1.FabricIP{v6, v4} {
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
	}
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != v4.Spec.Address {
		t.Fatal("dual-stack lookup lost IPv4 preference", got)
	}
	if got := fabricClaimAddress(store, "wanted", "", ""); got != v4.Spec.Address {
		t.Fatal("legacy lookup lost Pod UID or family selection", got)
	}
	updated := v4.DeepCopy()
	updated.Spec.PodUID, updated.Spec.ContainerID = "replacement", "new-sandbox"
	if err := store.Update(updated); err != nil {
		t.Fatal(err)
	}
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != v6.Spec.Address {
		t.Fatal("updated claim remained in the old sandbox index", got)
	}
	if got := fabricClaimAddress(store, "replacement", "new-sandbox", "eth0"); got != v4.Spec.Address {
		t.Fatal("updated claim missing from current index", got)
	}
	for _, claim := range []*localv1.FabricIP{v6, updated} {
		if err := store.Delete(claim); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{fabricPodUIDIndex, fabricSandboxIndex} {
		if keys := store.ListIndexFuncValues(name); len(keys) != 0 {
			t.Fatal("deleted claims retained historical index values", keys)
		}
	}
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != "" || store.lists != 0 {
		t.Fatal("deleted claim or global fallback returned", got)
	}
	for i := range 1000 {
		claim := lookupClaim("192.0.2.15", fmt.Sprintf("pod-%d", i), fmt.Sprintf("sandbox-%d", i), "eth0")
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
		if got := fabricClaimAddress(store, claim.Spec.PodUID, claim.Spec.ContainerID, "eth0"); got != claim.Spec.Address {
			t.Fatal("current churn claim missing", got)
		}
		if err := store.Delete(claim); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.ListIndexFuncValues(fabricPodUIDIndex)) != 0 || len(store.ListIndexFuncValues(fabricSandboxIndex)) != 0 {
		t.Fatal("churn retained historical index values")
	}
}

func TestFabricLookupRefusesMissingIndexesAndMalformedAddresses(t *testing.T) {
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)}
	if err := store.Add(lookupClaim("192.0.2.12", "wanted", "sandbox", "eth0")); err != nil {
		t.Fatal(err)
	}
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != "" || store.lists != 0 {
		t.Fatal("missing index caused an unscoped fallback", got)
	}
	store = &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, fabricClaimIndexers())}
	if err := store.Add(lookupClaim("invalid", "wanted", "sandbox", "eth0")); err != nil {
		t.Fatal(err)
	}
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != "" {
		t.Fatal("invalid address used as a fabric handle", got)
	}
	store.rows = 0
	if got := fabricClaimAddress(store, "", "sandbox", "eth0"); got != "" || store.rows != 0 {
		t.Fatal("empty Pod identity queried claims", got)
	}
}

func TestFabricWatchRegistersOwnershipIndexesBeforeServing(t *testing.T) {
	claim := lookupClaim("192.0.2.12", "wanted", "sandbox", "eth0")
	factory := localinformers.NewSharedInformerFactory(localfake.NewSimpleClientset(claim), 0)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer func() { cancel(); factory.Shutdown() }()
	routes := &fabricRemoteReconciler{
		store:    factory.Local().V1alpha1().FabricIPs().Informer().GetStore(),
		writer:   &fakeFabricRemoteWriter{routes: map[string]string{}},
		nodeIPOf: func(string) net.IP { return net.ParseIP("192.0.2.1") }, self: "local",
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if err := watchFabricIPs(ctx, factory, routes, routes.log); err != nil {
		t.Fatal(err)
	}
	if got := fabricByPodUID(factory, "wanted", "sandbox", "eth0"); got != claim.Spec.Address {
		t.Fatal("real informer lookup lacked the ownership index", got)
	}
}

func (s *observedFabricIndexer) List() []any {
	objects := s.Indexer.List()
	s.lists++
	s.rows += len(objects)
	return objects
}

func (s *observedFabricIndexer) ByIndex(name, value string) ([]any, error) {
	objects, err := s.Indexer.ByIndex(name, value)
	s.indexed++
	s.rows += len(objects)
	return objects, err
}

func lookupClaim(address, uid, cid, iface string) *localv1.FabricIP {
	return &localv1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: localv1.FabricIPName(address)}, Spec: localv1.FabricIPSpec{
		Address: address, PodUID: uid, PodNamespace: "tenant", PodName: "workload", Node: "node", ContainerID: cid, IfName: iface,
	}}
}

func fabricLookupFixture(t testing.TB) *observedFabricIndexer {
	t.Helper()
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, fabricClaimIndexers())}
	for i := range 10000 {
		ip := net.IPv4(10, 100, byte(i/250), byte(i%250+1)).String()
		if err := store.Add(lookupClaim(ip, fmt.Sprintf("other-%05d", i), "other", "eth0")); err != nil {
			t.Fatal(err)
		}
	}
	for _, claim := range []*localv1.FabricIP{
		lookupClaim("fd00::42", "wanted", "sandbox", "eth0"),
		lookupClaim("192.0.2.10", "wanted", "old-sandbox", "eth0"),
		lookupClaim("192.0.2.11", "wanted", "sandbox", "net1"),
	} {
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestFabricLookupRetrievesOnlySandboxClaims(t *testing.T) {
	store := fabricLookupFixture(t)
	if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != "fd00::42" {
		t.Fatal("lookup borrowed another sandbox or interface", got)
	}
	if store.lists != 0 || store.indexed != 1 || store.rows != 1 {
		t.Fatalf("one sandbox lookup materialized cluster claims: lists=%d indexed=%d rows=%d", store.lists, store.indexed, store.rows)
	}
	store.indexed, store.rows = 0, 0
	if got := fabricClaimAddress(store, "wanted", "", ""); net.ParseIP(got).To4() == nil {
		t.Fatal("legacy Pod lookup lost IPv4 preference", got)
	}
	if store.lists != 0 || store.indexed != 1 || store.rows != 3 {
		t.Fatal("legacy lookup retrieved unrelated Pods", store.lists, store.indexed, store.rows)
	}
}

func TestFabricLookupUsesFullContainerID(t *testing.T) {
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, fabricClaimIndexers())}
	oldCID := strings.Repeat("a", 64)
	newCID := oldCID[:63] + "b"
	for _, claim := range []*localv1.FabricIP{
		lookupClaim("192.0.2.20", "pod", oldCID, "eth0"),
		lookupClaim("fd00::21", "pod", newCID, "eth0"),
	} {
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
	}
	if got := fabricClaimAddress(store, "pod", newCID, "eth0"); got != "fd00::21" || store.rows != 1 || store.lists != 0 {
		t.Fatal("64-character container IDs conflated by their common prefix", got, store.rows)
	}
}

func BenchmarkFabricLookupAmong10000Claims(b *testing.B) {
	store := fabricLookupFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if got := fabricClaimAddress(store, "wanted", "sandbox", "eth0"); got != "fd00::42" {
			b.Fatal(got)
		}
	}
}
