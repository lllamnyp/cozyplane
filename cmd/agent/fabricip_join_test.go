package main

import (
	"fmt"
	"testing"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
)

func TestMigrationClaimJoinRetrievesOnlyLocalSandbox(t *testing.T) {
	store := fabricLookupFixture(t)
	otherNode := lookupClaim("192.0.2.20", "wanted", "sandbox", "eth0")
	otherNode.Spec.Node = "other-node"
	otherNamespace := lookupClaim("192.0.2.21", "wanted", "sandbox", "eth0")
	otherNamespace.Spec.PodNamespace = "other-tenant"
	for _, claim := range []*localv1.FabricIP{otherNode, otherNamespace} {
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
	}
	claims, err := fabricClaimsForNodeSandbox(store, "node", "tenant", "sandbox")
	if err != nil || len(claims) != 2 {
		t.Fatal("target join conflated another node, namespace or sandbox", len(claims), err)
	}
	if store.lists != 0 || store.indexed != 1 || store.rows != 2 {
		t.Fatalf("local target join materialized cluster claims: lists=%d indexed=%d rows=%d", store.lists, store.indexed, store.rows)
	}
}

func BenchmarkMigrationClaimJoinAmong10000Claims(b *testing.B) {
	store := fabricLookupFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		claims, err := fabricClaimsForNodeSandbox(store, "node", "tenant", "sandbox")
		if err != nil || len(claims) != 2 {
			b.Fatal("invalid join", len(claims), err)
		}
	}
}

func TestMigrationClaimJoinIndexRemovesRetargetedAndDeletedObjects(t *testing.T) {
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, fabricClaimIndexers())}
	claim := lookupClaim("192.0.2.25", "pod", "sandbox", "eth0")
	if err := store.Add(claim); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{"node", "namespace", "container"} {
		old := claim
		claim = claim.DeepCopy()
		switch change {
		case "node":
			claim.Spec.Node = "replacement-node"
		case "namespace":
			claim.Spec.PodNamespace = "replacement-tenant"
		case "container":
			claim.Spec.ContainerID = "replacement-sandbox"
		}
		if err := store.Update(claim); err != nil {
			t.Fatal(err)
		}
		claims, err := fabricClaimsForNodeSandbox(store, old.Spec.Node, old.Spec.PodNamespace, old.Spec.ContainerID)
		if err != nil || len(claims) != 0 {
			t.Fatal("retarget left membership in the old scope", change, len(claims), err)
		}
		claims, err = fabricClaimsForNodeSandbox(store, claim.Spec.Node, claim.Spec.PodNamespace, claim.Spec.ContainerID)
		if err != nil || len(claims) != 1 || claims[0].Spec != claim.Spec {
			t.Fatal("retarget missing from current scope", change, err)
		}
	}
	if err := store.Delete(claim); err != nil {
		t.Fatal(err)
	}
	for i := range 1000 {
		claim := lookupClaim("192.0.2.25", "pod", fmt.Sprintf("sandbox-%d", i), "eth0")
		if err := store.Add(claim); err != nil {
			t.Fatal(err)
		}
		if err := store.Delete(claim); err != nil {
			t.Fatal(err)
		}
	}
	if values := store.ListIndexFuncValues(fabricNodeSandboxIndex); len(values) != 0 || store.lists != 0 {
		t.Fatal("churn retained historical sandbox scopes", values, store.lists)
	}
}

func TestMigrationClaimJoinMissingIdentityOrIndexNeverScansCluster(t *testing.T) {
	store := &observedFabricIndexer{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)}
	for _, fields := range [][3]string{{"", "tenant", "sandbox"}, {"node", "", "sandbox"}, {"node", "tenant", ""}} {
		if claims, err := fabricClaimsForNodeSandbox(store, fields[0], fields[1], fields[2]); err != nil || len(claims) != 0 {
			t.Fatal("incomplete identity looked up an invented scope", err)
		}
	}
	if store.indexed != 0 || store.lists != 0 {
		t.Fatal("incomplete identity scanned cache")
	}
	if claims, err := fabricClaimsForNodeSandbox(store, "node", "tenant", "sandbox"); err == nil || len(claims) != 0 || store.lists != 0 {
		t.Fatal("missing index caused a global fallback or authorized a claim", err)
	}
}
