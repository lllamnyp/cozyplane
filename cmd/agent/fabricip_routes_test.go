package main

import (
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

type fakeFabricRemoteWriter struct {
	mu      sync.Mutex
	routes  map[string]string
	entered chan struct{}
	release chan struct{}
}

func (w *fakeFabricRemoteWriter) SetRemote(_ uint32, cidr string, node net.IP) error {
	w.mu.Lock()
	entered, release := w.entered, w.release
	w.entered, w.release = nil, nil
	w.mu.Unlock()
	if entered != nil {
		close(entered)
		<-release
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.routes[cidr] = node.String()
	return nil
}
func (w *fakeFabricRemoteWriter) DelRemote(_ uint32, cidr string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.routes, cidr)
	return nil
}
func (w *fakeFabricRemoteWriter) PruneFabricRemotes(cidrs []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	want := map[string]bool{}
	for _, cidr := range cidrs {
		want[cidr] = true
	}
	for cidr := range w.routes {
		if !want[cidr] {
			delete(w.routes, cidr)
		}
	}
	return nil
}
func (w *fakeFabricRemoteWriter) route(cidr string) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.routes[cidr]
}

func TestFabricRouteReconciliationUsesCurrentClaim(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	w := &fakeFabricRemoteWriter{routes: map[string]string{}}
	nodes := newNodeIPIndex()
	nodes.byName["remote-a"] = net.ParseIP("192.0.2.1")
	nodes.byName["remote-b"] = net.ParseIP("192.0.2.2")
	r := &fabricRemoteReconciler{store: store, writer: w, nodeIPOf: nodes.get, self: "local", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	old := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "claim", UID: types.UID("old")}, Spec: localv1alpha1.FabricIPSpec{Address: "10.0.0.10", Node: "remote-a"}}
	if err := store.Add(old); err != nil {
		t.Fatal(err)
	}
	r.apply(old)
	current := old.DeepCopy()
	current.UID = "current"
	current.Spec.Node = "remote-b"
	if err := store.Update(current); err != nil {
		t.Fatal(err)
	}
	r.apply(cache.DeletedFinalStateUnknown{Key: old.Name, Obj: old})
	if got := w.route("10.0.0.10/32"); got != "192.0.2.2" {
		t.Fatalf("old DEL removed replacement route: %q", got)
	}
	nodes.del("remote-b")
	r.resync()
	if got := w.route("10.0.0.10/32"); got != "" {
		t.Fatalf("missing-node route retained: %q", got)
	}
	if err := store.Delete(current); err != nil {
		t.Fatal(err)
	}
	r.apply(old)
	if got := w.route("10.0.0.10/32"); got != "" {
		t.Fatalf("stale ADD resurrected route: %q", got)
	}
}

func TestFabricRouteDeleteSerializesAgainstNodeResync(t *testing.T) {
	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	entered, release := make(chan struct{}), make(chan struct{})
	w := &fakeFabricRemoteWriter{routes: map[string]string{}, entered: entered, release: release}
	r := &fabricRemoteReconciler{store: store, writer: w, nodeIPOf: func(string) net.IP { return net.ParseIP("192.0.2.1") }, self: "local", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "claim"}, Spec: localv1alpha1.FabricIPSpec{Address: "10.0.0.10", Node: "remote"}}
	if err := store.Add(claim); err != nil {
		t.Fatal(err)
	}
	resynced := make(chan struct{})
	go func() { r.resync(); close(resynced) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("resync did not reach writer")
	}
	if err := store.Delete(claim); err != nil {
		close(release)
		t.Fatal(err)
	}
	deleted := make(chan struct{})
	go func() { r.apply(claim); close(deleted) }()
	close(release)
	for _, done := range []chan struct{}{resynced, deleted} {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("route reconciliation deadlocked")
		}
	}
	if got := w.route("10.0.0.10/32"); got != "" {
		t.Fatalf("old resync resurrected deleted route: %q", got)
	}
	w.routes["10.0.0.99/32"] = "192.0.2.99"
	if err := r.syncInitial(); err != nil {
		t.Fatal(err)
	}
	if got := w.route("10.0.0.99/32"); got != "" {
		t.Fatalf("orphaned pinned route survived initial sync: %q", got)
	}
}
