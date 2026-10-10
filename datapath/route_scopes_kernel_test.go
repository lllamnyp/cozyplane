package datapath

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelRouteScopeBoundariesRestartAndWriteFailure(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux environment")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	newMap := func(name string) *ebpf.Map {
		t.Helper()
		mpSpec := *spec.Maps[name]
		mpSpec.Pinning = ebpf.PinNone
		mp, err := ebpf.NewMap(&mpSpec)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { mp.Close() })
		return mp
	}
	routes, guard, scopes := newMap("vpc_routes"), newMap("route_guard"), newMap("route_scopes")
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcRoutes: routes, RouteGuard: guard, RouteScopes: scopes}}}
	blocked := []uint32{1, 31, 32, 4095, 4096, 1<<22 - 1}
	if err := m.SyncRoutesScoped(nil, blocked); err != nil {
		t.Fatal(err)
	}
	for _, scope := range blocked {
		var cell overlayRouteScopeGuard
		if err := scopes.Lookup(scope>>12, &cell); err != nil || cell.Blocked[(scope>>5)&127]&(1<<(scope&31)) == 0 {
			t.Fatalf("missing boundary bit %d: %v", scope, err)
		}
	}
	if len(m.routeScopeCells) != 3 {
		t.Fatalf("unexpected retained cells: %d", len(m.routeScopeCells))
	}
	// A new Manager must clear inherited bits in every page before reopening,
	// even though it has no knowledge of the old desired scope set.
	m = &Manager{objs: m.objs}
	if err := m.SyncRoutes(nil); err != nil {
		t.Fatal(err)
	}
	for page := uint32(0); page < 1024; page++ {
		var cell overlayRouteScopeGuard
		if err := scopes.Lookup(page, &cell); err != nil || cell != (overlayRouteScopeGuard{}) {
			t.Fatalf("stale page %d survived restart: %v", page, err)
		}
	}
	closed, err := scopes.Clone()
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	m.objs.RouteScopes = closed
	if err := m.SyncRoutesScoped(nil, blocked); err == nil {
		t.Fatal("closed scope map accepted publication")
	}
	var value uint32
	if err := guard.Lookup(uint32(0), &value); err != nil || value != 1 {
		t.Fatalf("scope write failure reopened global gate: %d %v", value, err)
	}
	m.objs.RouteScopes = scopes
	if err := m.SyncRoutesScoped(nil, blocked); err != nil {
		t.Fatal(err)
	}
	for i := uint32(0); i < 1100; i++ {
		if err := m.SyncRoutesScoped(nil, []uint32{(i%1024)<<12 | 1}); err != nil {
			t.Fatal(err)
		}
		if len(m.routeScopeCells) != 1 {
			t.Fatal("scope history accumulated")
		}
	}
	if err := m.SyncRoutes(nil); err != nil {
		t.Fatal(err)
	}
	if len(m.routeScopeCells) != 0 {
		t.Fatal("withdrawn guard retained scope history")
	}
	for _, scope := range []uint32{0, 1 << 22, ^uint32(0)} {
		if err := m.SyncRoutesScoped(nil, []uint32{scope}); err == nil {
			t.Fatal("out-of-range blocked scope accepted")
		}
		if err := guard.Lookup(uint32(0), &value); err != nil || value != 1 {
			t.Fatal("invalid scope failed open")
		}
	}
}

func BenchmarkKernelRouteScopeRestart(b *testing.B) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		b.Skip("requires isolated privileged Linux environment")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		b.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		b.Fatal(err)
	}
	newMap := func(name string) *ebpf.Map {
		mpSpec := *spec.Maps[name]
		mpSpec.Pinning = ebpf.PinNone
		mp, err := ebpf.NewMap(&mpSpec)
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { mp.Close() })
		return mp
	}
	objects := overlayObjects{overlayMaps: overlayMaps{VpcRoutes: newMap("vpc_routes"), RouteGuard: newMap("route_guard"), RouteScopes: newMap("route_scopes")}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := &Manager{objs: objects}
		if err := m.SyncRoutesScoped(nil, []uint32{101}); err != nil {
			b.Fatal(err)
		}
	}
}
