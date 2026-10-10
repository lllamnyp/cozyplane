package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelRouteCapacityFailurePreservesCompleteSnapshot(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	routeSpec := *spec.Maps["vpc_routes"]
	routeSpec.Pinning, routeSpec.MaxEntries = ebpf.PinNone, 1
	mp, err := ebpf.NewMap(&routeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()
	guardSpec := *spec.Maps["route_guard"]
	guardSpec.Pinning = ebpf.PinNone
	guard, err := ebpf.NewMap(&guardSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()
	scopeSpec := *spec.Maps["route_scopes"]
	scopeSpec.Pinning = ebpf.PinNone
	scopes, err := ebpf.NewMap(&scopeSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer scopes.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcRoutes: mp, RouteGuard: guard, RouteScopes: scopes}}}
	old := RouteEntry{Scope: 101, CIDR: "203.0.113.0/24", GwIP: net.ParseIP("10.0.0.1")}
	if err := m.SyncRoutes([]RouteEntry{old}); err != nil {
		t.Fatal(err)
	}
	tooLarge := []RouteEntry{
		{Scope: 101, CIDR: "198.51.100.0/24", GwIP: net.ParseIP("10.0.0.2")},
		{Scope: 101, CIDR: "192.0.2.0/24", GwIP: net.ParseIP("10.0.0.3")},
	}
	if err := m.SyncRoutes(tooLarge); err == nil {
		t.Fatal("oversized route snapshot accepted")
	}
	key, want, err := routeMapEntry(old)
	if err != nil {
		t.Fatal(err)
	}
	var got overlayRouteEntry
	if err := mp.Lookup(key, &got); err != nil || got != want {
		t.Fatal("capacity failure erased complete route snapshot", got, err)
	}
	// Recovery publishes a complete replacement, including removal of old rows.
	if err := m.SyncRoutes(tooLarge[:1]); err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &got); !isNotExist(err) {
		t.Fatal("stale route survived valid recovery", err)
	}
	key, want, err = routeMapEntry(tooLarge[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &got); err != nil || got != want {
		t.Fatal("complete recovery route missing", got, err)
	}
}
