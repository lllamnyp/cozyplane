package datapath

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestKernelRouteBootstrapClosesCompatibleReload(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux environment")
	}
	if entries, err := os.ReadDir(PinRoot); err == nil && len(entries) != 0 {
		t.Fatal("refusing to touch existing pinned state")
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/sys/fs/bpf", 0)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	var previousID ebpf.MapID
	for i := 0; i < 2; i++ {
		m := &Manager{}
		func() {
			defer m.Close()
			if err := m.Load(DefaultVNI); err != nil {
				t.Fatal(err)
			}
			if i == 1 && len(m.RecreatedPins()) != 0 {
				t.Fatalf("reload was not ABI-compatible: %v", m.RecreatedPins())
			}
			info, err := m.objs.RouteGuard.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, ok := info.ID()
			if !ok || (i == 1 && id != previousID) {
				t.Fatal("compatible reload replaced the pinned route guard")
			}
			previousID = id
			var guard uint32
			if err := m.objs.RouteGuard.Lookup(uint32(0), &guard); err != nil || guard != 1 {
				t.Fatalf("loader did not close egress: guard=%d err=%v", guard, err)
			}
			if err := m.SyncRoutes(nil); err != nil {
				t.Fatal(err)
			}
			if err := m.objs.RouteGuard.Lookup(uint32(0), &guard); err != nil || guard != 0 {
				t.Fatalf("complete empty snapshot did not restore egress: guard=%d err=%v", guard, err)
			}
		}()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("loader/reload leaked descriptors: before=%d after=%d err=%v", len(before), len(after), err)
	}
}

// Measure the real writer at the shipped capacity, including its update guard,
// desired-state allocation and kernel syscalls. No pins or interfaces are used.
func BenchmarkKernelRouteSyncFullCapacity(b *testing.B) {
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
	for _, mp := range spec.Maps {
		mp.Pinning = ebpf.PinNone
	}
	routes, err := ebpf.NewMap(spec.Maps["vpc_routes"])
	if err != nil {
		b.Fatal(err)
	}
	defer routes.Close()
	guard, err := ebpf.NewMap(spec.Maps["route_guard"])
	if err != nil {
		b.Fatal(err)
	}
	defer guard.Close()
	scopeSpec := *spec.Maps["route_scopes"]
	scopeSpec.Pinning = ebpf.PinNone
	scopes, err := ebpf.NewMap(&scopeSpec)
	if err != nil {
		b.Fatal(err)
	}
	defer scopes.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcRoutes: routes, RouteGuard: guard, RouteScopes: scopes}}}
	desired := make([]RouteEntry, routes.MaxEntries())
	for i := range desired {
		desired[i] = RouteEntry{Scope: 101, CIDR: fmt.Sprintf("198.18.%d.%d/32", i>>8, i&255), GwIP: net.ParseIP("10.0.0.1")}
	}
	if err := m.SyncRoutes(desired); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	var beforeCPU, afterCPU unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &beforeCPU); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := m.SyncRoutes(desired); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &afterCPU); err != nil {
		b.Fatal(err)
	}
	cpu := unix.TimevalToNsec(afterCPU.Utime) + unix.TimevalToNsec(afterCPU.Stime) - unix.TimevalToNsec(beforeCPU.Utime) - unix.TimevalToNsec(beforeCPU.Stime)
	b.ReportMetric(float64(cpu)/float64(b.N), "cpu-ns/op")
}
