package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelPruneFabricRemotesPreservesTenantScopes(t *testing.T) {
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
	ms := spec.Maps["remotes"].Copy()
	ms.Pinning = ebpf.PinNone
	ms.MaxEntries = 16
	mp, err := ebpf.NewMap(ms)
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Remotes: mp}}}
	entries := []struct {
		scope uint32
		cidr  string
		keep  bool
	}{
		{0, "10.0.0.10/32", true}, {0, "2001:db8::10/128", true},
		{0, "10.0.0.99/32", false}, {0, "10.1.0.0/24", false},
		{77, "10.0.0.99/32", true}, {77, "2001:db8::99/128", true},
	}
	for _, entry := range entries {
		if err := m.SetRemote(entry.scope, entry.cidr, net.ParseIP("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.PruneFabricRemotes([]string{"10.0.0.10/32", "2001:db8::10/128"}); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		key, _ := lpmKey(entry.scope, entry.cidr)
		var value uint32
		err := mp.Lookup(key, &value)
		if entry.keep && err != nil {
			t.Fatalf("current/tenant route removed: %+v %v", entry, err)
		}
		if !entry.keep && !isNotExist(err) {
			t.Fatalf("orphan route retained: %+v %v", entry, err)
		}
	}
}
