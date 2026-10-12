package datapath

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func floatingKernelManager(t *testing.T, smallMap string) *Manager {
	t.Helper()
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
	clear(spec.Programs)
	for name, mp := range spec.Maps {
		if name != "floating" && name != "floating_egress" {
			delete(spec.Maps, name)
			continue
		}
		mp.Pinning = ebpf.PinNone
		if name == smallMap {
			mp.MaxEntries = 1
		}
	}
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Floating: c.Maps["floating"], FloatingEgress: c.Maps["floating_egress"]}}}
}

func TestKernelFloatingRetargetWithdrawsOldSNAT(t *testing.T) {
	for _, addresses := range [][3]string{{"203.0.113.10", "10.0.0.2", "10.0.0.3"}, {"2001:db8::10", "fd00::2", "fd00::3"}} {
		t.Run(addresses[0], func(t *testing.T) {
			m := floatingKernelManager(t, "")
			if err := m.SetFloating(addresses[0], addresses[1], 101); err != nil {
				t.Fatal(err)
			}
			if err := m.SetFloating(addresses[0], addresses[2], 102); err != nil {
				t.Fatal(err)
			}
			oldIP, _ := addr128Str(addresses[1])
			old := overlayLocalKey{Net: 101, Ip: oldIP}
			var pub overlayAddr128
			if err := m.objs.FloatingEgress.Lookup(old, &pub); !isNotExist(err) {
				t.Fatalf("retired target can still SNAT as public address: %s err=%v", addr128ToIP(pub), err)
			}
			newIP, _ := addr128Str(addresses[2])
			wanted, _ := addr128Str(addresses[0])
			if err := m.objs.FloatingEgress.Lookup(overlayLocalKey{Net: 102, Ip: newIP}, &pub); err != nil || pub != wanted {
				t.Fatalf("replacement SNAT missing: %v", err)
			}
		})
	}
}

func TestKernelFloatingRetargetAtFullReverseMap(t *testing.T) {
	m := floatingKernelManager(t, "floating_egress")
	if err := m.SetFloating("203.0.113.10", "10.0.0.2", 101); err != nil {
		t.Fatal(err)
	}
	if err := m.SetFloating("203.0.113.10", "10.0.0.3", 102); err != nil {
		t.Fatalf("retarget cannot replace retired entry at capacity: %v", err)
	}
	oldIP, _ := addr128Str("10.0.0.2")
	var pub overlayAddr128
	if err := m.objs.FloatingEgress.Lookup(overlayLocalKey{Net: 101, Ip: oldIP}, &pub); !isNotExist(err) {
		t.Fatal("old identity retained", err)
	}
}

func TestKernelFloatingCompleteProjectionPrunesOrphans(t *testing.T) {
	for _, addresses := range [][4]string{{"203.0.113.10", "203.0.113.11", "10.0.0.2", "10.0.0.3"}, {"2001:db8::10", "2001:db8::11", "fd00::2", "fd00::3"}} {
		t.Run(addresses[0], func(t *testing.T) {
			m := floatingKernelManager(t, "")
			targets := map[string]FloatingTarget{addresses[0]: {VNI: 101, VPCIP: addresses[2]}, addresses[1]: {VNI: 102, VPCIP: addresses[2]}}
			if err := m.SyncFloating(targets); err != nil {
				t.Fatal("overlapping private addresses must remain scoped", err)
			}
			orphanIP, _ := addr128Str(addresses[3])
			pub, _ := addr128Str(addresses[0])
			orphan := overlayLocalKey{Net: 777, Ip: orphanIP}
			if err := m.objs.FloatingEgress.Put(orphan, pub); err != nil {
				t.Fatal(err)
			}
			targets[addresses[0]] = FloatingTarget{VNI: 101, VPCIP: addresses[3]}
			delete(targets, addresses[1])
			if err := m.SyncFloating(targets); err != nil {
				t.Fatal(err)
			}
			var got overlayAddr128
			oldIP, _ := addr128Str(addresses[2])
			for _, key := range []overlayLocalKey{orphan, {Net: 101, Ip: oldIP}, {Net: 102, Ip: oldIP}} {
				if err := m.objs.FloatingEgress.Lookup(key, &got); !isNotExist(err) {
					t.Fatal("orphan SNAT remains", key, err)
				}
			}
			if err := m.objs.FloatingEgress.Lookup(overlayLocalKey{Net: 101, Ip: orphanIP}, &got); err != nil || got != pub {
				t.Fatal("new reverse mapping missing", got, err)
			}
			if err := m.SyncFloating(nil); err != nil {
				t.Fatal(err)
			}
			var key overlayLocalKey
			it := m.objs.FloatingEgress.Iterate()
			if it.Next(&key, &got) || it.Err() != nil {
				t.Fatal("reverse state not empty", it.Err())
			}
			var ep overlayBridgeEp
			fit := m.objs.Floating.Iterate()
			if fit.Next(&got, &ep) || fit.Err() != nil {
				t.Fatal("forward state not empty", fit.Err())
			}
		})
	}
}

func TestKernelFloatingCapacityAndOwnershipPreflight(t *testing.T) {
	for _, smallMap := range []string{"floating", "floating_egress"} {
		t.Run(smallMap, func(t *testing.T) {
			m := floatingKernelManager(t, smallMap)
			old := map[string]FloatingTarget{"203.0.113.10": {VNI: 101, VPCIP: "10.0.0.2"}}
			if err := m.SyncFloating(old); err != nil {
				t.Fatal(err)
			}
			for _, invalid := range []map[string]FloatingTarget{
				{"203.0.113.11": {VNI: 102, VPCIP: "10.0.0.3"}, "203.0.113.12": {VNI: 103, VPCIP: "10.0.0.4"}},
				{"203.0.113.11": {VNI: 101, VPCIP: "10.0.0.2"}, "203.0.113.12": {VNI: 101, VPCIP: "10.0.0.2"}},
				{"203.0.113.11": {VNI: 0, VPCIP: "10.0.0.2"}},
				{"203.0.113.11": {VNI: 101, VPCIP: "fd00::2"}},
				{"2001:db8::10": {VNI: 101, VPCIP: "fd00::2"}, "2001:0db8::10": {VNI: 102, VPCIP: "fd00::3"}},
			} {
				if err := m.SyncFloating(invalid); err == nil {
					t.Fatal("invalid projection admitted")
				}
				pub, _ := addr128Str("203.0.113.10")
				ip, _ := addr128Str("10.0.0.2")
				var ep overlayBridgeEp
				var got overlayAddr128
				if err := m.objs.Floating.Lookup(pub, &ep); err != nil || ep.Net != 101 || ep.VpcIp != ip {
					t.Fatal("preflight changed forward", ep, err)
				}
				if err := m.objs.FloatingEgress.Lookup(overlayLocalKey{Net: 101, Ip: ip}, &got); err != nil || got != pub {
					t.Fatal("preflight changed reverse", got, err)
				}
			}
		})
	}
}

func TestKernelFloatingOldPublicDeletionPreservesReplacementSNAT(t *testing.T) {
	m := floatingKernelManager(t, "")
	for _, pub := range []string{"203.0.113.10", "203.0.113.11"} {
		if err := m.SetFloating(pub, "10.0.0.2", 101); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.DelFloating("203.0.113.10"); err != nil {
		t.Fatal(err)
	}
	ip, _ := addr128Str("10.0.0.2")
	want, _ := addr128Str("203.0.113.11")
	var got overlayAddr128
	if err := m.objs.FloatingEgress.Lookup(overlayLocalKey{Net: 101, Ip: ip}, &got); err != nil || got != want {
		t.Fatal("retired public address erased replacement", got, err)
	}
}
