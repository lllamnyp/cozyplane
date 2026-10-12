package datapath

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelNetworkPartitionsReconcileWithoutHistory(t *testing.T) {
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
	manager := func(t *testing.T) *Manager {
		t.Helper()
		ms := spec.Maps["networks"].Copy()
		ms.Pinning, ms.MaxEntries = ebpf.PinNone, 8
		mp, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mp.Close() })
		return &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Networks: mp}}}
	}
	lookup := func(t *testing.T, m *Manager, scope uint32, prefix string, want uint32) {
		t.Helper()
		key, err := lpmKey(scope, prefix)
		if err != nil {
			t.Fatal(err)
		}
		var value uint32
		err = m.objs.Networks.Lookup(key, &value)
		if want == 0 {
			if !isNotExist(err) {
				t.Fatal("obsolete network row survived", value, err)
			}
		} else if err != nil || value != want {
			t.Fatal("network row changed", value, want, err)
		}
	}
	count := func(t *testing.T, m *Manager) int {
		t.Helper()
		it := m.objs.Networks.Iterate()
		var key overlayLpmKey
		var value uint32
		n := 0
		for it.Next(&key, &value) {
			n++
		}
		if err := it.Err(); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("replacement and restart history", func(t *testing.T) {
		m := manager(t)
		if err := m.SetNetwork(101, "10.99.0.0/24", 101); err != nil {
			t.Fatal(err)
		}
		peer := PeerNet{Scope: 101, CIDR: "203.0.113.0/24", Net: 202}
		if err := m.SyncPeerNetworks([]PeerNet{peer}); err != nil {
			t.Fatal(err)
		}
		previous := "10.99.0.0/24"
		for i := range 1200 {
			prefix := fmt.Sprintf("10.8.%d.%d/32", i/256, i%256)
			if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: prefix, Net: 101}, {Scope: 102, CIDR: prefix, Net: 102}}); err != nil {
				t.Fatal(err)
			}
			lookup(t, m, 101, prefix, 101)
			lookup(t, m, 102, prefix, 102) // overlapping CIDRs remain scoped
			lookup(t, m, 101, previous, 0)
			lookup(t, m, 101, peer.CIDR, peer.Net)
			if got := count(t, m); got != 3 {
				t.Fatalf("round=%d retained=%d rows", i, got)
			}
			previous = prefix
		}
		if err := m.SyncOwnNetworks(nil); err != nil {
			t.Fatal(err)
		}
		if got := count(t, m); got != 1 {
			t.Fatal("deleted VPC rows remained", got)
		}
		lookup(t, m, 101, peer.CIDR, peer.Net)
	})
	t.Run("shared capacity preflight", func(t *testing.T) {
		m := manager(t)
		old := "10.0.0.1/32"
		if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: old, Net: 101}}); err != nil {
			t.Fatal(err)
		}
		var peers []PeerNet
		for i := range 7 {
			peers = append(peers, PeerNet{Scope: 101, CIDR: fmt.Sprintf("198.51.100.%d/32", i), Net: 202})
		}
		if err := m.SyncPeerNetworks(peers); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: "10.0.0.2/32", Net: 101}, {Scope: 101, CIDR: "10.0.0.3/32", Net: 101}}); err == nil {
			t.Fatal("shared map capacity overflow accepted")
		}
		lookup(t, m, 101, old, 101)
		if got := count(t, m); got != 8 {
			t.Fatal("failed preflight pruned existing rows", got)
		}
		if err := m.SyncPeerNetworks(nil); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: "10.0.0.2/32", Net: 101}}); err != nil {
			t.Fatal("capacity recovery failed", err)
		}
	})
	t.Run("normalization and collision refusal", func(t *testing.T) {
		m := manager(t)
		if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: "192.0.2.0/24", Net: 101}, {Scope: 101, CIDR: "::ffff:192.0.2.0/120", Net: 101}}); err != nil {
			t.Fatal(err)
		}
		if got := count(t, m); got != 1 {
			t.Fatal("mapped route alias consumed another row", got)
		}
		if err := m.SyncPeerNetworks([]PeerNet{{Scope: 101, CIDR: "192.0.2.0/24", Net: 202}}); err == nil {
			t.Fatal("peer overwrote own partition")
		}
		lookup(t, m, 101, "192.0.2.17/32", 101)
		if err := m.SyncOwnNetworks([]PeerNet{{Scope: 101, CIDR: "bad", Net: 101}}); err == nil {
			t.Fatal("invalid CIDR accepted")
		}
		lookup(t, m, 101, "192.0.2.17/32", 101)
	})
	t.Run("concurrent writers retain both partitions", func(t *testing.T) {
		m := manager(t)
		var wg sync.WaitGroup
		errors := make(chan error, 2)
		for _, own := range []bool{false, true} {
			wg.Go(func() {
				for i := range 100 {
					entry := PeerNet{Scope: 101, Net: 202, CIDR: fmt.Sprintf("198.51.100.%d/32", i)}
					var err error
					if own {
						entry.Net, entry.CIDR = 101, fmt.Sprintf("10.0.0.%d/32", i)
						err = m.SyncOwnNetworks([]PeerNet{entry})
					} else {
						err = m.SyncPeerNetworks([]PeerNet{entry})
					}
					if err != nil {
						errors <- err
						return
					}
				}
			})
		}
		wg.Wait()
		close(errors)
		for err := range errors {
			t.Fatal(err)
		}
		lookup(t, m, 101, "10.0.0.99/32", 101)
		lookup(t, m, 101, "198.51.100.99/32", 202)
		if got := count(t, m); got != 2 {
			t.Fatal("concurrent writer left history", got)
		}
	})
}
