package datapath

import (
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func counterLifetimeManager(t *testing.T) *Manager {
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
	makeMap := func(name string) *ebpf.Map {
		ms := spec.Maps[name].Copy()
		ms.MaxEntries, ms.Pinning = 8, ebpf.PinNone
		mp, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = mp.Close() })
		return mp
	}
	return &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcCounters: makeMap("vpc_counters"), SgDrops: makeMap("sg_drops")}}}
}

func TestKernelCounterLifetimeChurn(t *testing.T) {
	m := counterLifetimeManager(t)
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for net := uint32(1); net <= 1200; net++ {
		if err := m.SyncVPCCounterScopes([]uint32{net}); err != nil {
			t.Fatal(err)
		}
		if err := m.EnsureVPCCounter(net); err != nil {
			t.Fatalf("counter capacity lost after %d sequential VPCs: %v", net, err)
		}
		if err := m.EnsureSGDrop(net); err != nil {
			t.Fatalf("drop-counter capacity lost after %d sequential VPCs: %v", net, err)
		}
	}
	vpc, err := m.VPCCounters()
	if err != nil || len(vpc) != 1 {
		t.Fatal("counter history survived churn", len(vpc), err)
	}
	sg, err := m.SGDrops()
	if err != nil || len(sg) != 1 {
		t.Fatal("drop counter history survived churn", len(sg), err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(fds) {
		t.Fatal("counter reconciliation leaked descriptors", len(fds), len(after), err)
	}
}

func TestKernelCounterLifetimePreservesCurrentValuesAndRejectsStaleSeeds(t *testing.T) {
	m := counterLifetimeManager(t)
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	values := make([]overlayVpcCounter, ncpu)
	drops := make([]uint64, ncpu)
	for i := range values {
		values[i].TxPackets = uint64(i + 1)
		drops[i] = uint64(i + 2)
	}
	for _, net := range []uint32{101, 202} {
		if err := m.objs.VpcCounters.Put(net, values); err != nil {
			t.Fatal(err)
		}
		if err := m.objs.SgDrops.Put(net, drops); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 100 {
				if err := m.SyncVPCCounterScopes([]uint32{202}); err != nil {
					t.Error(err)
				}
				for _, net := range []uint32{101, 202} {
					if err := m.EnsureVPCCounter(net); err != nil {
						t.Error(err)
					}
					if err := m.EnsureSGDrop(net); err != nil {
						t.Error(err)
					}
				}
			}
		})
	}
	wg.Wait()
	var got []overlayVpcCounter
	var gotDrops []uint64
	if err := m.objs.VpcCounters.Lookup(uint32(202), &got); err != nil {
		t.Fatal(err)
	}
	if err := m.objs.SgDrops.Lookup(uint32(202), &gotDrops); err != nil {
		t.Fatal(err)
	}
	for i := range values {
		if got[i].TxPackets != values[i].TxPackets || gotDrops[i] != drops[i] {
			t.Fatal("live per-CPU values reset", i)
		}
	}
	if err := m.objs.VpcCounters.Lookup(uint32(101), &got); !isNotExist(err) {
		t.Fatal("late seeder recreated retired traffic counter", err)
	}
	if err := m.objs.SgDrops.Lookup(uint32(101), &gotDrops); !isNotExist(err) {
		t.Fatal("late seeder recreated retired drop counter", err)
	}
	for _, input := range [][]uint32{{0}, {1 << 22}, make([]uint32, 65537)} {
		if err := m.SyncVPCCounterScopes(input); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if err := m.objs.VpcCounters.Lookup(uint32(202), &got); err != nil {
			t.Fatal("invalid snapshot removed live counters", err)
		}
	}
	if err := m.SyncVPCCounterScopes(nil); err != nil {
		t.Fatal(err)
	}
	if err := m.EnsureSGDrop(202); err != nil {
		t.Fatal(err)
	}
	if err := m.objs.SgDrops.Lookup(uint32(202), &gotDrops); !isNotExist(err) {
		t.Fatal("empty complete snapshot did not retire all scopes", err)
	}
}

func TestKernelCounterLifetimeIncompleteScanPreservesCounters(t *testing.T) {
	m := counterLifetimeManager(t)
	if err := m.EnsureVPCCounter(101); err != nil {
		t.Fatal(err)
	}
	if err := m.objs.SgDrops.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncVPCCounterScopes(nil); err == nil {
		t.Fatal("incomplete scan succeeded")
	}
	var got []overlayVpcCounter
	if err := m.objs.VpcCounters.Lookup(uint32(101), &got); err != nil {
		t.Fatal("first map was pruned before second scan completed", err)
	}
	if err := m.EnsureVPCCounter(202); err != nil {
		t.Fatal("incomplete snapshot installed scope gate", err)
	}
	if err := m.objs.VpcCounters.Lookup(uint32(202), &got); err != nil {
		t.Fatal(err)
	}
}
