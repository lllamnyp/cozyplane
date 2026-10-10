package datapath

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func migrationLifetimeMap(t *testing.T) (*Manager, *ebpf.Map) {
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
	ms := spec.Maps["migrate_fwd"].Copy()
	ms.Pinning, ms.MaxEntries = ebpf.PinNone, 8
	mp, err := ebpf.NewMap(ms)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mp.Close() })
	return &Manager{objs: overlayObjects{overlayMaps: overlayMaps{MigrateFwd: mp}}}, mp
}

func TestKernelMigrationExpiryPreservesRenewedInstallation(t *testing.T) {
	m, mp := migrationLifetimeMap(t)
	ip, target := net.ParseIP("10.0.0.2"), net.ParseIP("192.0.2.1")
	key, _ := localKey(100, ip)
	old, err := m.InstallMigrateFwd(100, ip, target)
	if err != nil {
		t.Fatal(err)
	}
	oldTime := m.migrateOwners[key].installed
	current, err := m.InstallMigrateFwd(100, ip, target)
	if err != nil {
		t.Fatal(err)
	}
	currentTime := m.migrateOwners[key].installed
	if !currentTime.After(oldTime) {
		t.Fatal("installations must have distinct observed times")
	}
	if err := old(); err != nil {
		t.Fatal(err)
	}
	grace := 15 * time.Second
	if err := m.ExpireMigrateForwards(oldTime.Add(grace), grace); err != nil {
		t.Fatal(err)
	}
	var value uint32
	if err := mp.Lookup(key, &value); err != nil {
		t.Fatal("old deadline expired renewed same-target installation", err)
	}
	if err := m.ExpireMigrateForwards(currentTime.Add(grace), grace); err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &value); !isNotExist(err) || len(m.migrateOwners) != 0 {
		t.Fatal("current installation did not expire at its deadline", err)
	}
	if err := current(); err != nil {
		t.Fatal("expired cleanup must remain idempotent", err)
	}
}

func TestKernelMigrationChurnBoundsStateAndDescriptors(t *testing.T) {
	m, mp := migrationLifetimeMap(t)
	countFD := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	beforeFD, beforeGo := countFD(), runtime.NumGoroutine()
	target := net.ParseIP("192.0.2.1")
	for i := range 1200 {
		ip := net.ParseIP(fmt.Sprintf("10.1.%d.%d", i/250, i%250+1))
		for range 4 {
			if _, err := m.InstallMigrateFwd(100, ip, target); err != nil {
				t.Fatal(err)
			}
		}
		if len(m.migrateOwners) != 1 {
			t.Fatal("replacements retained event history")
		}
		if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err != nil {
			t.Fatal(err)
		}
		key, _ := localKey(100, ip)
		var value uint32
		if err := mp.Lookup(key, &value); !isNotExist(err) || len(m.migrateOwners) != 0 {
			t.Fatal("churn retained expired ownership", err)
		}
	}
	for i := range 8 {
		if _, err := m.InstallMigrateFwd(100, net.ParseIP(fmt.Sprintf("10.2.0.%d", i+1)), target); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.InstallMigrateFwd(100, net.ParseIP("10.2.0.9"), target); err == nil || len(m.migrateOwners) != 8 {
		t.Fatal("failed ninth map insertion must not grow expiry state", err)
	}
	// A concurrent loader can clear the shared kernel map. Admission still
	// bounds this manager's old owners instead of relying solely on map.Put.
	for i := range 8 {
		key, _ := localKey(100, net.ParseIP(fmt.Sprintf("10.2.0.%d", i+1)))
		if err := mp.Delete(key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.InstallMigrateFwd(100, net.ParseIP("10.2.0.9"), target); err == nil || len(m.migrateOwners) != 8 {
		t.Fatal("empty kernel map bypassed the retained-owner capacity", err)
	}
	if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err != nil || len(m.migrateOwners) != 0 {
		t.Fatal("full map did not expire", err)
	}
	cleanup, err := m.InstallMigrateFwd(100, net.ParseIP("10.2.0.9"), target)
	if err != nil {
		t.Fatal("expired admission did not recover", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if after := countFD(); after != beforeFD {
		t.Fatalf("FD grew %d -> %d", beforeFD, after)
	}
	if after := runtime.NumGoroutine(); after > beforeGo+2 {
		t.Fatalf("goroutines grew %d -> %d", beforeGo, after)
	}
}

func TestKernelMigrationExpiryConcurrentReplacement(t *testing.T) {
	m, mp := migrationLifetimeMap(t)
	ip, target := net.ParseIP("10.0.0.2"), net.ParseIP("192.0.2.1")
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				cleanup, err := m.InstallMigrateFwd(100, ip, target)
				if err != nil {
					t.Error(err)
					return
				}
				if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err != nil {
					t.Error(err)
				}
				if err := cleanup(); err != nil {
					t.Error(err)
				}
			}
		})
	}
	workers.Wait()
	before := time.Now()
	if _, err := m.InstallMigrateFwd(100, ip, target); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpireMigrateForwards(before, 15*time.Second); err != nil {
		t.Fatal(err)
	}
	var value uint32
	key, _ := localKey(100, ip)
	if err := mp.Lookup(key, &value); err != nil || len(m.migrateOwners) != 1 {
		t.Fatal("completed stale cleanup removed the final renewed installation", err)
	}
	if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err != nil || len(m.migrateOwners) != 0 {
		t.Fatal("concurrent replacement did not drain", err)
	}
}

func TestKernelMigrationExpiryRetriesFailedDelete(t *testing.T) {
	m, mp := migrationLifetimeMap(t)
	_, err := m.InstallMigrateFwd(100, net.ParseIP("10.0.0.2"), net.ParseIP("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	clone, err := mp.Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer clone.Close()
	if err := mp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err == nil || len(m.migrateOwners) != 1 {
		t.Fatal("failed deletion must retain a retry witness", err)
	}
	m.objs.MigrateFwd = clone
	if err := m.ExpireMigrateForwards(time.Now().Add(time.Hour), 15*time.Second); err != nil || len(m.migrateOwners) != 0 {
		t.Fatal("recovered map failed to retry deletion", err)
	}
}
