package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelMigrationForwardCleanupOwnsInstallation(t *testing.T) {
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
	ms.Pinning = ebpf.PinNone
	ms.MaxEntries = 16
	mp, err := ebpf.NewMap(ms)
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{MigrateFwd: mp}}}
	vm := net.ParseIP("10.0.0.10")
	target := net.ParseIP("192.0.2.1")
	key, _ := localKey(77, vm)
	old, err := m.InstallMigrateFwd(77, vm, target)
	if err != nil {
		t.Fatal(err)
	}
	// Same target is intentional: address comparison alone is not a lease.
	current, err := m.InstallMigrateFwd(77, vm, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := old(); err != nil {
		t.Fatal(err)
	}
	var value uint32
	if err := mp.Lookup(key, &value); err != nil {
		t.Fatal("old cleanup removed current forward", err)
	}
	if err := current(); err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &value); !isNotExist(err) {
		t.Fatal("current cleanup retained forward", err)
	}
	stale, err := m.InstallMigrateFwd(77, vm, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DelMigrateFwd(77, vm); err != nil {
		t.Fatal(err)
	}
	newLease, err := m.InstallMigrateFwd(77, vm, net.ParseIP("192.0.2.2"))
	if err != nil {
		t.Fatal(err)
	}
	if err := stale(); err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &value); err != nil {
		t.Fatal("revoked lease removed replacement", err)
	}
	if err := m.clearMigrateForwards(); err != nil {
		t.Fatal(err)
	}
	if err := mp.Lookup(key, &value); !isNotExist(err) {
		t.Fatal("startup retained forward", err)
	}
	if err := newLease(); err != nil {
		t.Fatal(err)
	}
}
