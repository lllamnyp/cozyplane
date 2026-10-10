package datapath

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestKernelForwardingMapUpgradeAndReplay(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if entries, err := os.ReadDir(PinRoot); err == nil && len(entries) > 0 {
		t.Fatal("refusing to touch existing pinned state")
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/sys/fs/bpf", 0)
	if err := os.MkdirAll(PinRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	current := spec.Maps["fwd_cidrs"].Copy()
	current.Pinning = ebpf.PinNone
	legacy := current.Copy()
	legacy.KeySize, legacy.Key = 24, nil
	old, err := ebpf.NewMap(legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	path := filepath.Join(PinRoot, "fwd_cidrs")
	if err := old.Pin(path); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	oldKey, _ := lpmKey(1, "::/0")
	if err := old.Put(oldKey, uint8(1)); err != nil {
		t.Fatal(err)
	}
	removed, err := reconcilePins()
	if err != nil || len(removed) != 1 || removed[0] != "fwd_cidrs" {
		t.Fatal("legacy forwarding map was not recreated", removed, err)
	}
	var one uint8
	if err := old.Lookup(oldKey, &one); err != nil || one != 1 {
		t.Fatal("unpin prematurely destroyed old attached-program state", one, err)
	}
	mp, err := ebpf.NewMap(current)
	if err != nil {
		t.Fatal(err)
	}
	defer mp.Close()
	if err := mp.Pin(path); err != nil {
		t.Fatal(err)
	}
	if err := current.Compatible(mp); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"198.51.100.0/24", "2001:db8::/32"}
	for _, prefix := range prefixes {
		key, _ := fwdCIDRKey(1, prefix)
		if err := mp.Lookup(key, &one); !isNotExist(err) {
			t.Fatal("recreated map authorized traffic before replay", one, err)
		}
	}
	foreign, _ := fwdCIDRKey(2, "::/0")
	if err := SetFwdCidr(2, "::/0"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 16; round++ {
		for _, prefix := range prefixes {
			if err := SetFwdCidr(1, prefix); err != nil {
				t.Fatal(err)
			}
			key, _ := fwdCIDRKey(1, prefix)
			if err := mp.Lookup(key, &one); err != nil || one != 1 {
				t.Fatal("owned replay did not restore prefix", one, err)
			}
		}
		if err := ClearFwdCidrs(1); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range prefixes {
			key, _ := fwdCIDRKey(1, prefix)
			if err := mp.Lookup(key, &one); !isNotExist(err) {
				t.Fatal("clear retained owned family prefix", one, err)
			}
		}
		if err := mp.Lookup(foreign, &one); err != nil || one != 1 {
			t.Fatal("clear removed another leg's grant", one, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("forwarding replay leaked descriptors", len(before), len(after), err)
	}
}
