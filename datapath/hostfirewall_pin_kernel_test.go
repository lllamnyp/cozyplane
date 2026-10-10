package datapath

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestKernelHostFirewallModePinSurvivesParamsLoss(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := unix.Mount("bpf", root, "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, 0); err != nil {
			t.Error(err)
		}
	})
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ebpf.NewMapWithOptions(spec.Maps["params"], ebpf.MapOptions{PinPath: root})
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	if err := legacy.Put(cfgHFEnabled, uint32(1)); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Put(cfgHFEgEnabled, uint32(2)); err != nil {
		t.Fatal(err)
	}
	if err := ensureHFModePin(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "params")); err != nil {
		t.Fatal(err)
	}
	if err := ensureHFModePin(root); err != nil {
		t.Fatal("lost params overwrote initialized isolation", err)
	}
	modes, err := ebpf.LoadPinnedMap(filepath.Join(root, "hf_modes"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer modes.Close()
	for direction, want := range []uint32{1, 2, 1} {
		var mode uint32
		if err := modes.Lookup(uint32(direction), &mode); err != nil || mode != want {
			t.Fatal("persisted mode", direction, mode, want, err)
		}
	}
	params, err := ebpf.NewMapWithOptions(spec.Maps["params"], ebpf.MapOptions{PinPath: root})
	if err != nil {
		t.Fatal(err)
	}
	defer params.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{HfModes: modes, Params: params}}}
	if err := m.armHFBootstrap(nil); err != nil {
		t.Fatal(err)
	}
	for direction, want := range []uint32{1, 2} {
		var mode uint32
		if err := params.Lookup(cfgHFEnabled+uint32(direction), &mode); err != nil || mode != want {
			t.Fatal("legacy program mirror", mode, err)
		}
	}
}
