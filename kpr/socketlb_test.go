package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestSocketLBObjectCompatibility(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bpfSockObject))
	if err != nil {
		t.Fatal(err)
	}
	for name, attach := range attachTypes {
		prog := spec.Programs[name]
		if prog == nil || prog.AttachType != attach {
			t.Fatalf("embedded program %s has incompatible attachment: %+v", name, prog)
		}
	}
	// Derive the map ABI from the imported control plane's real constructors.
	// Capacity is deliberately excluded: the live reconciler chooses it.
	for _, m := range []*bpf.Map{
		lbmaps.NewService4Map(1), lbmaps.NewService6Map(1),
		lbmaps.NewBackend4Map(1), lbmaps.NewBackend6Map(1),
		lbmaps.NewRevNat4Map(1), lbmaps.NewRevNat6Map(1),
		lbmaps.NewSockRevNat4Map(1), lbmaps.NewSockRevNat6Map(1),
	} {
		got := spec.Maps[m.Name()]
		if got == nil || got.Type != m.Type() || got.KeySize != m.KeySize() || got.ValueSize != m.ValueSize() {
			t.Fatalf("embedded map %s disagrees with the control plane: %+v", m.Name(), got)
		}
	}
}

// Run only in a fresh privileged container with a private cgroup namespace,
// without host bpffs or cgroup mounts. Programs attach to an empty test child.
func TestSocketLBKernelCompatibility(t *testing.T) {
	if os.Getenv("COZYPLANE_KPR_BPF_TEST") != "1" {
		t.Skip("requires an isolated privileged Linux container with a private cgroup namespace")
	}
	bpffs, cgroups := t.TempDir(), t.TempDir()
	if err := unix.Mount("none", bpffs, "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(bpffs, unix.MNT_DETACH)
	if err := unix.Mount("none", cgroups, "cgroup2", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount(cgroups, unix.MNT_DETACH)
	child := filepath.Join(cgroups, "audit")
	if err := os.Mkdir(child, 0755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(child)
	if err := os.MkdirAll(filepath.Join(bpffs, "tc", "globals"), 0755); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	coll, links, err := attachSocketLB(logger, socketLBConfig{BPFFSRoot: bpffs, CgroupRoot: child}, bpfSockObject)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
	defer func() {
		for _, l := range links {
			_ = l.Unpin()
			_ = l.Close()
		}
	}()
	if len(links) != len(attachTypes) {
		t.Fatalf("attached %d programs, want %d", len(links), len(attachTypes))
	}
	for _, l := range links {
		if _, err := l.Info(); err != nil {
			t.Fatal(err)
		}
	}
}
