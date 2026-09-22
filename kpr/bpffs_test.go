// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEnsureBPFFSSkipsExistingMount is the regression for the Talos outage: the
// shipped guard grepped busybox `mount` output for the source name "bpf", and
// Talos names its host bpffs source "none". The guard therefore decided "no
// bpffs here" on a node that had one and mounted a second, empty bpffs over the
// first; with Bidirectional propagation that empty mount reached the host and
// shadowed every program/map/link the agent had pinned under
// /sys/fs/bpf/cozyplane, so the CNI plugin's OpenPinnedProgram failed on every
// pod ADD.
//
// The decision must depend only on what is mounted at the target, never on what
// it is called. A probe reporting "already mounted" must produce no mount call,
// whatever the source name would have been.
func TestEnsureBPFFSSkipsExistingMount(t *testing.T) {
	mounts := 0
	err := ensureBPFFS("/sys/fs/bpf",
		func(string) (bool, error) { return true, nil },
		func(string) error { mounts++; return nil },
	)
	if err != nil {
		t.Fatalf("ensureBPFFS: %v", err)
	}
	if mounts != 0 {
		t.Fatalf("stacked %d mount(s) on an existing bpffs; the old source-name guard did exactly this", mounts)
	}
}

func TestEnsureBPFFSMountsWhenAbsent(t *testing.T) {
	root := t.TempDir() + "/bpf"
	var got string
	mounts := 0
	err := ensureBPFFS(root,
		func(string) (bool, error) { return false, nil },
		func(target string) error { mounts++; got = target; return nil },
	)
	if err != nil {
		t.Fatalf("ensureBPFFS: %v", err)
	}
	if mounts != 1 || got != root {
		t.Fatalf("mounts=%d target=%q, want 1 mount at %q", mounts, got, root)
	}
}

func TestEnsureBPFFSPropagatesProbeError(t *testing.T) {
	sentinel := errors.New("boom")
	err := ensureBPFFS("/sys/fs/bpf",
		func(string) (bool, error) { return false, sentinel },
		func(string) error { t.Fatal("must not mount when the probe failed"); return nil },
	)
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

// TestBPFFSMountedAtChecksFilesystemType exercises the real syscall: the probe
// keys on the filesystem type reported by statfs at the target. statfs cannot
// observe a mount's source name at all, which is what makes the check immune to
// the Talos "none" naming that broke the shell guard.
func TestBPFFSMountedAtChecksFilesystemType(t *testing.T) {
	// /proc is always mounted and is never a bpffs.
	if mounted, err := bpffsMountedAt("/proc"); err != nil || mounted {
		t.Fatalf("bpffsMountedAt(/proc) = %v, %v; want false, nil", mounted, err)
	}

	if missing, err := bpffsMountedAt(t.TempDir() + "/absent"); err != nil || missing {
		t.Fatalf("bpffsMountedAt(absent) = %v, %v; want false, nil", missing, err)
	}

	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/bpf", &st); err != nil || st.Type != unix.BPF_FS_MAGIC {
		t.Skip("no bpffs mounted at /sys/fs/bpf on this host")
	}
	mounted, err := bpffsMountedAt("/sys/fs/bpf")
	if err != nil || !mounted {
		t.Fatalf("bpffsMountedAt(/sys/fs/bpf) = %v, %v; want true, nil", mounted, err)
	}
}
