// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// bpffsMountedAt reports whether a bpf filesystem is already mounted at path.
//
// It asks statfs for the filesystem type *at the target*, which is the only
// check that is correct everywhere: a mount's source name is arbitrary. Talos
// mounts the host bpffs with the source "none", so a guard that matched on the
// source name "bpf" concluded "not mounted" on a node that had one, mounted a
// second, empty bpffs over it, and — under Bidirectional propagation —
// shadowed every pin the agent had made under /sys/fs/bpf/cozyplane. statfs
// cannot see the source at all, so it cannot be fooled that way.
func bpffsMountedAt(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("statfs %s: %w", path, err)
	}
	return st.Type == unix.BPF_FS_MAGIC, nil
}

// ensureBPFFS mounts a bpf filesystem at root if one is not already there.
//
// This mirrors datapath.EnsureBPFFS in the main cozyplane module, which the
// agent calls at startup. It is duplicated rather than imported because kpr is
// a separate module that pins Cilium's dependency tree (see go.mod): requiring
// the main module here would drag its cilium/ebpf version into this module's
// build through MVS, against the pin.
//
// probe and mount are parameters so the mount decision is testable without
// privileges; ensureBPFFSAt supplies the real ones.
func ensureBPFFS(root string, probe func(string) (bool, error), mount func(string) error) error {
	mounted, err := probe(root)
	if err != nil {
		return err
	}
	if mounted {
		return nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", root, err)
	}
	return mount(root)
}

// ensureBPFFSAt is ensureBPFFS wired to the real syscalls.
func ensureBPFFSAt(root string) error {
	return ensureBPFFS(root, bpffsMountedAt, func(target string) error {
		if err := unix.Mount("bpf", target, "bpf", 0, ""); err != nil {
			return fmt.Errorf("mount bpffs at %s: %w", target, err)
		}
		return nil
	})
}
