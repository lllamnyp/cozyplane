/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// EnsureBPFFS mounts a bpf filesystem at the parent of PinRoot if one is not
// already present. kind nodes (and some hosts) don't mount bpffs by default,
// but pinning programs/maps requires it.
func EnsureBPFFS() error {
	mountpoint := filepath.Dir(PinRoot) // /sys/fs/bpf

	var st unix.Statfs_t
	if err := unix.Statfs(mountpoint, &st); err == nil && st.Type == unix.BPF_FS_MAGIC {
		return nil
	}

	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountpoint, err)
	}
	if err := unix.Mount("bpf", mountpoint, "bpf", 0, ""); err != nil {
		return fmt.Errorf("mount bpffs at %s: %w", mountpoint, err)
	}
	return nil
}
