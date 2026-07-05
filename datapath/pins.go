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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
)

// reconcilePins removes pinned maps that the current object file could not
// reuse — a map whose shape changed across an upgrade (the 128-bit rekey was
// the first such change), or a pin that cannot even be opened. Without this
// the load fails on the incompatible pin and the agent crash-loops until the
// node is rebooted to clear bpffs (issue #7). Removing a pin is invisible to
// running pods: the tcx links on their veths keep the old program, and with it
// the old map objects, alive until the agent re-attaches them (see rebuild.go).
// Returns the names of the removed pins, sorted.
func reconcilePins() ([]string, error) {
	spec, err := loadOverlay()
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	var removed []string
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			continue
		}
		path := filepath.Join(PinRoot, name)
		pinned, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue // no pin — the load creates it fresh
		}
		if err == nil {
			cerr := ms.Compatible(pinned) // the same test map reuse applies
			pinned.Close()
			if cerr == nil {
				continue
			}
		}
		if err := os.Remove(path); err != nil {
			return removed, fmt.Errorf("remove incompatible pin %s: %w", name, err)
		}
		removed = append(removed, name)
	}
	sort.Strings(removed)
	return removed, nil
}
