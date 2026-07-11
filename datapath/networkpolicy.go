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
	"net"
)

// NetworkPolicy at net 0 (docs/network-policy.md). The agent compiles upstream
// networking.k8s.io/v1 NetworkPolicies into np_ident (fabric IP -> identity +
// isolation flags) and np_allow (identity-pair rules); enforcement is
// destination-side in to_pod, node-origin plumbing exempt via np_nodes. All
// syncs are full-state diffs against the pinned maps, like SecurityGroups.

// NP flag and reserved-identity values, mirroring bpf/overlay.c.
const (
	NPIngIsolated uint32 = 1
	NPEgIsolated  uint32 = 2

	NPDirIn uint8 = 0
	NPDirEg uint8 = 1

	NPSrcAny    uint64 = 0
	NPSrcAnyPod uint64 = 1
	// NPFirstRealID is the smallest identity the compiler may emit; hashes
	// below it are remapped so the reserved ids stay unambiguous.
	NPFirstRealID uint64 = 2
)

// NPIdent is one pod address's identity row.
type NPIdent struct {
	IP    net.IP
	ID    uint64
	Flags uint32
}

// NPAllow is one compiled identity-pair rule. Port is host order (stored
// network order); 0 = any port.
type NPAllow struct {
	DstID uint64
	SrcID uint64
	Dir   uint8
	Proto uint8
	Port  uint16
}

// SyncNPIdents makes np_ident exactly `idents` (full-state diff). An address
// with no row is simply "no pod identity" — never isolated.
func (m *Manager) SyncNPIdents(idents []NPIdent) error {
	want := map[overlayAddr128]overlayNpIdentVal{}
	for _, id := range idents {
		a, err := addr128(id.IP)
		if err != nil {
			return fmt.Errorf("np ident IP: %w", err)
		}
		want[a] = overlayNpIdentVal{Id: id.ID, Flags: id.Flags}
	}
	return syncMap(m.objs.NpIdent, want)
}

// SyncNPAllows makes np_allow exactly `allows` (full-state diff).
func (m *Manager) SyncNPAllows(allows []NPAllow) error {
	want := map[overlayNpAllowKey]uint8{}
	for _, r := range allows {
		want[overlayNpAllowKey{
			DstId: r.DstID,
			SrcId: r.SrcID,
			Port:  htons(r.Port),
			Dir:   r.Dir,
			Proto: r.Proto,
		}] = 1
	}
	return syncMap(m.objs.NpAllow, want)
}

// SetNPNode marks an address as node-origin (ingress-policy exempt);
// DelNPNode unmarks it. Incremental, like SetNodeRemote.
func (m *Manager) SetNPNode(ip net.IP) error {
	a, err := addr128(ip)
	if err != nil {
		return fmt.Errorf("np node IP: %w", err)
	}
	one := uint8(1)
	return m.objs.NpNodes.Put(&a, &one)
}

func (m *Manager) DelNPNode(ip net.IP) error {
	a, err := addr128(ip)
	if err != nil {
		return fmt.Errorf("np node IP: %w", err)
	}
	if err := m.objs.NpNodes.Delete(&a); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// NPDrops returns the per-direction policy-drop totals (summed across CPUs).
func (m *Manager) NPDrops() (map[uint8]uint64, error) {
	out := map[uint8]uint64{}
	for dir := uint32(0); dir < 2; dir++ {
		var perCPU []uint64
		if err := m.objs.NpDrops.Lookup(dir, &perCPU); err != nil {
			return nil, fmt.Errorf("lookup np_drops[%d]: %w", dir, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[uint8(dir)] = sum
	}
	return out, nil
}
