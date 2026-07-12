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
	// Entity peers (docs/policy-layers.md § entities): the vocabulary
	// upstream NetworkPolicy lacks. NPSrcLocalNode is compiled but not
	// probed — the structural local-node exemption supersedes it (the
	// forward path to a strict mode that drops the exemption).
	NPSrcNodes     uint64 = 2
	NPSrcLocalPods uint64 = 3
	NPSrcLocalNode uint64 = 4
	// NPFirstRealID is the smallest identity the compiler may emit; hashes
	// below it are remapped so the reserved ids stay unambiguous (5-7 are
	// spare headroom for further entities).
	NPFirstRealID uint64 = 8
)

// NPNodeLocal marks an np_nodes entry as one of THIS node's own addresses:
// only the local node's origin traffic is unconditionally ingress-exempt
// (kubelet probes — plumbing); remote-node origin is gated and admitted by
// the `nodes` entity.
const NPNodeLocal uint8 = 1

// NPIdent is one pod address's identity row.
type NPIdent struct {
	IP    net.IP
	ID    uint64
	Flags uint32
}

// NPAllow is one compiled identity-pair rule. Port is host order (stored
// network order); 0 = any port. EndPort != 0 makes [Port, EndPort] a range
// (upstream endPort), decomposed into LPM prefixes by the sync.
type NPAllow struct {
	DstID   uint64
	SrcID   uint64
	Dir     uint8
	Proto   uint8
	Port    uint16
	EndPort uint16
}

// npPortPrefix is one big-endian port prefix: `bits` leading bits of `port`.
type npPortPrefix struct {
	port uint16 // host order here; stored network order
	bits uint32 // 0..16
}

// npPortPrefixes covers [lo, hi] with maximal aligned power-of-two blocks —
// the standard range-to-prefix decomposition (≤ 2*16-1 prefixes). lo == 0
// with hi == 0 is the any-port rule: one /0.
func npPortPrefixes(lo, hi uint16) []npPortPrefix {
	if lo == 0 && hi == 0 {
		return []npPortPrefix{{port: 0, bits: 0}}
	}
	var out []npPortPrefix
	l, h := uint32(lo), uint32(hi)
	for l <= h {
		// The largest block aligned at l that fits within [l, h].
		size := uint32(1)
		for {
			next := size << 1
			if l&(next-1) != 0 || l+next-1 > h {
				break
			}
			size = next
		}
		bits := uint32(16)
		for s := size; s > 1; s >>= 1 {
			bits--
		}
		out = append(out, npPortPrefix{port: uint16(l), bits: bits})
		l += size
		if l == 0 {
			break // uint32 keeps this unreachable; belt and braces
		}
	}
	return out
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

// SyncNPAllows makes np_allow exactly `allows` (full-state diff). The port
// is an LPM suffix behind 160 fixed bits: exact = /16, any = /0, a range =
// its prefix decomposition. Stored network order so prefixes nest.
func (m *Manager) SyncNPAllows(allows []NPAllow) error {
	want := map[overlayNpAllowKey]uint8{}
	for _, r := range allows {
		lo, hi := r.Port, r.Port
		if r.EndPort != 0 {
			hi = r.EndPort
		}
		if lo == 0 {
			hi = 0 // any-port: a single /0
		}
		for _, pp := range npPortPrefixes(lo, hi) {
			want[overlayNpAllowKey{
				Prefixlen: 160 + pp.bits,
				Dir:       r.Dir,
				Proto:     r.Proto,
				DstId:     r.DstID,
				SrcId:     r.SrcID,
				Port:      htons(pp.port),
			}] = 1
		}
	}
	return syncMap(m.objs.NpAllow, want)
}

// NPCidr is one compiled ipBlock entry: for the isolated identity (the
// destination of an ingress rule, the source of an egress one), an address
// range that admits (Allow) or masks (an `except` — !Allow) traffic on
// (proto, port). Port 0 = any. Longest-prefix-match makes an except win over
// its enclosing allow; at an identical prefix an allow from any policy wins
// (policies union).
type NPCidr struct {
	ID    uint64
	Dir   uint8
	Proto uint8
	Port  uint16 // host order; stored network order
	CIDR  *net.IPNet
	Allow bool
}

// SyncNPCidrs makes the np_cidr LPM exactly `entries` (full-state diff). A v4
// range lives in NAT64 form, so its /N becomes /(96+N) in the address space;
// the key prefix is the 96 fixed bits (dir+proto+port+id) plus that.
func (m *Manager) SyncNPCidrs(entries []NPCidr) error {
	want := map[overlayNpCidrKey]uint8{}
	for _, e := range entries {
		if e.CIDR == nil {
			continue
		}
		ones, _ := e.CIDR.Mask.Size()
		ip := e.CIDR.IP
		var bits uint32
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 96 + uint32(ones)
		} else {
			bits = uint32(ones)
		}
		a, err := addr128(ip)
		if err != nil {
			return fmt.Errorf("np_cidr range %q: %w", e.CIDR, err)
		}
		key := overlayNpCidrKey{
			Prefixlen: 96 + bits,
			Dir:       e.Dir,
			Proto:     e.Proto,
			Port:      htons(e.Port),
			Id:        e.ID,
			Addr:      a,
		}
		var v uint8
		if e.Allow {
			v = 1
		}
		if prev, ok := want[key]; ok && prev == 1 {
			continue // an allow from any policy wins at an identical prefix
		}
		want[key] = v
	}
	return syncMap(m.objs.NpCidr, want)
}

// SetNPNode records an address as a node's. `local` marks this node's own
// addresses — the only ones unconditionally exempt from ingress policy.
// DelNPNode removes it. Incremental, like SetNodeRemote.
func (m *Manager) SetNPNode(ip net.IP, local bool) error {
	a, err := addr128(ip)
	if err != nil {
		return fmt.Errorf("np node IP: %w", err)
	}
	var v uint8
	if local {
		v = NPNodeLocal
	}
	return m.objs.NpNodes.Put(&a, &v)
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
