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

	"github.com/cilium/ebpf"
)

// Security groups (docs/security-groups.md). The agent projects Ports'
// resolved membership into sg_members ({net, VPC IP} -> group bitmap) and
// SecurityGroups' compiled rules into sg_rules ({net, dst group, proto, port}
// -> allowed-source bitmap). Enforcement is destination-side in to_pod. Both
// syncs are full-state diffs against the pinned map, like SyncServiceVIPs.

// SGWorldGroup mirrors SG_WORLD in bpf/overlay.c: the reserved pseudo-group id
// for north-south (cidr) sources. Real group ids run 1..SGWorldGroup-1.
const SGWorldGroup = 63

// SGMember is a Port's datapath membership: its VPC IP and group bitmap.
type SGMember struct {
	Net    uint32
	IP     net.IP
	Groups uint64
}

// SGRule is one compiled datapath rule: for (net, src net, dst group, proto,
// port), the bitmap of source groups (in src net's id space) allowed to reach
// it. SrcNet == Net for a same-VPC rule, the peer VNI for a peer-group rule.
// Port 0 is the any-port rule.
type SGRule struct {
	Net     uint32
	SrcNet  uint32
	Group   uint16
	Proto   uint8
	Port    uint16 // host order; stored network order
	Allowed uint64
}

// SyncSGMembers makes sg_members exactly `members` (full-state diff): a Port
// that loses all groups (or is deleted) has its entry pruned, so the datapath
// falls back to legacy allow for that address.
func (m *Manager) SyncSGMembers(members []SGMember) error {
	want := map[overlayLocalKey]uint64{}
	for _, mem := range members {
		if mem.Groups == 0 {
			continue // no groups -> no entry (zero == legacy allow)
		}
		ip, err := addr128(mem.IP)
		if err != nil {
			return fmt.Errorf("sg member IP: %w", err)
		}
		want[overlayLocalKey{Net: mem.Net, Ip: ip}] = mem.Groups
	}
	return syncMap(m.objs.SgMembers, want)
}

// SGCidr is one compiled north-south cidr rule: for (net, proto, port), a client
// CIDR and the bitmap of destination groups that admit it (security groups v2
// stage 2). The all-addresses CIDR takes the SG_WORLD path (SyncSGRules), not
// this map.
type SGCidr struct {
	Net           uint32
	Proto         uint8
	Port          uint16 // host order; stored network order
	CIDR          *net.IPNet
	AllowedGroups uint64
}

// SyncSGCidr makes the sg_cidr LPM map exactly `entries` (full-state diff). A v4
// CIDR is encoded in the datapath's NAT64 form (client addresses are v4_to_128),
// so its /N becomes /(96+N) in the 128-bit client space; the map key prefix is
// the 64 fixed bits (net+port+proto) plus that client prefix.
// cidrGroup is one north-south CIDR rule for containment analysis: a scope
// (net for ingress, src_net for egress), the {proto, port} tier, the range, and
// the source groups the rule admits.
type cidrGroup struct {
	scope  uint32
	proto  uint8
	port   uint16
	cidr   *net.IPNet
	groups uint64
}

// unionContaining fixes #11: the sg_cidr LPM returns exactly ONE entry (the
// longest match), so a narrower prefix from an unrelated group SHADOWS a broader
// one, and rules that should union do not. The map cannot express "match all
// covering prefixes" in one lookup, so the union is precomputed here: each
// entry's bitmap gains the groups of every rule in the same {scope, proto, port}
// tier whose CIDR CONTAINS it. The longest-match entry then carries the union of
// every rule covering its range. O(n^2) per tier, n tiny.
func unionContaining(items []cidrGroup) []uint64 {
	out := make([]uint64, len(items))
	for i := range items {
		e := items[i]
		if e.cidr == nil {
			continue
		}
		eOnes, _ := e.cidr.Mask.Size()
		acc := e.groups
		for j := range items {
			if j == i {
				continue
			}
			f := items[j]
			if f.cidr == nil || f.scope != e.scope || f.proto != e.proto || f.port != e.port {
				continue
			}
			fOnes, _ := f.cidr.Mask.Size()
			// f contains e iff f is no more specific and e's network sits in f.
			if fOnes <= eOnes && f.cidr.Contains(e.cidr.IP) {
				acc |= f.groups
			}
		}
		out[i] = acc
	}
	return out
}

func (m *Manager) SyncSGCidr(entries []SGCidr) error {
	items := make([]cidrGroup, len(entries))
	for i, e := range entries {
		items[i] = cidrGroup{scope: e.Net, proto: e.Proto, port: e.Port, cidr: e.CIDR, groups: e.AllowedGroups}
	}
	groups := unionContaining(items)
	want := map[overlaySgCidrKey]uint64{}
	for i, e := range entries {
		if e.CIDR == nil {
			continue
		}
		ones, _ := e.CIDR.Mask.Size()
		ip := e.CIDR.IP
		var clientPrefix uint32
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			clientPrefix = 96 + uint32(ones) // NAT64 96-bit prefix ahead of the v4
		} else {
			clientPrefix = uint32(ones)
		}
		a, err := addr128(ip)
		if err != nil {
			return fmt.Errorf("sg_cidr client %q: %w", e.CIDR, err)
		}
		key := overlaySgCidrKey{
			Prefixlen: 64 + clientPrefix,
			Net:       e.Net,
			Port:      htons(e.Port),
			Proto:     uint16(e.Proto),
			Client:    a,
		}
		want[key] |= groups[i]
	}
	return syncMap(m.objs.SgCidr, want)
}

// SGEgressCidr is one compiled north-south egress rule: source group members in
// SrcNet may egress to a destination CIDR on (proto, port). AllowedGroups is the
// bitmap of source groups (in SrcNet's id space) admitted there.
type SGEgressCidr struct {
	SrcNet        uint32
	Proto         uint8
	Port          uint16 // host order; stored network order
	CIDR          *net.IPNet
	AllowedGroups uint64
}

// SyncSGEgressCidr makes the sg_egress_cidr LPM map exactly `entries` (full-state
// diff), the egress twin of SyncSGCidr keyed by source net + destination CIDR.
func (m *Manager) SyncSGEgressCidr(entries []SGEgressCidr) error {
	items := make([]cidrGroup, len(entries))
	for i, e := range entries {
		items[i] = cidrGroup{scope: e.SrcNet, proto: e.Proto, port: e.Port, cidr: e.CIDR, groups: e.AllowedGroups}
	}
	groups := unionContaining(items)
	want := map[overlaySgEgressCidrKey]uint64{}
	for i, e := range entries {
		if e.CIDR == nil {
			continue
		}
		ones, _ := e.CIDR.Mask.Size()
		ip := e.CIDR.IP
		var destPrefix uint32
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			destPrefix = 96 + uint32(ones)
		} else {
			destPrefix = uint32(ones)
		}
		a, err := addr128(ip)
		if err != nil {
			return fmt.Errorf("sg_egress_cidr dest %q: %w", e.CIDR, err)
		}
		key := overlaySgEgressCidrKey{
			Prefixlen: 64 + destPrefix,
			SrcNet:    e.SrcNet,
			Port:      htons(e.Port),
			Proto:     uint16(e.Proto),
			Dest:      a,
		}
		want[key] |= groups[i]
	}
	return syncMap(m.objs.SgEgressCidr, want)
}

// SyncSGRules makes sg_rules exactly `rules` (full-state diff).
func (m *Manager) SyncSGRules(rules []SGRule) error {
	want := map[overlaySgRuleKey]uint64{}
	for _, r := range rules {
		key := overlaySgRuleKey{Net: r.Net, SrcNet: r.SrcNet, Group: r.Group, Port: htons(r.Port), Proto: r.Proto}
		want[key] |= r.Allowed // union rules that share a key
	}
	return syncMap(m.objs.SgRules, want)
}

// SGEgress is one compiled datapath egress rule: for a source group in src net,
// the bitmap of destination groups (in dst net's id space) it may reach on
// (proto, port). SrcNet == DstNet for a same-VPC rule, the peer VNI for a
// peered destination. Port 0 is the any-port rule.
type SGEgress struct {
	SrcNet  uint32
	DstNet  uint32
	Group   uint16 // source group id
	Proto   uint8
	Port    uint16 // host order; stored network order
	Allowed uint64 // destination-group bitmap
}

// SyncSGEgress makes sg_egress exactly `rules` (full-state diff), the mirror of
// SyncSGRules for the egress direction.
func (m *Manager) SyncSGEgress(rules []SGEgress) error {
	want := map[overlaySgEgressKey]uint64{}
	for _, r := range rules {
		key := overlaySgEgressKey{SrcNet: r.SrcNet, DstNet: r.DstNet, Group: r.Group, Port: htons(r.Port), Proto: r.Proto}
		want[key] |= r.Allowed
	}
	return syncMap(m.objs.SgEgress, want)
}

// syncMap makes a hash map exactly `want` (prune stale, put desired).
func syncMap[K, V comparable](mp *ebpf.Map, want map[K]V) error {
	var key K
	var val V
	var stale []K
	it := mp.Iterate()
	for it.Next(&key, &val) {
		if _, ok := want[key]; !ok {
			k := key
			stale = append(stale, k)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate map: %w", err)
	}
	for _, k := range stale {
		if err := mp.Delete(&k); err != nil && !isNotExist(err) {
			return err
		}
	}
	for k, v := range want {
		if err := mp.Put(&k, &v); err != nil {
			return fmt.Errorf("put map entry: %w", err)
		}
	}
	return nil
}

// EnsureSGDrop seeds a zeroed per-CPU sg_drops entry for a net, so count_sg_drop
// (which only increments) has an entry to bump — the same agent-seeded pattern
// as EnsureVPCCounter.
func (m *Manager) EnsureSGDrop(net uint32) error {
	if net == 0 {
		return nil
	}
	var existing []uint64
	if err := m.objs.SgDrops.Lookup(net, &existing); err == nil {
		return nil
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("possible CPUs: %w", err)
	}
	zero := make([]uint64, ncpu)
	if err := m.objs.SgDrops.Put(net, zero); err != nil {
		return fmt.Errorf("seed sg_drops for net %d: %w", net, err)
	}
	return nil
}

// SGDrops returns the per-net policy-drop totals (summed across CPUs).
func (m *Manager) SGDrops() (map[uint32]uint64, error) {
	out := map[uint32]uint64{}
	var net uint32
	var perCPU []uint64
	it := m.objs.SgDrops.Iterate()
	for it.Next(&net, &perCPU) {
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		out[net] = sum
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate sg_drops: %w", err)
	}
	return out, nil
}
