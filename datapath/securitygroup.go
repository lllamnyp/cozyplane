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

// SyncSGRules makes sg_rules exactly `rules` (full-state diff).
func (m *Manager) SyncSGRules(rules []SGRule) error {
	want := map[overlaySgRuleKey]uint64{}
	for _, r := range rules {
		key := overlaySgRuleKey{Net: r.Net, SrcNet: r.SrcNet, Group: r.Group, Port: htons(r.Port), Proto: r.Proto}
		want[key] |= r.Allowed // union rules that share a key
	}
	return syncMap(m.objs.SgRules, want)
}

// syncMap makes a hash map exactly `want` (prune stale, put desired).
func syncMap[K comparable](mp *ebpf.Map, want map[K]uint64) error {
	var key K
	var val uint64
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
