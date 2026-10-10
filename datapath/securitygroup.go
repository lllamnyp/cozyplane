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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"

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

// SGMembershipBitmap distinguishes an empty membership from a selected group
// awaiting allocation. Bit zero has no admitting rules, so pending/invalid
// identities keep default-deny while other resolved groups still union normally.
func SGMembershipBitmap(ids []int32) uint64 {
	var bitmap uint64
	for _, id := range ids {
		if id > 0 && id < SGWorldGroup {
			bitmap |= 1 << uint(id)
		} else {
			bitmap |= 1
		}
	}
	return bitmap
}

// SGMember is a Port's datapath membership: its VPC IP and group bitmap.
type SGMember struct {
	Net    uint32
	IP     net.IP
	Groups uint64
	Owner  [4]uint64
}

// SGEndpointOwner binds membership to a specific Port and sandbox. Incomplete
// legacy witnesses stay zero and cannot authorize a registered local endpoint.
func SGEndpointOwner(portUID, containerID, ifName string) [4]uint64 {
	if portUID == "" || containerID == "" || ifName == "" {
		return [4]uint64{}
	}
	// A Linux interface alias cannot carry a witness larger than 255 bytes.
	// Reject before summing lengths or copying untrusted annotation payloads.
	const limit = 255
	if len(portUID) > limit || len(containerID) > limit || len(ifName) > limit || len(portUID)+len(containerID)+len(ifName)+2 > limit {
		return [4]uint64{}
	}
	var buf [limit]byte
	n := copy(buf[:], portUID)
	n++ // zero separator
	n += copy(buf[n:], containerID)
	n++
	n += copy(buf[n:], ifName)
	digest := sha256.Sum256(buf[:n])
	return [4]uint64{binary.LittleEndian.Uint64(digest[0:8]), binary.LittleEndian.Uint64(digest[8:16]), binary.LittleEndian.Uint64(digest[16:24]), binary.LittleEndian.Uint64(digest[24:32])}
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

// BlockSecurityGroups guards a rejected compiler snapshot before map sync.
func (m *Manager) BlockSecurityGroups() error {
	m.sgMu.Lock()
	defer m.sgMu.Unlock()
	return m.objs.Params.Put(cfgSGUpdating, uint32(1))
}

// ApplySecurityGroups guards all five map diffs so missing membership or a
// partially replaced ruleset cannot admit flows after a failed update.
func (m *Manager) ApplySecurityGroups(members []SGMember, rules []SGRule, cidrs []SGCidr, egress []SGEgress, egressCIDRs []SGEgressCidr) error {
	m.sgMu.Lock()
	defer m.sgMu.Unlock()
	if err := m.objs.Params.Put(cfgSGUpdating, uint32(1)); err != nil {
		return fmt.Errorf("arm SecurityGroup update guard: %w", err)
	}
	if err := m.SyncSGMembers(members); err != nil {
		return err
	}
	if err := m.SyncSGRules(rules); err != nil {
		return err
	}
	if err := m.SyncSGCidr(cidrs); err != nil {
		return err
	}
	if err := m.SyncSGEgress(egress); err != nil {
		return err
	}
	if err := m.SyncSGEgressCidr(egressCIDRs); err != nil {
		return err
	}
	if err := m.objs.Params.Put(cfgSGInitialized, uint32(1)); err != nil {
		return err
	}
	return m.objs.Params.Put(cfgSGUpdating, uint32(0))
}

// SyncSGMembers publishes explicit zero for resolved unselected Ports. Missing
// registered local VPC endpoints stay pending under the datapath fallback.
func (m *Manager) SyncSGMembers(members []SGMember) error {
	want := map[overlayLocalKey]overlaySgMember{}
	for _, mem := range members {
		ip, err := addr128(mem.IP)
		if err != nil {
			return fmt.Errorf("sg member IP: %w", err)
		}
		if err := putDesired(m.objs.SgMembers, want, overlayLocalKey{Net: mem.Net, Ip: ip}, overlaySgMember{Groups: mem.Groups, Owner: mem.Owner}); err != nil {
			return err
		}
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
// every rule covering its range. Prefix ancestry bounds work to 129 lookups
// per entry, independent of the number of unrelated tenant rules.
func unionContaining(items []cidrGroup) []uint64 {
	type prefixKey struct {
		scope  uint32
		proto  uint8
		port   uint16
		prefix netip.Prefix
	}
	index := make(map[prefixKey]uint64, len(items))
	keys := make([]prefixKey, len(items))
	for i, item := range items {
		if item.cidr == nil {
			continue
		}
		prefix, err := normalizedCIDR(item.cidr)
		if err != nil {
			continue
		}
		key := prefixKey{item.scope, item.proto, item.port, prefix}
		keys[i] = key
		index[key] |= item.groups
	}
	out := make([]uint64, len(items))
	for i := range items {
		key := keys[i]
		if !key.prefix.IsValid() {
			continue
		}
		addr := key.prefix.Addr()
		for bits := 0; bits <= keys[i].prefix.Bits(); bits++ {
			key.prefix = netip.PrefixFrom(addr, bits).Masked()
			out[i] |= index[key]
		}
	}
	return out
}

func (m *Manager) SyncSGCidr(entries []SGCidr) error {
	items := make([]cidrGroup, len(entries))
	for i, e := range entries {
		if e.CIDR != nil {
			if _, _, err := cidrAddressPrefix(e.CIDR); err != nil {
				return err
			}
		}
		items[i] = cidrGroup{scope: e.Net, proto: e.Proto, port: e.Port, cidr: e.CIDR, groups: e.AllowedGroups}
	}
	groups := unionContaining(items)
	want := map[overlaySgCidrKey]uint64{}
	for i, e := range entries {
		if e.CIDR == nil {
			continue
		}
		a, clientPrefix, family, err := cidrPolicyPrefix(e.CIDR)
		if err != nil {
			return fmt.Errorf("sg_cidr client %q: %w", e.CIDR, err)
		}
		key := overlaySgCidrKey{
			Prefixlen: 64 + clientPrefix,
			Net:       e.Net,
			Port:      htons(e.Port),
			Proto:     uint16(e.Proto) | uint16(family)<<8,
			Client:    a,
		}
		if err := putDesired(m.objs.SgCidr, want, key, want[key]|groups[i]); err != nil {
			return err
		}
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
		if e.CIDR != nil {
			if _, _, err := cidrAddressPrefix(e.CIDR); err != nil {
				return err
			}
		}
		items[i] = cidrGroup{scope: e.SrcNet, proto: e.Proto, port: e.Port, cidr: e.CIDR, groups: e.AllowedGroups}
	}
	groups := unionContaining(items)
	want := map[overlaySgEgressCidrKey]uint64{}
	for i, e := range entries {
		if e.CIDR == nil {
			continue
		}
		a, destPrefix, family, err := cidrPolicyPrefix(e.CIDR)
		if err != nil {
			return fmt.Errorf("sg_egress_cidr dest %q: %w", e.CIDR, err)
		}
		key := overlaySgEgressCidrKey{
			Prefixlen: 64 + destPrefix,
			SrcNet:    e.SrcNet,
			Port:      htons(e.Port),
			Proto:     uint16(e.Proto) | uint16(family)<<8,
			Dest:      a,
		}
		if err := putDesired(m.objs.SgEgressCidr, want, key, want[key]|groups[i]); err != nil {
			return err
		}
	}
	return syncMap(m.objs.SgEgressCidr, want)
}

// SyncSGRules makes sg_rules exactly `rules` (full-state diff).
func (m *Manager) SyncSGRules(rules []SGRule) error {
	want := map[overlaySgRuleKey]uint64{}
	for _, r := range rules {
		key := overlaySgRuleKey{Net: r.Net, SrcNet: r.SrcNet, Group: r.Group, Port: htons(r.Port), Proto: r.Proto}
		if err := putDesired(m.objs.SgRules, want, key, want[key]|r.Allowed); err != nil {
			return err
		}
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
		if err := putDesired(m.objs.SgEgress, want, key, want[key]|r.Allowed); err != nil {
			return err
		}
	}
	return syncMap(m.objs.SgEgress, want)
}

// syncMap makes a hash map exactly `want` (prune stale, put desired).
// putDesired bounds desired-state memory before range expansion can grow beyond
// kernel capacity. Existing keys can still union at a full map.
func putDesired[K comparable, V any](mp *ebpf.Map, want map[K]V, key K, value V) error {
	if _, exists := want[key]; !exists && uint64(len(want)) >= uint64(mp.MaxEntries()) {
		return fmt.Errorf("desired state exceeds map capacity %d", mp.MaxEntries())
	}
	want[key] = value
	return nil
}

func syncMap[K, V comparable](mp *ebpf.Map, want map[K]V) error {
	if uint64(len(want)) > uint64(mp.MaxEntries()) {
		return fmt.Errorf("desired state exceeds map capacity %d", mp.MaxEntries())
	}
	var key K
	var val V
	var stale []K
	unchanged := make(map[K]bool)
	it := mp.Iterate()
	for it.Next(&key, &val) {
		if desired, ok := want[key]; !ok {
			k := key
			stale = append(stale, k)
		} else if desired == val {
			unchanged[key] = true
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
		if unchanged[k] {
			continue
		}
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
	m.counterMu.Lock()
	defer m.counterMu.Unlock()
	if net == 0 || (m.counterScopes != nil && !m.counterScopes[net]) {
		return nil
	}
	var existing []uint64
	if err := m.objs.SgDrops.Lookup(net, &existing); err == nil {
		return nil
	} else if !isNotExist(err) {
		return fmt.Errorf("lookup sg_drops for net %d: %w", net, err)
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("possible CPUs: %w", err)
	}
	zero := make([]uint64, ncpu)
	if err := m.objs.SgDrops.Update(net, zero, ebpf.UpdateNoExist); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
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
