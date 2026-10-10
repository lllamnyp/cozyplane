package datapath

import (
	"fmt"
	"net"
)

// Boundary is a complete operator policy for one VNI. Revision zero closes a
// newly discovered managed VPC until a complete version can be published.
type Boundary struct {
	Net      uint32
	Revision uint64
	Identity uint64
	Internet bool
	Rules    []BoundaryRule
	CIDRs    []*net.IPNet
}

type BoundaryRule struct {
	Peer     uint32
	Ingress  bool
	Protocol uint8
	Port     uint16
}
type PrimaryPort struct {
	Net uint32
	IP  net.IP
}

// Each node stages both old and new rule versions before publishing the VPC's
// pointer to the new revision. Publication is one atomic map update per VPC.
// The old pointer remains authoritative on any staging failure.
func (m *Manager) SyncBoundaries(desired []Boundary, known []uint32, primary []PrimaryPort) error {
	m.boundaryMu.Lock()
	defer m.boundaryMu.Unlock()
	policies := map[uint32]overlayBoundaryPolicy{}
	rules := map[overlayBoundaryRule]uint8{}
	cidrs := map[overlayBoundaryCidr]uint8{}
	for _, b := range desired {
		if b.Net == 0 || b.Revision == 0 || b.Identity == 0 {
			return fmt.Errorf("invalid boundary identity or revision")
		}
		if _, exists := policies[b.Net]; exists {
			return fmt.Errorf("duplicate boundary VNI")
		}
		p := overlayBoundaryPolicy{Revision: b.Revision, Identity: b.Identity}
		if b.Internet {
			p.Internet = 1
		}
		policies[b.Net] = p
		for _, r := range b.Rules {
			if r.Peer == 0 || r.Peer == b.Net {
				return fmt.Errorf("invalid boundary peer")
			}
			d := uint8(0)
			if r.Ingress {
				d = 1
			}
			rules[overlayBoundaryRule{Revision: b.Revision, Net: b.Net, Peer: r.Peer, Proto: r.Protocol, Direction: d, Port: htons(r.Port)}] = 1
		}
		for _, c := range b.CIDRs {
			if c == nil {
				return fmt.Errorf("invalid boundary CIDR")
			}
			ip, err := addr128(c.IP)
			if err != nil {
				return err
			}
			bits, size := c.Mask.Size()
			if size != 32 && size != 128 {
				return fmt.Errorf("invalid boundary CIDR mask")
			}
			if c.IP.To4() != nil {
				bits += 96
			}
			if bits < 0 || bits > 128 {
				return fmt.Errorf("invalid boundary CIDR prefix")
			}
			cidrs[overlayBoundaryCidr{Prefixlen: uint32(bits), Addr: ip}] = 1
		}
	}
	if len(policies) > 16384 || len(rules) > 65536 || len(cidrs) > 32768 || len(primary) > 65536 {
		return fmt.Errorf("boundary map capacity exceeded")
	}
	current := map[uint32]overlayBoundaryPolicy{}
	var n uint32
	var p overlayBoundaryPolicy
	it := m.objs.BoundaryPolicy.Iterate()
	for it.Next(&n, &p) {
		current[n] = p
	}
	if err := it.Err(); err != nil {
		return err
	}
	knownSet := map[uint32]bool{}
	for _, n := range known {
		knownSet[n] = true
	}
	// A VNI recycled for another VPC must not inherit CT or a permissive policy.
	for n, p := range policies {
		old, ok := current[n]
		if !ok || old.Identity != p.Identity {
			closed := overlayBoundaryPolicy{Identity: p.Identity}
			if err := m.objs.BoundaryPolicy.Put(n, closed); err != nil {
				return err
			}
			current[n] = closed
		}
	}
	for n, p := range current {
		if !knownSet[n] && (p.Revision != 0 || p.Internet != 0) {
			p.Revision = 0
			p.Internet = 0
			if err := m.objs.BoundaryPolicy.Put(n, p); err != nil {
				return err
			}
			current[n] = p
		}
	}
	// Prune only obsolete staging versions, never the version a live pointer uses.
	stage := map[overlayBoundaryRule]uint8{}
	existingRules := map[overlayBoundaryRule]uint8{}
	var k overlayBoundaryRule
	var v uint8
	ri := m.objs.BoundaryRules.Iterate()
	for ri.Next(&k, &v) {
		existingRules[k] = v
		if p, ok := current[k.Net]; ok && p.Revision == k.Revision {
			stage[k] = v
		}
	}
	if err := ri.Err(); err != nil {
		return err
	}
	for k, v := range rules {
		stage[k] = v
	}
	if len(stage) > 131072 {
		return fmt.Errorf("boundary staging map capacity exceeded")
	}
	// Drop unreachable leftovers before writes, retaining all currently live keys.
	ri = m.objs.BoundaryRules.Iterate()
	var stale []overlayBoundaryRule
	for ri.Next(&k, &v) {
		if _, ok := stage[k]; !ok {
			stale = append(stale, k)
		}
	}
	if err := ri.Err(); err != nil {
		return err
	}
	for _, k := range stale {
		if err := m.objs.BoundaryRules.Delete(k); err != nil && !isNotExist(err) {
			return err
		}
	}
	for k, v := range rules {
		if previous, exists := existingRules[k]; exists && previous == v {
			continue
		}
		if err := m.objs.BoundaryRules.Put(k, v); err != nil {
			return err
		}
	}
	prim := map[overlayLocalKey]uint8{}
	for _, port := range primary {
		ip, err := addr128(port.IP)
		if err != nil {
			return err
		}
		prim[overlayLocalKey{Net: port.Net, Ip: ip}] = 1
	}
	if err := syncMap(m.objs.BoundaryPrimary, prim); err != nil {
		return err
	}
	if err := syncMap(m.objs.BoundaryCidrs, cidrs); err != nil {
		return err
	}
	for n, p := range policies {
		if previous, exists := current[n]; exists && previous == p {
			continue
		}
		if err := m.objs.BoundaryPolicy.Put(n, p); err != nil {
			return err
		}
	}
	// An explicit operator-authorized removal returns a still-existing VPC to
	// legacy policy. Deleted VPCs stay closed until their VNI is safely recycled.
	for n := range current {
		if knownSet[n] {
			if _, managed := policies[n]; !managed {
				if err := m.objs.BoundaryPolicy.Delete(n); err != nil && !isNotExist(err) {
					return err
				}
			}
		}
	}
	return syncMap(m.objs.BoundaryRules, rules)
}
