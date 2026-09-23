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
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// A floating IP is the north-south bridge turned outward: a routable public
// address mapped 1:1 to a pod's (net, VPC IP), with the external client's source
// preserved. Unlike the fabric bridge it needs no /32 route — from_uplink
// intercepts the address at the node uplink's tc ingress (before kernel routing)
// and redirects it into the pod's veth, where to_pod DNATs public->VPC. Here we
// only publish the mapping in the pinned `floating` map the datapath keys on.
// Nothing here announces the address: the fabric must already hand it to a node
// (tenet 3, docs/north-south.md).

// linkInfo is the part of a link carriesWire needs, split out to be testable.
type linkInfo struct {
	Flags net.Flags
	Type  string
}

func linkInfoOf(l netlink.Link) linkInfo {
	return linkInfo{Flags: l.Attrs().Flags, Type: l.Type()}
}

// carriesWire reports whether a packet from the wire can arrive on this link.
// Binding one that cannot points the node's single floating slot at a device
// that never delivers, black-holing every floating and LB reply.
func carriesWire(l linkInfo) bool {
	if l.Flags&net.FlagLoopback != 0 || l.Type == "dummy" {
		return false
	}
	return l.Flags&net.FlagUp != 0
}

// floatFacts are the facts about one external address that decide where, if
// anywhere, the floating machinery binds.
type floatFacts struct {
	// RouteLink is the ifindex the FIB would send out of; 0 if it named none.
	RouteLink int
	// RouteGw is the next hop the FIB named; nil for an on-link or local answer.
	RouteGw net.IP
	// RouteLocal records that the FIB answered RTN_LOCAL: the node owns this
	// address.
	RouteLocal bool
	// OwnerLink is the ifindex the address is CONFIGURED on; 0 if it is not
	// ours. Only meaningful when RouteLocal.
	OwnerLink int
	// OwnerUsable reports carriesWire for that link.
	OwnerUsable bool
	// DefaultUplink is the ifindex from_uplink is already attached to.
	DefaultUplink int
}

// factsFor reads one route answer; needsOwner says whether the costlier owner
// lookup is warranted.
func factsFor(r netlink.Route, defaultUplink int) floatFacts {
	return floatFacts{
		RouteLink:     r.LinkIndex,
		RouteGw:       r.Gw,
		RouteLocal:    r.Type == unix.RTN_LOCAL,
		DefaultUplink: defaultUplink,
	}
}

func (f floatFacts) needsOwner() bool { return f.RouteLocal }

// bindLink resolves which link's ingress must carry the floating machinery for
// this address, or 0 when there is nothing to program. Addresses owned by the
// node's own interfaces are special-cased: the FIB answers RTN_LOCAL for them,
// so OwnerLink and not RouteLink decides.
//
// See docs/lb-ingress.md § "Node-owned external addresses".
func (f floatFacts) bindLink() (int, error) {
	if f.RouteLocal {
		switch {
		case f.OwnerLink == 0:
			return 0, fmt.Errorf("address is local to this node but configured on no link")
		case !f.OwnerUsable:
			return 0, fmt.Errorf("address is local but its owning link cannot carry traffic from the wire")
		case f.OwnerLink == f.DefaultUplink:
			return 0, nil
		default:
			return f.OwnerLink, nil
		}
	}
	// Attracted from outside: the FIB's egress link is also the arrival link,
	// whether the address is on-link there or behind a gateway on it.
	if f.RouteLink == 0 || f.RouteLink == f.DefaultUplink {
		return 0, nil
	}
	return f.RouteLink, nil
}

// ownerFromAddrs finds the link ip is configured on, preferring one that can
// carry wire traffic. An unusable owner is still reported, so errors can name it.
func ownerFromAddrs(addrs []netlink.Addr, links map[int]linkInfo, ip net.IP) (idx int, usable bool) {
	for _, a := range addrs {
		// a.IP is a.IPNet.IP: the embedded pointer must be checked first.
		if a.IPNet == nil || a.IP == nil || !a.IP.Equal(ip) {
			continue
		}
		li, ok := links[a.LinkIndex]
		if !ok {
			continue
		}
		if carriesWire(li) {
			return a.LinkIndex, true
		}
		if idx == 0 {
			idx = a.LinkIndex
		}
	}
	return idx, false
}

// addrOwnerLink returns the ifindex of the link ip is configured on, or 0 if
// the address is not the node's own. Two dumps, not one per link: AddrList
// always dumps the whole table and filters client-side.
func addrOwnerLink(ip net.IP) (int, bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return 0, false, fmt.Errorf("list addresses: %w", err)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return 0, false, fmt.Errorf("list links: %w", err)
	}
	byIndex := make(map[int]linkInfo, len(links))
	for _, l := range links {
		byIndex[l.Attrs().Index] = linkInfoOf(l)
	}
	idx, usable := ownerFromAddrs(addrs, byIndex, ip)
	return idx, usable, nil
}

// coveringSubnet picks the link prefix anchor sits in, longest first, and its
// first host — the L2 fabric's virtual router by convention. A host prefix is
// not a subnet: its "first host" is the neighbour, not a router. nil when no
// prefix covers anchor.
func coveringSubnet(addrs []netlink.Addr, anchor net.IP) (*net.IPNet, net.IP) {
	var best *net.IPNet
	bestOnes := -1
	for _, a := range addrs {
		if a.IPNet == nil || !a.IPNet.Contains(anchor) {
			continue
		}
		ones, bits := a.IPNet.Mask.Size()
		if bits == 0 || ones == bits {
			continue
		}
		if ones > bestOnes {
			best, bestOnes = a.IPNet, ones
		}
	}
	if best == nil {
		return nil, nil
	}
	base := best.IP.Mask(best.Mask).To4()
	if base == nil {
		return nil, nil
	}
	// Masked, so the caller gets a network rather than the kernel's
	// address-with-a-prefix form.
	return &net.IPNet{IP: base, Mask: best.Mask}, net.IPv4(base[0], base[1], base[2], base[3]+1)
}

// routeLookupErr separates a failed FIB query from an empty answer: %w on a nil
// error renders as %!w(<nil>).
func routeLookupErr(publicIP string, n int, err error) error {
	if err != nil {
		return fmt.Errorf("route lookup for %s: %w", publicIP, err)
	}
	if n == 0 {
		return fmt.Errorf("route lookup for %s: no route", publicIP)
	}
	return nil
}

// EnsureFloatingUplink makes the datapath serve an external address from the
// link that actually carries it: binding it to the default uplink instead would
// egress a spoof-guarded NIC with a foreign source. Called for every floating
// address, LB ingress address and Service externalIP the agent programs; a
// no-op unless the address arrives on a non-default link, so single-NIC nodes
// are unchanged. Which link that is — see floatFacts.bindLink.
func (m *Manager) EnsureFloatingUplink(publicIP string) error {
	ip := net.ParseIP(publicIP)
	if ip == nil || ip.To4() == nil {
		return nil // v6 floating-uplink selection: with v6 floating support
	}
	routes, err := netlink.RouteGet(ip)
	if e := routeLookupErr(publicIP, len(routes), err); e != nil {
		return e
	}
	r := routes[0]
	facts := factsFor(r, m.uplinkIfindex)
	if facts.needsOwner() {
		if facts.OwnerLink, facts.OwnerUsable, err = addrOwnerLink(ip); err != nil {
			return fmt.Errorf("owner lookup for %s: %w", publicIP, err)
		}
	}

	idx, err := facts.bindLink()
	if err != nil {
		return fmt.Errorf("floating uplink for %s: %w", publicIP, err)
	}
	if idx == 0 {
		return nil
	}
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return fmt.Errorf("floating uplink link %d: %w", idx, err)
	}
	return m.bindFloatUplink(link, ip, r.Gw)
}

// bindFloatUplink attaches from_uplink at link's ingress and programs the egress
// ifindex, the covering subnet and the off-subnet next-hop. gw is the FIB's next
// hop for a routed address: the VIP is then off this link's subnet, so the
// router anchors the lookup and is itself the next-hop.
func (m *Manager) bindFloatUplink(link netlink.Link, ip, gw net.IP) error {
	idx := link.Attrs().Index
	if !carriesWire(linkInfoOf(link)) {
		return fmt.Errorf("floating uplink %s cannot carry traffic from the wire", link.Attrs().Name)
	}
	anchor := ip
	if gw != nil {
		anchor = gw
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("floating uplink %s addrs: %w", link.Attrs().Name, err)
	}
	subnet, firstHost := coveringSubnet(addrs, anchor)
	if subnet == nil {
		// A zero CFG_FLOAT_NH resolves replies via the DEFAULT link's gateway
		// while forcing them out this one, and the slot is global — it would
		// break every floating and LB reply on the node.
		return fmt.Errorf("floating uplink %s carries no subnet covering %s", link.Attrs().Name, anchor)
	}
	nh := firstHost
	if gw != nil {
		nh = gw
	}

	// Serialized: several watchers call this on the same event cascade, and a
	// concurrent attach would tear down the winner's pinned link (see floatMu).
	var nhv uint32
	if nh4 := nh.To4(); nh4 != nil {
		nhv = binary.NativeEndian.Uint32(nh4)
	}
	want := floatBinding{
		ifindex: idx,
		nh:      nhv,
		base:    binary.NativeEndian.Uint32(subnet.IP.To4()),
		mask:    binary.NativeEndian.Uint32(net.IP(subnet.Mask).To4()),
	}

	m.floatMu.Lock()
	defer m.floatMu.Unlock()
	if !floatNeedsProgram(m.floatBound, want) {
		return nil // already configured this run
	}
	if floatRebind(m.floatBound, want) {
		// One slot: the loser keeps from_uplink attached and the two flip on
		// every resync.
		slog.Default().Warn("floating uplink re-bound to a different link; two links are contending for the single slot",
			"from", m.floatBound.ifindex, "to", idx, "link", link.Attrs().Name)
	}

	if err := AttachIngress(idx, m.objs.CozyplaneFromUplink); err != nil {
		return fmt.Errorf("attach from_uplink on %s: %w", link.Attrs().Name, err)
	}
	// Vestigial: nothing reads this map; written to keep its pinned shape.
	var v overlayCozyMac
	copy(v.Addr[:], link.Attrs().HardwareAddr)
	if err := m.objs.FloatUplinkMac.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set floating uplink mac: %w", err)
	}
	if err := m.objs.Params.Put(cfgFloatNH, want.nh); err != nil {
		return fmt.Errorf("set floating next-hop: %w", err)
	}
	fn := overlayFloatNet{Base: want.base, Mask: want.mask}
	if err := m.objs.FloatNet.Put(uint32(0), &fn); err != nil {
		return fmt.Errorf("set floating subnet: %w", err)
	}
	// Last: the ifindex is the commit point, so the datapath never sees the new
	// link paired with the previous subnet and next-hop.
	if err := m.objs.Params.Put(cfgFloatIfindex, uint32(idx)); err != nil {
		return fmt.Errorf("set floating uplink ifindex: %w", err)
	}
	m.floatBound = want
	return nil
}

// floatBinding is everything the single floating slot holds. Comparing the whole
// binding, not just the link, catches two addresses that share a link but
// resolve different next-hops — the second used to be discarded silently.
type floatBinding struct {
	ifindex    int
	nh         uint32
	base, mask uint32
}

// floatNeedsProgram reports whether the slot must be rewritten. The comparison
// is over the whole binding: two addresses can share a link and still resolve
// different next-hops, and keying on the link alone dropped the second.
func floatNeedsProgram(cur, want floatBinding) bool { return cur != want }

// floatRebind reports that the slot is being moved to a different link.
func floatRebind(cur, next floatBinding) bool {
	return cur.ifindex != 0 && next.ifindex != 0 && cur.ifindex != next.ifindex
}

// SetFloating records the 1:1 mapping in both directions: floating[publicIP] =
// {net, VPC IP} for inbound DNAT, and floating_egress[{net, VPC IP}] = publicIP
// for the pod's outbound SNAT. net is the target pod's network id (its VNI). No
// conntrack — the datapath is stateless in both directions.
func (m *Manager) SetFloating(publicIP, vpcIP string, net_ uint32) error {
	pub, err := addr128Str(publicIP)
	if err != nil {
		return fmt.Errorf("public IP: %w", err)
	}
	vpc, err := addr128Str(vpcIP)
	if err != nil {
		return fmt.Errorf("vpc IP: %w", err)
	}
	if err := m.objs.Floating.Put(&pub, &overlayBridgeEp{Net: net_, VpcIp: vpc}); err != nil {
		return fmt.Errorf("set floating %s: %w", publicIP, err)
	}
	if err := m.objs.FloatingEgress.Put(&overlayLocalKey{Net: net_, Ip: vpc}, &pub); err != nil {
		return fmt.Errorf("set floating egress %s: %w", publicIP, err)
	}
	return nil
}

// DelFloating removes a public IP from both directions of the floating map
// (idempotent). The reverse entry is keyed by {net, VPC IP}, recovered from the
// forward entry — and deleted only while it still points at THIS public IP.
// When a live target's address is reassigned (the LB implementation re-pins it —
// e.g. a claim's driver moving the pin onto a fresh Service), the watcher sets
// the new address before removing the stale one, so the egress entry already
// maps the target to the NEW address; deleting it blindly would sever the
// reply path (found live on dev4: every SYN-ACK left unSNAT'd and the claimed
// address black-holed).
func (m *Manager) DelFloating(publicIP string) error {
	pub, err := addr128Str(publicIP)
	if err != nil {
		return fmt.Errorf("public IP: %w", err)
	}
	var ep overlayBridgeEp
	if err := m.objs.Floating.Lookup(&pub, &ep); err == nil {
		key := overlayLocalKey{Net: ep.Net, Ip: ep.VpcIp}
		var cur overlayAddr128
		if err := m.objs.FloatingEgress.Lookup(&key, &cur); err == nil && cur == pub {
			_ = m.objs.FloatingEgress.Delete(&key)
		}
	}
	if err := m.objs.Floating.Delete(&pub); err != nil && !isNotExist(err) {
		return fmt.Errorf("del floating %s: %w", publicIP, err)
	}
	return nil
}

// SetInternal makes the internal map exactly `cidrs` — the cluster-internal
// networks (pod/service/node) a floating pod's egress must not float to (it
// bypasses the VPC gateway that would otherwise deny them). Diffed against the
// pinned map like SyncMasqSources: the map outlives the agent, so a CIDR
// removed from --internal-cidrs must be PRUNED — a stale entry silently
// reclassifies destinations as internal and drops floating replies to them
// (bit us on the dev cluster: a leftover node-net entry FLOAT_MISSed every reply to a
// VLAN client into the closed-island drop).
func (m *Manager) SetInternal(cidrs []string) error {
	want := map[overlayLpmKey]bool{}
	for _, c := range cidrs {
		key, err := lpmKey(0, c)
		if err != nil {
			return err
		}
		want[key] = true
	}
	var key overlayLpmKey
	var val uint8
	var stale []overlayLpmKey
	it := m.objs.Internal.Iterate()
	for it.Next(&key, &val) {
		if !want[key] {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate internal: %w", err)
	}
	for _, k := range stale {
		if err := m.objs.Internal.Delete(&k); err != nil && !isNotExist(err) {
			return err
		}
	}
	var one uint8 = 1
	for k := range want {
		if err := m.objs.Internal.Put(&k, one); err != nil {
			return fmt.Errorf("set internal: %w", err)
		}
	}
	return nil
}

// Floatings returns the public IPs currently programmed in the floating map, so
// a restarted agent can prune entries whose FloatingIPs or target Ports vanished
// while it was down.
func (m *Manager) Floatings() (map[string]bool, error) {
	out := map[string]bool{}
	var key overlayAddr128
	var ep overlayBridgeEp
	it := m.objs.Floating.Iterate()
	for it.Next(&key, &ep) {
		out[addr128ToIP(key).String()] = true
	}
	return out, it.Err()
}

// Cozyplane does not ATTRACT a floating address — it delivers one
// (docs/north-south.md, tenet 3). Something else must make the fabric hand the
// address to a node: a CCM assigning it to a VNIC, MetalLB, a static route, an
// address configured on a node. Because from_uplink sits at tc ingress, ahead of
// the kernel's routing decision, delivery works however that was arranged and to
// whichever node the address lands on — the pod is found through `floating` and
// reached over the overlay if it lives elsewhere.
