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
	"net"

	"github.com/vishvananda/netlink"
)

// A floating IP is the north-south bridge turned outward: a routable public
// address mapped 1:1 to a pod's (net, VPC IP), with the external client's source
// preserved. Unlike the fabric bridge it needs no /32 route — from_uplink
// intercepts the address at the node uplink's tc ingress (before kernel routing)
// and redirects it into the pod's veth, where to_pod DNATs public->VPC. Here we
// only publish the mapping in the pinned `floating` map the datapath keys on; the
// agent advertises the address (ARP/NDP) separately, from the pod's own node.

// floatFacts are the facts about one external address that decide where, if
// anywhere, the floating machinery binds.
type floatFacts struct {
	// RouteLink is the ifindex the FIB would send out of; 0 if it named none.
	RouteLink int
	// RouteGw is the next hop the FIB named; nil for an on-link or local answer.
	RouteGw net.IP
	// RouteViaLo records that the FIB answered "local" — the node owns this
	// address.
	RouteViaLo bool
	// OwnerLink is the ifindex the address is CONFIGURED on; 0 if it is not
	// ours. Only meaningful when RouteViaLo.
	OwnerLink int
	// DefaultUplink is the ifindex from_uplink is already attached to.
	DefaultUplink int
}

// bindLink resolves which link's ingress must carry the floating machinery for
// this address, or 0 when there is nothing to program. Addresses owned by the
// node's own interfaces are special-cased: the FIB answers "via lo" for them,
// so OwnerLink and not RouteLink decides.
//
// See docs/lb-ingress.md § "Node-owned external addresses".
func (f floatFacts) bindLink() (int, error) {
	switch {
	case f.RouteGw != nil:
		// Routed to us from elsewhere (a routed pool): it arrives on the
		// default uplink, which is already hooked.
		return 0, nil

	case f.RouteViaLo:
		// The node's own address.
		switch {
		case f.OwnerLink == 0:
			return 0, fmt.Errorf("address is local to this node but configured on no link")
		case f.OwnerLink == f.RouteLink:
			// RouteViaLo means RouteLink IS the loopback, so this says the
			// owner resolved to lo. Refuse rather than bind it.
			return 0, fmt.Errorf("address is local and its owning link resolved to the loopback")
		case f.OwnerLink == f.DefaultUplink:
			// Arrives where from_uplink already is, and the default route
			// resolves an off-subnet reply. Nothing to program.
			return 0, nil
		default:
			return f.OwnerLink, nil
		}

	case f.RouteLink == 0, f.RouteLink == f.DefaultUplink:
		return 0, nil

	default:
		// On-link on a non-default NIC: the floating case.
		return f.RouteLink, nil
	}
}

// addrOwnerLink returns the ifindex of the link ip is configured on, or 0 if
// the address is not the node's own.
func addrOwnerLink(ip net.IP) (int, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		if l.Attrs().Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
		if err != nil {
			continue // a link that vanished mid-scan is not the owner
		}
		for _, a := range addrs {
			if a.IP != nil && a.IP.Equal(ip) {
				return l.Attrs().Index, nil
			}
		}
	}
	return 0, nil
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
	if err != nil || len(routes) == 0 {
		return fmt.Errorf("route lookup for %s: %w", publicIP, err)
	}
	r := routes[0]
	facts := floatFacts{RouteLink: r.LinkIndex, RouteGw: r.Gw, DefaultUplink: m.uplinkIfindex}

	// The address lookup is only worth its cost when the FIB answered "local",
	// so the attracted-address path stays one route lookup.
	var routeLink netlink.Link
	if r.Gw == nil && r.LinkIndex != 0 {
		if routeLink, err = netlink.LinkByIndex(r.LinkIndex); err != nil {
			return fmt.Errorf("floating uplink link %d: %w", r.LinkIndex, err)
		}
		if routeLink.Attrs().Flags&net.FlagLoopback != 0 {
			facts.RouteViaLo = true
			if facts.OwnerLink, err = addrOwnerLink(ip); err != nil {
				return fmt.Errorf("owner lookup for %s: %w", publicIP, err)
			}
		}
	}

	idx, err := facts.bindLink()
	if err != nil {
		return fmt.Errorf("floating uplink for %s: %w", publicIP, err)
	}
	if idx == 0 {
		return nil
	}

	link := routeLink
	if link == nil || link.Attrs().Index != idx {
		if link, err = netlink.LinkByIndex(idx); err != nil {
			return fmt.Errorf("floating uplink link %d: %w", idx, err)
		}
	}
	return m.bindFloatUplink(link, ip)
}

// bindFloatUplink attaches from_uplink at link's ingress and programs the four
// facts the datapath needs to emit a reply out of it: the egress ifindex, the
// source MAC, the covering subnet, and the off-subnet next-hop.
func (m *Manager) bindFloatUplink(link netlink.Link, ip net.IP) error {
	idx := link.Attrs().Index
	// Serialized: several watchers call this on the same event cascade, and a
	// concurrent attach would tear down the winner's pinned link (see floatMu).
	m.floatMu.Lock()
	defer m.floatMu.Unlock()
	if m.floatIfindex == idx {
		return nil // already configured this run
	}
	// Every real NIC has one; a link without is mis-selected.
	mac := link.Attrs().HardwareAddr
	if len(mac) != 6 {
		return fmt.Errorf("floating uplink %s has no MAC", link.Attrs().Name)
	}

	// The covering subnet's first host = the fabric's virtual router; the
	// subnet itself lets the datapath tell on-subnet destinations (their own
	// neighbour) from off-subnet ones (via the router — see float_net).
	var nh net.IP
	var subnet *net.IPNet
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("floating uplink %s addrs: %w", link.Attrs().Name, err)
	}
	for _, a := range addrs {
		if a.IPNet != nil && a.IPNet.Contains(ip) {
			base := a.IPNet.IP.Mask(a.IPNet.Mask).To4()
			nh = net.IPv4(base[0], base[1], base[2], base[3]+1)
			subnet = a.IPNet
			break
		}
	}

	// from_uplink at the floating link's ingress: inbound DNAT.
	if err := AttachIngress(idx, m.objs.CozyplaneFromUplink); err != nil {
		return fmt.Errorf("attach from_uplink on %s: %w", link.Attrs().Name, err)
	}
	var v overlayCozyMac
	copy(v.Addr[:], mac)
	if err := m.objs.FloatUplinkMac.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set floating uplink mac: %w", err)
	}
	if err := m.objs.Params.Put(cfgFloatIfindex, uint32(idx)); err != nil {
		return fmt.Errorf("set floating uplink ifindex: %w", err)
	}
	var nhv uint32
	if nh4 := nh.To4(); nh4 != nil {
		nhv = binary.NativeEndian.Uint32(nh4)
	}
	if err := m.objs.Params.Put(cfgFloatNH, nhv); err != nil {
		return fmt.Errorf("set floating next-hop: %w", err)
	}
	var fn overlayFloatNet
	if subnet != nil {
		fn.Base = binary.NativeEndian.Uint32(subnet.IP.Mask(subnet.Mask).To4())
		fn.Mask = binary.NativeEndian.Uint32(net.IP(subnet.Mask).To4())
	}
	if err := m.objs.FloatNet.Put(uint32(0), &fn); err != nil {
		return fmt.Errorf("set floating subnet: %w", err)
	}
	m.floatIfindex = idx
	m.floatMAC = mac
	return nil
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
