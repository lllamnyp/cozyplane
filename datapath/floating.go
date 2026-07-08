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

// EnsureFloatingUplink makes the datapath serve a floating address from the
// link that actually owns it. The FIB is authoritative: if the address is
// on-link on a NON-default interface (e.g. an OCI L2 VLAN carrying the floating
// range, while the default route rides the native, spoof-guarded NIC), floating
// must attach, answer ARP/NDP, announce, and egress THERE — binding it to the
// default uplink is a bug (the announcement goes to the wrong segment and the
// egress leaves a spoof-guarded NIC with a foreign source). Called by the agent
// for every floating address it programs; a no-op when the address is off-link
// (a routed pool) or on the default uplink, so single-NIC nodes are unchanged.
//
// The off-subnet next-hop is the covering subnet's first host — the L2 fabric's
// virtual router by convention (OCI, and most gateways) — since the node's FIB
// carries no route via that link.
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
	if r.Gw != nil || r.LinkIndex == 0 || r.LinkIndex == m.uplinkIfindex {
		return nil // routed pool, or already the default uplink
	}
	if m.floatIfindex == r.LinkIndex {
		return nil // already configured this run
	}
	link, err := netlink.LinkByIndex(r.LinkIndex)
	if err != nil {
		return fmt.Errorf("floating uplink link %d: %w", r.LinkIndex, err)
	}
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

	// from_uplink at the floating link's ingress: ARP answers + inbound DNAT.
	if err := AttachIngress(r.LinkIndex, m.objs.CozyplaneFromUplink); err != nil {
		return fmt.Errorf("attach from_uplink on %s: %w", link.Attrs().Name, err)
	}
	var v overlayCozyMac
	copy(v.Addr[:], mac)
	if err := m.objs.FloatUplinkMac.Put(uint32(0), &v); err != nil {
		return fmt.Errorf("set floating uplink mac: %w", err)
	}
	if err := m.objs.Params.Put(cfgFloatIfindex, uint32(r.LinkIndex)); err != nil {
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
	m.floatIfindex = r.LinkIndex
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
// forward entry.
func (m *Manager) DelFloating(publicIP string) error {
	pub, err := addr128Str(publicIP)
	if err != nil {
		return fmt.Errorf("public IP: %w", err)
	}
	var ep overlayBridgeEp
	if err := m.objs.Floating.Lookup(&pub, &ep); err == nil {
		_ = m.objs.FloatingEgress.Delete(&overlayLocalKey{Net: ep.Net, Ip: ep.VpcIp})
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
// (bit us on dev4: a leftover node-net entry FLOAT_MISSed every reply to a
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

// Advertisement is not a host-side operation: from_uplink answers ARP for a
// floating IP as long as it has an entry here with a live local pod (see
// floating_arp in bpf/overlay.c). Programming the map is the advertisement.
