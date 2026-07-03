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

// SetFloating records publicIP -> {net, VPC IP} in the floating map. net is the
// target pod's network id (its VNI). The reply reversal (VPC IP -> publicIP) is
// stateful in float_ct, managed entirely in the datapath.
func (m *Manager) SetFloating(publicIP, vpcIP string, net_ uint32) error {
	pip := net.ParseIP(publicIP).To4()
	vip := net.ParseIP(vpcIP).To4()
	if pip == nil || vip == nil {
		return fmt.Errorf("public %q / vpc %q not IPv4", publicIP, vpcIP)
	}
	ep := overlayBridgeEp{Net: net_, VpcIp: binary.LittleEndian.Uint32(vip)}
	if err := m.objs.Floating.Put(binary.LittleEndian.Uint32(pip), &ep); err != nil {
		return fmt.Errorf("set floating %s: %w", publicIP, err)
	}
	return nil
}

// DelFloating removes a public IP from the floating map (idempotent).
func (m *Manager) DelFloating(publicIP string) error {
	pip := net.ParseIP(publicIP).To4()
	if pip == nil {
		return fmt.Errorf("public IP %q is not IPv4", publicIP)
	}
	if err := m.objs.Floating.Delete(binary.LittleEndian.Uint32(pip)); err != nil && !isNotExist(err) {
		return fmt.Errorf("del floating %s: %w", publicIP, err)
	}
	return nil
}

// Floatings returns the public IPs currently programmed in the floating map, so
// a restarted agent can prune entries whose FloatingIPs or target Ports vanished
// while it was down.
func (m *Manager) Floatings() (map[string]bool, error) {
	out := map[string]bool{}
	var key uint32
	var ep overlayBridgeEp
	it := m.objs.Floating.Iterate()
	for it.Next(&key, &ep) {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, key)
		out[net.IP(b).String()] = true
	}
	return out, it.Err()
}

// AdvertiseFloating makes this node answer ARP for a public IP by assigning it
// as a /32 on the uplink. Proxy-ARP (pneigh) is unusable here: floating IPs are
// drawn from an L2 the node is already on, so the kernel treats the address as
// same-link and never proxies it. Assigning the /32 makes the kernel answer ARP
// for it as a local address; from_uplink still intercepts inbound packets at tc
// ingress before any local delivery, and replies leave via redirect_neigh (which
// sidesteps the martian-source check the local /32 would otherwise trigger).
// Idempotent.
func AdvertiseFloating(publicIP, uplink string) error {
	link, err := netlink.LinkByName(uplink)
	if err != nil {
		return fmt.Errorf("lookup uplink %s: %w", uplink, err)
	}
	addr, err := floatingAddr(publicIP)
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("advertise floating %s on %s: %w", publicIP, uplink, err)
	}
	return nil
}

// UnadvertiseFloating removes the /32 for a public IP from the uplink (idempotent).
func UnadvertiseFloating(publicIP, uplink string) error {
	link, err := netlink.LinkByName(uplink)
	if err != nil {
		return nil // uplink gone; the address went with it
	}
	addr, err := floatingAddr(publicIP)
	if err != nil {
		return err
	}
	if err := netlink.AddrDel(link, addr); err != nil && !isNotExist(err) {
		return fmt.Errorf("unadvertise floating %s on %s: %w", publicIP, uplink, err)
	}
	return nil
}

func floatingAddr(publicIP string) (*netlink.Addr, error) {
	ip := net.ParseIP(publicIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("public IP %q is not IPv4", publicIP)
	}
	return &netlink.Addr{IPNet: &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}}, nil
}
