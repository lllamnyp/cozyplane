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

// AdvertiseFloating answers ARP for a public IP on the uplink so the physical
// fabric delivers it to this node — a per-address proxy neighbour (NTF_PROXY),
// which responds for exactly this IP and needs no global proxy_arp. Idempotent.
func AdvertiseFloating(publicIP, uplink string) error {
	neigh, err := floatingProxyNeigh(publicIP, uplink)
	if err != nil {
		return err
	}
	if err := netlink.NeighAdd(neigh); err != nil && !isExist(err) {
		return fmt.Errorf("advertise floating %s on %s: %w", publicIP, uplink, err)
	}
	return nil
}

// UnadvertiseFloating removes the proxy-ARP entry for a public IP (idempotent).
func UnadvertiseFloating(publicIP, uplink string) error {
	neigh, err := floatingProxyNeigh(publicIP, uplink)
	if err != nil {
		return err
	}
	if err := netlink.NeighDel(neigh); err != nil && !isNotExist(err) {
		return fmt.Errorf("unadvertise floating %s on %s: %w", publicIP, uplink, err)
	}
	return nil
}

func floatingProxyNeigh(publicIP, uplink string) (*netlink.Neigh, error) {
	link, err := netlink.LinkByName(uplink)
	if err != nil {
		return nil, fmt.Errorf("lookup uplink %s: %w", uplink, err)
	}
	ip := net.ParseIP(publicIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("public IP %q is not IPv4", publicIP)
	}
	return &netlink.Neigh{
		LinkIndex: link.Attrs().Index,
		Family:    netlink.FAMILY_V4,
		Flags:     netlink.NTF_PROXY,
		IP:        ip,
	}, nil
}
