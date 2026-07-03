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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// GatewayIP is the link-local next hop every pod routes through. The bridge
// masquerades node->pod traffic to this address so a tenant pod never sees a
// fabric/node address; the pod replies here and the eBPF datapath reverses it.
// It must match linkLocalGW in the CNI plugin and LINK_LOCAL_GW in bpf/overlay.c.
const GatewayIP = "169.254.1.1"

// The dual-address bridge gives a VPC pod a unique fabric IP (its status.podIP,
// from the node pod CIDR) while its interface carries the (tenant) VPC IP.
// North-south traffic to the fabric IP is DNATed to the VPC IP and its client
// masqueraded to the gateway; the pod's reply is reversed. All of that NAT lives
// in the eBPF datapath (to_pod/from_pod, see bpf/overlay.c) — there is no
// iptables, no fwmark, no policy routing. Here we only:
//
//   - route the (unique) fabric IP to the pod's veth, so node-originated
//     traffic (kubelet probes) reaches to_pod, and
//   - publish the fabric IP -> {net, VPC IP} mapping in the pinned `bridges`
//     map the datapath keys on.
//
// Because fabric IPs are unique, the /32 route never collides even when two
// same-node pods share a VPC IP (overlapping CIDRs).

// AddBridge routes the fabric IP to the pod's veth and records the pod's
// (net, VPC IP) in the bridges map. net is the pod's network id (its VNI).
func AddBridge(fabricIP, vpcIP, hostVeth string, net_ uint32) error {
	if err := addFabricRoute(fabricIP, hostVeth); err != nil {
		return err
	}
	if err := setBridge(fabricIP, vpcIP, net_); err != nil {
		return err
	}
	return nil
}

// DelBridge removes the fabric route and the bridges-map entry (idempotent).
func DelBridge(fabricIP, hostVeth string) error {
	rerr := delFabricRoute(fabricIP, hostVeth)
	berr := delBridge(fabricIP)
	if rerr != nil {
		return rerr
	}
	return berr
}

// addFabricRoute installs the /32 route fabricIP -> pod veth in the main table.
// Fabric IPs are unique per node, so this never collides; it exists so the
// kernel can deliver node-originated (OUTPUT-path) traffic to the veth, where
// to_pod performs the DNAT.
func addFabricRoute(fabricIP, hostVeth string) error {
	link, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", hostVeth, err)
	}
	route, err := fabricRoute(fabricIP, link.Attrs().Index)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add fabric route %s dev %s: %w", fabricIP, hostVeth, err)
	}
	return nil
}

func delFabricRoute(fabricIP, hostVeth string) error {
	link, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return nil // veth already gone; the route went with it
	}
	route, err := fabricRoute(fabricIP, link.Attrs().Index)
	if err != nil {
		return err
	}
	if err := netlink.RouteDel(route); err != nil && !isNotExist(err) {
		return fmt.Errorf("del fabric route %s: %w", fabricIP, err)
	}
	return nil
}

func fabricRoute(fabricIP string, ifindex int) (*netlink.Route, error) {
	ip := net.ParseIP(fabricIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("fabric IP %q is not IPv4", fabricIP)
	}
	return &netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Scope:     netlink.SCOPE_LINK,
	}, nil
}

// setBridge writes bridges[fabricIP] = {net, vpcIP} in the pinned map (used by
// the CNI plugin, like SetLocal).
func setBridge(fabricIP, vpcIP string, net_ uint32) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "bridges"), nil)
	if err != nil {
		return fmt.Errorf("open pinned bridges map: %w", err)
	}
	defer m.Close()

	fip, err := addr128Str(fabricIP)
	if err != nil {
		return fmt.Errorf("fabric IP: %w", err)
	}
	vip, err := addr128Str(vpcIP)
	if err != nil {
		return fmt.Errorf("vpc IP: %w", err)
	}
	ep := overlayBridgeEp{Net: net_, VpcIp: vip}
	if err := m.Put(fip, &ep); err != nil {
		return fmt.Errorf("set bridge: %w", err)
	}
	return nil
}

// delBridge removes a fabric IP from the bridges map.
func delBridge(fabricIP string) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "bridges"), nil)
	if err != nil {
		return fmt.Errorf("open pinned bridges map: %w", err)
	}
	defer m.Close()

	fip, err := addr128Str(fabricIP)
	if err != nil {
		return fmt.Errorf("fabric IP: %w", err)
	}
	if err := m.Delete(fip); err != nil && !isNotExist(err) {
		return fmt.Errorf("del bridge: %w", err)
	}
	return nil
}
