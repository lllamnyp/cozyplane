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

	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

// GatewayIP is the link-local next hop every pod routes through. The bridge
// masquerades node->pod traffic to this address so a tenant pod never sees a
// fabric/node address; replies come back here and conntrack reverses them. It
// must match linkLocalGW in the CNI plugin and the exemption in bpf/overlay.c.
const GatewayIP = "169.254.1.1"

// bridgeChain is the nat chain holding per-pod fabric->VPC DNAT rules.
const bridgeChain = "COZYPLANE-BRIDGE"

const (
	// bridgeTableBase offsets the per-pod routing tables well clear of the
	// main/local/default tables and any Cozystack/Talos custom tables.
	bridgeTableBase = 0x00C0_0000
	// bridgeRuleBase is the ip-rule priority band (base + fabric offset), so
	// each pod's rule has a unique, deterministic priority for exact deletion.
	// It MUST sort before the main table (priority 32766): the main table's
	// default route would otherwise match the post-DNAT VPC IP first and the
	// fwmark rule would never be consulted. 100 + a 12-bit offset stays well
	// under 32766 and above the local table (0).
	bridgeRuleBase = 100
	// bridgeMarkShift places the per-pod selector in fwmark bits [16..27],
	// avoiding kube-proxy (0x4000/0x8000) and Cilium's low magic marks.
	bridgeMarkShift = 16
	bridgeMarkMask  = 0x0FFF_0000
)

// The dual-address bridge gives a VPC pod a unique fabric IP (its status.podIP,
// node-reachable via the default overlay) while the pod's interface carries the
// (tenant) VPC IP. Node/Service traffic to the fabric IP is DNATed to the VPC IP
// and its source masqueraded to the gateway; conntrack reverses the pod's reply.
//
// Under overlapping VPC CIDRs two pods on one node can share a VPC IP, so the
// post-DNAT destination alone can't pick the right veth. The fabric IP *is*
// unique (from the node pod CIDR), so we derive a per-pod routing table and
// fwmark from the fabric IP's offset within that CIDR (deterministic, no
// allocator), mark the packet by its fabric IP before conntrack DNAT, and route
// the post-DNAT packet by that mark. The return path is plain kernel conntrack.

// EnsureBridgeChain creates the bridge nat chain and hooks it into PREROUTING and
// OUTPUT (so both forwarded and node-local traffic to a fabric IP is translated).
func EnsureBridgeChain() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}
	for _, tc := range []struct{ table, chain string }{
		{"nat", bridgeChain},
		{"mangle", bridgeChain},
	} {
		if exists, err := ipt.ChainExists(tc.table, tc.chain); err != nil {
			return err
		} else if !exists {
			if err := ipt.NewChain(tc.table, tc.chain); err != nil {
				return fmt.Errorf("create %s/%s chain: %w", tc.table, tc.chain, err)
			}
		}
	}
	for _, hook := range []string{"PREROUTING", "OUTPUT"} {
		// mangle runs before nat DNAT, so the MARK sees the original fabric dst.
		if err := ipt.AppendUnique("mangle", hook, "-j", bridgeChain); err != nil {
			return fmt.Errorf("hook mangle %s -> %s: %w", hook, bridgeChain, err)
		}
		if err := ipt.AppendUnique("nat", hook, "-j", bridgeChain); err != nil {
			return fmt.Errorf("hook nat %s -> %s: %w", hook, bridgeChain, err)
		}
	}
	return nil
}

// AddBridge installs the per-pod bridge: the fabric->VPC DNAT, the source
// masquerade to the gateway, the fabric-IP fwmark, and the mark-selected route
// to the pod's veth (so two same-node pods sharing a VPC IP still deliver
// correctly). podCIDR is this node's pod CIDR, which the fabric IP belongs to.
func AddBridge(fabricIP, vpcIP, hostVeth, podCIDR string) error {
	off, err := fabricOffset(fabricIP, podCIDR)
	if err != nil {
		return err
	}
	mark := off << bridgeMarkShift
	table := bridgeTableBase + int(off)

	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	// Mark the packet by its (unique) fabric IP, before conntrack DNAT rewrites
	// the destination, touching only our fwmark bits.
	if err := ipt.AppendUnique("mangle", bridgeChain,
		"-d", fabricIP, "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", mark, bridgeMarkMask)); err != nil {
		return fmt.Errorf("add fabric mark %s: %w", fabricIP, err)
	}
	if err := ipt.AppendUnique("nat", bridgeChain,
		"-d", fabricIP, "-j", "DNAT", "--to-destination", vpcIP); err != nil {
		return fmt.Errorf("add DNAT %s->%s: %w", fabricIP, vpcIP, err)
	}
	if err := ipt.AppendUnique("nat", "POSTROUTING",
		"-d", vpcIP, "-o", hostVeth, "-m", "conntrack", "--ctstate", "DNAT",
		"-j", "SNAT", "--to-source", GatewayIP); err != nil {
		return fmt.Errorf("add SNAT for %s: %w", vpcIP, err)
	}
	if err := addBridgeRoute(mark, table, vpcIP, hostVeth); err != nil {
		return err
	}
	return nil
}

// DelBridge removes the per-pod rules added by AddBridge (idempotent).
func DelBridge(fabricIP, vpcIP, hostVeth, podCIDR string) error {
	off, err := fabricOffset(fabricIP, podCIDR)
	if err != nil {
		return err
	}
	mark := off << bridgeMarkShift
	table := bridgeTableBase + int(off)

	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	merr := ipt.DeleteIfExists("mangle", bridgeChain,
		"-d", fabricIP, "-j", "MARK", "--set-xmark", fmt.Sprintf("0x%x/0x%x", mark, bridgeMarkMask))
	derr := ipt.DeleteIfExists("nat", bridgeChain,
		"-d", fabricIP, "-j", "DNAT", "--to-destination", vpcIP)
	serr := ipt.DeleteIfExists("nat", "POSTROUTING",
		"-d", vpcIP, "-o", hostVeth, "-m", "conntrack", "--ctstate", "DNAT",
		"-j", "SNAT", "--to-source", GatewayIP)
	rerr := delBridgeRoute(mark, table, vpcIP, hostVeth)
	for _, e := range []error{merr, derr, serr, rerr} {
		if e != nil {
			return e
		}
	}
	return nil
}

// addBridgeRoute installs the ip rule (fwmark -> table) and the table's route
// (vpcIP/32 -> pod veth). Idempotent.
func addBridgeRoute(mark uint32, table int, vpcIP, hostVeth string) error {
	link, err := netlink.LinkByName(hostVeth)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", hostVeth, err)
	}
	rule := bridgeRule(mark, table)
	if err := netlink.RuleAdd(rule); err != nil && !isExist(err) {
		return fmt.Errorf("add ip rule fwmark 0x%x table %d: %w", mark, table, err)
	}
	route, err := bridgeVPCRoute(vpcIP, link.Attrs().Index, table)
	if err != nil {
		return err
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("add route %s dev %s table %d: %w", vpcIP, hostVeth, table, err)
	}
	return nil
}

func delBridgeRoute(mark uint32, table int, vpcIP, hostVeth string) error {
	if err := netlink.RuleDel(bridgeRule(mark, table)); err != nil && !isNotExist(err) {
		return fmt.Errorf("del ip rule fwmark 0x%x: %w", mark, err)
	}
	if link, err := netlink.LinkByName(hostVeth); err == nil {
		if route, err := bridgeVPCRoute(vpcIP, link.Attrs().Index, table); err == nil {
			if err := netlink.RouteDel(route); err != nil && !isNotExist(err) {
				return fmt.Errorf("del route %s table %d: %w", vpcIP, table, err)
			}
		}
	}
	return nil
}

func bridgeRule(mark uint32, table int) *netlink.Rule {
	r := netlink.NewRule()
	r.Mark = mark
	r.Mask = new(uint32(bridgeMarkMask))
	r.Table = table
	r.Priority = bridgeRuleBase + int(mark>>bridgeMarkShift)
	return r
}

func bridgeVPCRoute(vpcIP string, ifindex, table int) (*netlink.Route, error) {
	ip := net.ParseIP(vpcIP).To4()
	if ip == nil {
		return nil, fmt.Errorf("vpc IP %q is not IPv4", vpcIP)
	}
	return &netlink.Route{
		LinkIndex: ifindex,
		Dst:       &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Table:     table,
		Scope:     netlink.SCOPE_LINK,
	}, nil
}

// fabricOffset returns the fabric IP's offset within the node pod CIDR — a
// per-pod, collision-free id derived from the (unique) fabric IP.
func fabricOffset(fabricIP, podCIDR string) (uint32, error) {
	fip := net.ParseIP(fabricIP).To4()
	if fip == nil {
		return 0, fmt.Errorf("fabric IP %q is not IPv4", fabricIP)
	}
	_, ipnet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return 0, fmt.Errorf("parse pod CIDR %q: %w", podCIDR, err)
	}
	base := ipnet.IP.To4()
	if base == nil {
		return 0, fmt.Errorf("pod CIDR %q is not IPv4", podCIDR)
	}
	off := binary.BigEndian.Uint32(fip) - binary.BigEndian.Uint32(base)
	if off > (bridgeMarkMask >> bridgeMarkShift) {
		return 0, fmt.Errorf("fabric IP %q offset %d in %q exceeds the bridge id space", fabricIP, off, podCIDR)
	}
	return off, nil
}
