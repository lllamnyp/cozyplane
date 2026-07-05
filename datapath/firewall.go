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

	"github.com/coreos/go-iptables/iptables"
)

// EnsureForwardRules accepts overlay traffic in the FORWARD chain ahead of
// kube-proxy's rules — per family, and only where kube-proxy exists (#10).
//
// Pod egress is encapsulated by an eBPF tc redirect, which bypasses conntrack.
// The decapsulated reply that returns on the Geneve device therefore has no
// matching conntrack entry and kube-proxy's "ctstate INVALID -j DROP" rule in
// KUBE-FORWARD discards it. Inserting an explicit ACCEPT for the Geneve device
// at the top of FORWARD lets decapsulated traffic through before that drop.
// kube-proxy programs the INVALID drop into ip6tables too, so both families
// need it — a v4-only ACCEPT dropped cross-node v6 north-south replies.
//
// The rule exists to counter kube-proxy's, so it is installed per family only
// when that family's KUBE-FORWARD chain does: on a kube-proxy-replacement node
// there is no drop to dodge, nothing is installed, and an unusable netfilter
// is a skip, not an error — cozyplane must not hard-require netfilter on nodes
// where nothing else uses it. (The rule cannot be designed away while an
// iptables kube-proxy is present: ClusterIP replies must traverse the client
// node's conntrack to reverse the service DNAT, which is why from_overlay
// hands default-network traffic to the kernel at all.)
// Returns the families the rules were installed for, for the agent's log.
func EnsureForwardRules() ([]string, error) {
	var installed []string
	for _, proto := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		name := "v4"
		if proto == iptables.ProtocolIPv6 {
			name = "v6"
		}
		ipt, err := iptables.NewWithProtocol(proto)
		if err != nil {
			continue // no iptables for this family: nothing installs drops either
		}
		if ok, err := ipt.ChainExists("filter", "KUBE-FORWARD"); err != nil || !ok {
			continue // no kube-proxy in this family; no INVALID drop to dodge
		}
		for _, spec := range [][]string{
			{"-i", GeneveDevice, "-j", "ACCEPT"},
			{"-o", GeneveDevice, "-j", "ACCEPT"},
		} {
			if err := ipt.InsertUnique("filter", "FORWARD", 1, spec...); err != nil {
				return installed, fmt.Errorf("insert FORWARD rule %v (%s): %w", spec, name, err)
			}
		}
		installed = append(installed, name)
	}
	return installed, nil
}

// masqChain holds the node masquerade policy.
const masqChain = "COZYPLANE-MASQ"

// EnsureMasquerade SNATs pod traffic leaving the cluster to this node's
// address (the flannel-style rule): without it pods have no return path from
// anything beyond the cluster, because pod CIDRs aren't routable outside.
//
// The rule must NOT be scoped to a single uplink (nodes may be multi-homed —
// e.g. internet via eth0, the node subnet via eth1) but must exclude every
// cozyplane-owned egress interface: a packet leaving via a pod veth or the
// Geneve device is a *delivery into the overlay* (e.g. a VPC gateway's reply
// carrying a cluster-CIDR source toward a tenant address) and must not be
// re-sourced on the way.
func EnsureMasquerade(clusterCIDR string) error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}
	if exists, err := ipt.ChainExists("nat", masqChain); err != nil {
		return fmt.Errorf("check %s chain: %w", masqChain, err)
	} else if !exists {
		if err := ipt.NewChain("nat", masqChain); err != nil {
			return fmt.Errorf("create %s chain: %w", masqChain, err)
		}
	}
	for _, spec := range [][]string{
		{"-o", GeneveDevice, "-j", "RETURN"},
		{"-o", "cph+", "-j", "RETURN"}, // pod veths
		{"-o", "cpg+", "-j", "RETURN"}, // gateway VPC-leg veths
		{"-j", "MASQUERADE"},
	} {
		if err := ipt.AppendUnique("nat", masqChain, spec...); err != nil {
			return fmt.Errorf("append %s rule %v: %w", masqChain, spec, err)
		}
	}
	spec := []string{"-s", clusterCIDR, "!", "-d", clusterCIDR, "-j", masqChain}
	if err := ipt.AppendUnique("nat", "POSTROUTING", spec...); err != nil {
		return fmt.Errorf("append MASQUERADE jump: %w", err)
	}
	return nil
}
