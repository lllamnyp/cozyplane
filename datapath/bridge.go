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

// GatewayIP is the link-local next hop every pod routes through. The bridge
// masquerades node->pod traffic to this address so a tenant pod never sees a
// fabric/node address; replies come back here and conntrack reverses them. It
// must match linkLocalGW in the CNI plugin and the exemption in bpf/overlay.c.
const GatewayIP = "169.254.1.1"

// bridgeChain is the nat chain holding per-pod fabric->VPC DNAT rules.
const bridgeChain = "COZYPLANE-BRIDGE"

// The dual-address bridge gives a VPC pod a unique fabric IP (its status.podIP,
// node-reachable via the default overlay) while the pod's interface carries the
// (tenant) VPC IP. Node/Service traffic to the fabric IP is DNATed to the VPC IP
// and its source masqueraded to the gateway; conntrack reverses the pod's reply.

// EnsureBridgeChain creates the bridge nat chain and hooks it into PREROUTING and
// OUTPUT (so both forwarded and node-local traffic to a fabric IP is translated).
func EnsureBridgeChain() error {
	ipt, err := iptables.New()
	if err != nil {
		return fmt.Errorf("init iptables: %w", err)
	}
	if exists, err := ipt.ChainExists("nat", bridgeChain); err != nil {
		return err
	} else if !exists {
		if err := ipt.NewChain("nat", bridgeChain); err != nil {
			return fmt.Errorf("create %s chain: %w", bridgeChain, err)
		}
	}
	for _, hook := range []string{"PREROUTING", "OUTPUT"} {
		if err := ipt.AppendUnique("nat", hook, "-j", bridgeChain); err != nil {
			return fmt.Errorf("hook %s -> %s: %w", hook, bridgeChain, err)
		}
	}
	return nil
}

// AddBridge installs the per-pod DNAT (fabricIP -> vpcIP) and SNAT (-> gateway,
// only for DNATed/bridged connections) rules.
func AddBridge(fabricIP, vpcIP, hostVeth string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
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
	return nil
}

// DelBridge removes the per-pod rules added by AddBridge (idempotent).
func DelBridge(fabricIP, vpcIP, hostVeth string) error {
	ipt, err := iptables.New()
	if err != nil {
		return err
	}
	derr := ipt.DeleteIfExists("nat", bridgeChain,
		"-d", fabricIP, "-j", "DNAT", "--to-destination", vpcIP)
	serr := ipt.DeleteIfExists("nat", "POSTROUTING",
		"-d", vpcIP, "-o", hostVeth, "-m", "conntrack", "--ctstate", "DNAT",
		"-j", "SNAT", "--to-source", GatewayIP)
	if derr != nil {
		return derr
	}
	return serr
}
