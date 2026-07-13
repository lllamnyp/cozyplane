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
)

// The VPC NAT gateway's port sharding (docs/north-south.md § increment 2). Must
// match NAT_PORT_BASE / NAT_SHARD_SPAN / NAT_SHARDS in bpf/overlay.c.
//
// One address per VPC, and each node draws its masquerade ports from its own
// shard — so a reply arriving at whichever node ATTRACTS the address can be
// demuxed by port back to the node whose connection table holds the flow. That is
// what lets egress stay distributed instead of hairpinning through one node.
const (
	NATPortBase  = 1024
	NATShardSpan = 4032 // concurrent flows per node, per VPC
	NATShards    = 16   // ... across up to this many nodes
)

// NATShardFor returns the port range a node owns for every VPC NAT address.
// Deterministic in the node's index, so every agent computes the same partition.
func NATShardFor(nodeIndex int) (base, span uint32, ok bool) {
	if nodeIndex < 0 || nodeIndex >= NATShards {
		return 0, 0, false
	}
	return NATPortBase + uint32(nodeIndex)*NATShardSpan, NATShardSpan, true
}

// SetVPCNAT gives a VPC its egress identity on THIS node: the address its traffic
// wears on the wire, and this node's slice of the port space.
func (m *Manager) SetVPCNAT(net_ uint32, natIP string, portBase, portSpan uint32) error {
	ip, err := addr128Str(natIP)
	if err != nil {
		return fmt.Errorf("nat address: %w", err)
	}
	v := overlayVpcNat{Ip: ip, PortBase: portBase, PortSpan: portSpan}
	if err := m.objs.VpcNat.Put(net_, &v); err != nil {
		return fmt.Errorf("set vpc_nat for net %d: %w", net_, err)
	}
	// And the reverse direction's first question: whose address is this?
	if err := m.objs.NatOf.Put(&ip, net_); err != nil {
		return fmt.Errorf("set nat_of for %s: %w", natIP, err)
	}
	return nil
}

// DelVPCNAT removes a VPC's egress identity (idempotent).
func (m *Manager) DelVPCNAT(net_ uint32, natIP string) error {
	if err := m.objs.VpcNat.Delete(net_); err != nil && !isNotExist(err) {
		return fmt.Errorf("del vpc_nat for net %d: %w", net_, err)
	}
	if natIP != "" {
		if ip, err := addr128Str(natIP); err == nil {
			if err := m.objs.NatOf.Delete(&ip); err != nil && !isNotExist(err) {
				return fmt.Errorf("del nat_of for %s: %w", natIP, err)
			}
		}
	}
	return nil
}

// SetNATOwner records which node's connection table holds the flows in a port
// shard. EVERY node programs the whole table: any of them may be the one the
// fabric hands the reply to, and it has to know where to forward it.
func (m *Manager) SetNATOwner(natIP string, shard uint16, nodeIP net.IP) error {
	ip, err := addr128Str(natIP)
	if err != nil {
		return fmt.Errorf("nat address: %w", err)
	}
	v4 := nodeIP.To4()
	if v4 == nil {
		return fmt.Errorf("node IP %s is not v4", nodeIP)
	}
	k := overlayNatShardKey{Ip: ip, Shard: shard}
	if err := m.objs.NatOwner.Put(&k, binary.BigEndian.Uint32(v4)); err != nil {
		return fmt.Errorf("set nat_owner %s/%d: %w", natIP, shard, err)
	}
	return nil
}

// NATOwners returns the shard table as programmed, so the agent can prune it.
func (m *Manager) NATOwners() (map[string]bool, error) {
	out := map[string]bool{}
	var k overlayNatShardKey
	var v uint32
	it := m.objs.NatOwner.Iterate()
	for it.Next(&k, &v) {
		out[fmt.Sprintf("%s/%d", addr128ToIP(k.Ip), k.Shard)] = true
	}
	return out, it.Err()
}

// DelNATOwner drops one shard entry (idempotent).
func (m *Manager) DelNATOwner(natIP string, shard uint16) error {
	ip, err := addr128Str(natIP)
	if err != nil {
		return fmt.Errorf("nat address: %w", err)
	}
	k := overlayNatShardKey{Ip: ip, Shard: shard}
	if err := m.objs.NatOwner.Delete(&k); err != nil && !isNotExist(err) {
		return fmt.Errorf("del nat_owner %s/%d: %w", natIP, shard, err)
	}
	return nil
}

// VPCNATs returns the nets that currently have an egress identity here.
func (m *Manager) VPCNATs() (map[uint32]string, error) {
	out := map[uint32]string{}
	var net_ uint32
	var v overlayVpcNat
	it := m.objs.VpcNat.Iterate()
	for it.Next(&net_, &v) {
		out[net_] = addr128ToIP(v.Ip).String()
	}
	return out, it.Err()
}
