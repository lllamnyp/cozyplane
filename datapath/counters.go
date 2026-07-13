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

	"github.com/cilium/ebpf"
)

// NS doors — the ways a tenant's traffic can cross the VPC's north-south
// boundary (docs/north-south.md). Must match the NS_* constants in bpf/overlay.c.
const (
	NSGateway = 0 // out through the VPC's egress gateway (and back)
	NSEIP     = 1 // a floating address: 1:1, the tenant's own identity
	NSLB      = 2 // LoadBalancer/NodePort ingress landing on a VPC backend
	nsDoors   = 3
)

// NSDoorNames labels the doors for metrics; index by the NS* constants.
var NSDoorNames = [nsDoors]string{"gateway", "eip", "loadbalancer"}

// VPCCounter is the per-VPC traffic tally read from the datapath (#2).
//
// Tx/Rx are EAST-WEST (a VPC pod's egress / its ingress). NSPackets and NSBytes
// count every crossing of the VPC's north-south boundary, split by the door it
// went through and by direction ([door][in]) — which is the thing that was
// missing: a tenant could pull terabytes out through a floating address or a
// LoadBalancer Service and cozyplane could not say it happened.
type VPCCounter struct {
	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64
	NSPackets [nsDoors][2]uint64
	NSBytes   [nsDoors][2]uint64
	// NSDenied counts packets the boundary REFUSED, per door. Deliberately not
	// folded into the crossing counters: a refused packet did not cross, and the
	// byte meter must stay clean. It still has to be visible — "my LoadBalancer
	// doesn't reach the VPC" is answered by this being non-zero.
	NSDenied [nsDoors]uint64
}

// NorthSouthBytes totals every byte this VPC pushed across its boundary, in both
// directions and through every door — the number the three-door problem is about.
func (c VPCCounter) NorthSouthBytes() uint64 {
	var t uint64
	for door := range c.NSBytes {
		t += c.NSBytes[door][0] + c.NSBytes[door][1]
	}
	return t
}

// EnsureVPCCounter creates a zeroed vpc_counters entry for a net if absent.
// The datapath's count_dir never creates entries (a stack-free lookup+increment
// only — from_pod/to_pod are too stack-heavy to host the init), so the agent
// seeds one per VPC net when it programs the network. Idempotent; a net's
// first few packets before this runs are simply uncounted.
func (m *Manager) EnsureVPCCounter(net uint32) error {
	if net == 0 {
		return nil
	}
	var existing []overlayVpcCounter
	if err := m.objs.VpcCounters.Lookup(net, &existing); err == nil {
		return nil // already seeded; don't clobber live counts
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("possible CPUs: %w", err)
	}
	zero := make([]overlayVpcCounter, ncpu)
	if err := m.objs.VpcCounters.Put(net, zero); err != nil {
		return fmt.Errorf("seed vpc_counter for net %d: %w", net, err)
	}
	return nil
}

// VPCCounters reads the per-net traffic counters, summing the PERCPU values
// each hook wrote on its own CPU. Keyed by network id (VNI).
func (m *Manager) VPCCounters() (map[uint32]VPCCounter, error) {
	out := map[uint32]VPCCounter{}
	var net uint32
	var per []overlayVpcCounter
	it := m.objs.VpcCounters.Iterate()
	for it.Next(&net, &per) {
		var c VPCCounter
		for i := range per {
			c.TxPackets += per[i].TxPackets
			c.TxBytes += per[i].TxBytes
			c.RxPackets += per[i].RxPackets
			c.RxBytes += per[i].RxBytes
			for door := 0; door < nsDoors; door++ {
				c.NSDenied[door] += per[i].NsDenied[door]
				for in := 0; in < 2; in++ {
					c.NSPackets[door][in] += per[i].NsPackets[door][in]
					c.NSBytes[door][in] += per[i].NsBytes[door][in]
				}
			}
		}
		out[net] = c
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate vpc_counters: %w", err)
	}
	return out, nil
}

// SetVPCIngress opens a VPC to LoadBalancer ingress; DelVPCIngress closes it.
// Absent means closed — a Service type=LoadBalancer cannot open a door into a
// tenant's VPC unless that VPC's gateway admits it (docs/north-south.md, tenet 7).
func (m *Manager) SetVPCIngress(net uint32) error {
	if net == 0 {
		return nil // the default network is the platform's, not a tenant's
	}
	var one uint8 = 1
	if err := m.objs.VpcIngress.Put(net, one); err != nil {
		return fmt.Errorf("open vpc ingress for net %d: %w", net, err)
	}
	return nil
}

func (m *Manager) DelVPCIngress(net uint32) error {
	if err := m.objs.VpcIngress.Delete(net); err != nil && !isNotExist(err) {
		return fmt.Errorf("close vpc ingress for net %d: %w", net, err)
	}
	return nil
}

// VPCIngresses returns the nets currently admitting LoadBalancer ingress, so the
// agent can diff its desired set against the pinned map (which outlives it).
func (m *Manager) VPCIngresses() (map[uint32]bool, error) {
	out := map[uint32]bool{}
	var net uint32
	var v uint8
	it := m.objs.VpcIngress.Iterate()
	for it.Next(&net, &v) {
		out[net] = true
	}
	return out, it.Err()
}
