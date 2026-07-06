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

// VPCCounter is the per-VPC traffic tally read from the datapath (#2): tx is a
// VPC pod's egress, rx its east-west ingress. North-south (gateway/floating)
// is not metered yet.
type VPCCounter struct {
	TxPackets uint64
	TxBytes   uint64
	RxPackets uint64
	RxBytes   uint64
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
		}
		out[net] = c
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("iterate vpc_counters: %w", err)
	}
	return out, nil
}
