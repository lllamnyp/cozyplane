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
	"path/filepath"

	"github.com/cilium/ebpf"
)

// SetLocal records a local pod (its host-veth ifindex and pod-interface MAC) in
// the locals map, keyed by (network id, pod IP) so overlapping VPCs that host
// the same IP stay distinct. Same-node and post-decap traffic is delivered by
// eBPF redirect (through the to_pod hook), not a kernel-routing shortcut. Used
// by the CNI plugin via the pinned map.
func SetLocal(net_ uint32, podIP net.IP, ifindex int, mac net.HardwareAddr) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	ep := overlayEndpoint{Ifindex: uint32(ifindex)}
	copy(ep.Mac[:], mac)
	if err := m.Put(localKey(net_, podIP), &ep); err != nil {
		return fmt.Errorf("set local: %w", err)
	}
	return nil
}

// GetLocal returns the host-veth ifindex and pod MAC recorded for a local pod
// in a network, and whether an entry exists. Used by SeverLocal to find a live
// local pod's datapath when its Port is reaped.
func GetLocal(net_ uint32, podIP net.IP) (ifindex int, mac net.HardwareAddr, found bool, err error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return 0, nil, false, fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	var ep overlayEndpoint
	if err := m.Lookup(localKey(net_, podIP), &ep); err != nil {
		if isNotExist(err) {
			return 0, nil, false, nil
		}
		return 0, nil, false, fmt.Errorf("lookup local: %w", err)
	}
	return int(ep.Ifindex), net.HardwareAddr(ep.Mac[:]), true, nil
}

// DelLocal removes a pod from the locals map.
func DelLocal(net_ uint32, podIP net.IP) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	if err := m.Delete(localKey(net_, podIP)); err != nil && !isNotExist(err) {
		return fmt.Errorf("del local: %w", err)
	}
	return nil
}

// localKey builds the (network id, IP) key. The IP is laid out so its bytes
// match ip->daddr in the eBPF program (network order in memory).
func localKey(net_ uint32, ip net.IP) overlayLocalKey {
	return overlayLocalKey{Net: net_, Ip: binary.LittleEndian.Uint32(ip.To4())}
}
