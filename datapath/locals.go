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
// the locals map, so same-node traffic to it is delivered by eBPF redirect
// (through the to_pod hook) rather than a kernel-routing shortcut. Used by the
// CNI plugin via the pinned map.
func SetLocal(podIP net.IP, ifindex int, mac net.HardwareAddr) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	ep := overlayEndpoint{Ifindex: uint32(ifindex)}
	copy(ep.Mac[:], mac)
	if err := m.Put(localKey(podIP), &ep); err != nil {
		return fmt.Errorf("set local: %w", err)
	}
	return nil
}

// GetLocal returns the host-veth ifindex and pod MAC recorded for a local pod,
// and whether an entry exists. Used by SeverLocal to find a live local pod's
// datapath when its Port is reaped.
func GetLocal(podIP net.IP) (ifindex int, mac net.HardwareAddr, found bool, err error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return 0, nil, false, fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	var ep overlayEndpoint
	if err := m.Lookup(localKey(podIP), &ep); err != nil {
		if isNotExist(err) {
			return 0, nil, false, nil
		}
		return 0, nil, false, fmt.Errorf("lookup local: %w", err)
	}
	return int(ep.Ifindex), net.HardwareAddr(ep.Mac[:]), true, nil
}

// DelLocal removes a pod from the locals map.
func DelLocal(podIP net.IP) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	if err := m.Delete(localKey(podIP)); err != nil && !isNotExist(err) {
		return fmt.Errorf("del local: %w", err)
	}
	return nil
}

// localKey lays the IPv4 address out so its bytes match ip->daddr in the eBPF
// program (network order in memory; little-endian-decoded on this host).
func localKey(ip net.IP) uint32 {
	return binary.LittleEndian.Uint32(ip.To4())
}
