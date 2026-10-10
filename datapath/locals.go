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

// SetLocal records a local pod (its host-veth ifindex and pod-interface MAC) in
// the locals map, keyed by (network id, pod IP) so overlapping VPCs that host
// the same IP stay distinct. Same-node and post-decap traffic is delivered by
// eBPF redirect (through the to_pod hook), not a kernel-routing shortcut. Used
// by the CNI plugin via the pinned map.
func SetLocal(net_ uint32, podIP net.IP, ifindex int, mac net.HardwareAddr) error {
	if _, err := Ifindex(ifindex); err != nil {
		return err
	}
	return withBridgeLock(func() error { return setLocal(net_, podIP, ifindex, mac) })
}

func setLocal(net_ uint32, podIP net.IP, ifindex int, mac net.HardwareAddr) error {
	index, err := Ifindex(ifindex)
	if err != nil {
		return err
	}

	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return fmt.Errorf("find local endpoint: %w", err)
	}
	{
		if VethPortIdentity(link.Attrs().Alias).Staged {
			return nil
		}
		if raw, _, _, valid := parseVethAlias(link.Attrs().Alias); valid && (raw == QuarantineNet || PortNet(raw) != net_) {
			return fmt.Errorf("local endpoint state changed before map update")
		}
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	cid, iface := VethSandbox(link.Attrs().Alias)
	ep := overlayEndpoint{Ifindex: index, SgOwner: SGEndpointOwner(VethPortIdentity(link.Attrs().Alias).UID, cid, iface)}
	copy(ep.Mac[:], mac)
	key, err := localKey(net_, podIP)
	if err != nil {
		return err
	}
	if err := m.Put(key, &ep); err != nil {
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

	key, err := localKey(net_, podIP)
	if err != nil {
		return 0, nil, false, err
	}
	var ep overlayEndpoint
	if err := m.Lookup(key, &ep); err != nil {
		if isNotExist(err) {
			return 0, nil, false, nil
		}
		return 0, nil, false, fmt.Errorf("lookup local: %w", err)
	}
	return int(ep.Ifindex), net.HardwareAddr(ep.Mac[:]), true, nil
}

// DelLocal removes a pod from the locals map.
func DelLocal(net_ uint32, podIP net.IP) error {
	return withBridgeLock(func() error { return delLocal(net_, podIP) })
}

// Compare and delete under the same cross-process lock as SetLocal. A stale
// sandbox cannot delete the migration target's entry after a separate lookup.
func DelLocalIfOwned(net_ uint32, podIP net.IP, ifindices map[int]bool) error {
	return withBridgeLock(func() error {
		index, _, found, err := GetLocal(net_, podIP)
		if err != nil {
			return err
		}
		if !found || !ifindices[index] {
			return nil
		}
		return delLocal(net_, podIP)
	})
}

func delLocal(net_ uint32, podIP net.IP) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return fmt.Errorf("open pinned locals map: %w", err)
	}
	defer m.Close()

	key, err := localKey(net_, podIP)
	if err != nil {
		return err
	}
	if err := m.Delete(key); err != nil && !isNotExist(err) {
		return fmt.Errorf("del local: %w", err)
	}
	return nil
}

// localKey builds the (network id, IP) key. The IP is in the 16-byte NAT64-mapped
// form the eBPF program keys on (network order in memory).
func localKey(net_ uint32, ip net.IP) (overlayLocalKey, error) {
	a, err := addr128(ip)
	if err != nil {
		return overlayLocalKey{}, err
	}
	return overlayLocalKey{Net: net_, Ip: a}, nil
}
