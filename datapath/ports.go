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
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// SetPortNet records the network id of a pod's host-side veth in the ports map.
// Used by the CNI plugin via the pinned map. Every pod sets this (0 for the
// default/system network) so a reused ifindex never inherits a stale id.
func SetPortNet(ifindex int, netID uint32) error {
	if _, err := Ifindex(ifindex); err != nil {
		return err
	}
	return withBridgeLock(func() error { return setPortNet(ifindex, netID) })
}

func setPortNet(ifindex int, netID uint32) error {
	index, err := Ifindex(ifindex)
	if err != nil {
		return err
	}

	if netID != QuarantineNet {
		link, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		raw, _, _, valid := parseVethAlias(link.Attrs().Alias)
		if valid && (raw == QuarantineNet || raw != netID) {
			return fmt.Errorf("port state changed before map update")
		}
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	if err := m.Put(index, netID); err != nil {
		return fmt.Errorf("set port net: %w", err)
	}
	return nil
}

// GetPortNet returns the network id recorded for a veth (the gateway flag
// stripped), so a DEL can clean the local datapath by (net, IP) even when the
// pod's Port is not the one to consult — e.g. a migration source whose
// persistent Port has already been re-pointed to the target pod. ok is false
// when the veth has no entry.
func GetPortNet(ifindex int) (netID uint32, ok bool, err error) {
	raw, ok, err := GetPortState(ifindex)
	return PortNet(raw), ok, err
}

// GetPortState returns the complete value, including gateway/forwarding and
// quarantine flags. Grant reconciliation must not use the network-only accessor.
func GetPortState(ifindex int) (rawNet uint32, ok bool, err error) {
	index, err := Ifindex(ifindex)
	if err != nil {
		return 0, false, err
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return 0, false, fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	var v uint32
	if err := m.Lookup(index, &v); err != nil {
		if isNotExist(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("get port net: %w", err)
	}
	return v, true, nil
}

// DelPortNet removes a veth's entry from the ports map.
func DelPortNet(ifindex int) error {
	index, err := Ifindex(ifindex)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	if err := m.Delete(index); err != nil && !isNotExist(err) {
		return fmt.Errorf("del port net: %w", err)
	}
	return nil
}
