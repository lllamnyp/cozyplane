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
)

// SetPortNet records the network id of a pod's host-side veth in the ports map.
// Used by the CNI plugin via the pinned map. Every pod sets this (0 for the
// default/system network) so a reused ifindex never inherits a stale id.
func SetPortNet(ifindex int, netID uint32) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	if err := m.Put(uint32(ifindex), netID); err != nil {
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
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return 0, false, fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	var v uint32
	if err := m.Lookup(uint32(ifindex), &v); err != nil {
		if isNotExist(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("get port net: %w", err)
	}
	return PortNet(v), true, nil
}

// DelPortNet removes a veth's entry from the ports map.
func DelPortNet(ifindex int) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return fmt.Errorf("open pinned ports map: %w", err)
	}
	defer m.Close()

	if err := m.Delete(uint32(ifindex)); err != nil && !isNotExist(err) {
		return fmt.Errorf("del port net: %w", err)
	}
	return nil
}
