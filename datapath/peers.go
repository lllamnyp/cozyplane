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

// SetPeer connects two networks: from_pod/to_pod permit traffic between them
// in both directions (two map entries, so the eBPF lookup never normalizes).
func (m *Manager) SetPeer(a, b uint32) error {
	if err := m.objs.Peers.Put(overlayPeerKey{SrcNet: a, DstNet: b}, uint8(1)); err != nil {
		return err
	}
	return m.objs.Peers.Put(overlayPeerKey{SrcNet: b, DstNet: a}, uint8(1))
}

// DelPeer disconnects two networks, removing both directions.
func (m *Manager) DelPeer(a, b uint32) error {
	err1 := m.objs.Peers.Delete(overlayPeerKey{SrcNet: a, DstNet: b})
	err2 := m.objs.Peers.Delete(overlayPeerKey{SrcNet: b, DstNet: a})
	if err1 != nil && !isNotExist(err1) {
		return err1
	}
	if err2 != nil && !isNotExist(err2) {
		return err2
	}
	return nil
}

// Peers returns the network pairs currently programmed, normalized to
// (low, high). Reading the pinned map (rather than shadowing it in agent
// state) lets a restarted agent prune pairs programmed by a previous run.
func (m *Manager) Peers() (map[[2]uint32]bool, error) {
	out := map[[2]uint32]bool{}
	var key overlayPeerKey
	var val uint8
	it := m.objs.Peers.Iterate()
	for it.Next(&key, &val) {
		a, b := key.SrcNet, key.DstNet
		if a > b {
			a, b = b, a
		}
		out[[2]uint32{a, b}] = true
	}
	return out, it.Err()
}
