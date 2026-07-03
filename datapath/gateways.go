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

// SetGateway records a VPC's egress gateway from this node's point of view:
// nodeIP is nil when the gateway runs on this node (delivery by local
// redirect), else the node hosting it (delivery by encapsulation).
func (m *Manager) SetGateway(vni uint32, gwIP net.IP, nodeIP net.IP) error {
	gw, err := addr128(gwIP)
	if err != nil {
		return fmt.Errorf("gateway IP: %w", err)
	}
	e := overlayGwEntry{GwIp: gw}
	if nodeIP != nil {
		n4 := nodeIP.To4()
		if n4 == nil {
			return fmt.Errorf("gateway node IP %q is not IPv4", nodeIP)
		}
		e.NodeIp = binary.BigEndian.Uint32(n4) // tunnel-key host byte order
	}
	return m.objs.Gateways.Put(vni, &e)
}

// DelGateway removes a VPC's egress gateway entry.
func (m *Manager) DelGateway(vni uint32) error {
	if err := m.objs.Gateways.Delete(vni); err != nil && !isNotExist(err) {
		return err
	}
	return nil
}

// Gateways returns the VNIs with a gateway entry currently programmed, so a
// restarted agent can prune entries whose Ports vanished while it was down.
func (m *Manager) Gateways() (map[uint32]bool, error) {
	out := map[uint32]bool{}
	var vni uint32
	var e overlayGwEntry
	it := m.objs.Gateways.Iterate()
	for it.Next(&vni, &e) {
		out[vni] = true
	}
	return out, it.Err()
}

// AttachOverlay attaches the from_overlay classifier at the ingress of the
// Geneve device (gateway re-mark + local-gateway delivery after decap). Must
// run after EnsureGeneve.
func (m *Manager) AttachOverlay() error {
	if m.geneveIfindex == 0 {
		return fmt.Errorf("geneve device not initialized")
	}
	return AttachIngress(m.geneveIfindex, m.objs.CozyplaneFromOverlay)
}
