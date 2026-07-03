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
)

// A floating IP is the north-south bridge turned outward: a routable public
// address mapped 1:1 to a pod's (net, VPC IP), with the external client's source
// preserved. Unlike the fabric bridge it needs no /32 route — from_uplink
// intercepts the address at the node uplink's tc ingress (before kernel routing)
// and redirects it into the pod's veth, where to_pod DNATs public->VPC. Here we
// only publish the mapping in the pinned `floating` map the datapath keys on; the
// agent advertises the address (ARP/NDP) separately, from the pod's own node.

// SetFloating records the 1:1 mapping in both directions: floating[publicIP] =
// {net, VPC IP} for inbound DNAT, and floating_egress[{net, VPC IP}] = publicIP
// for the pod's outbound SNAT. net is the target pod's network id (its VNI). No
// conntrack — the datapath is stateless in both directions.
func (m *Manager) SetFloating(publicIP, vpcIP string, net_ uint32) error {
	pub, err := addr128Str(publicIP)
	if err != nil {
		return fmt.Errorf("public IP: %w", err)
	}
	vpc, err := addr128Str(vpcIP)
	if err != nil {
		return fmt.Errorf("vpc IP: %w", err)
	}
	if err := m.objs.Floating.Put(&pub, &overlayBridgeEp{Net: net_, VpcIp: vpc}); err != nil {
		return fmt.Errorf("set floating %s: %w", publicIP, err)
	}
	if err := m.objs.FloatingEgress.Put(&overlayLocalKey{Net: net_, Ip: vpc}, &pub); err != nil {
		return fmt.Errorf("set floating egress %s: %w", publicIP, err)
	}
	return nil
}

// DelFloating removes a public IP from both directions of the floating map
// (idempotent). The reverse entry is keyed by {net, VPC IP}, recovered from the
// forward entry.
func (m *Manager) DelFloating(publicIP string) error {
	pub, err := addr128Str(publicIP)
	if err != nil {
		return fmt.Errorf("public IP: %w", err)
	}
	var ep overlayBridgeEp
	if err := m.objs.Floating.Lookup(&pub, &ep); err == nil {
		_ = m.objs.FloatingEgress.Delete(&overlayLocalKey{Net: ep.Net, Ip: ep.VpcIp})
	}
	if err := m.objs.Floating.Delete(&pub); err != nil && !isNotExist(err) {
		return fmt.Errorf("del floating %s: %w", publicIP, err)
	}
	return nil
}

// SetInternal programs the cluster-internal CIDRs (pod/service/node networks)
// into the internal map. A floating pod's egress to any of them is dropped in
// from_pod — it bypasses the VPC gateway that would otherwise deny them.
func (m *Manager) SetInternal(cidrs []string) error {
	for _, c := range cidrs {
		key, err := lpmKey(0, c)
		if err != nil {
			return err
		}
		var one uint8 = 1
		if err := m.objs.Internal.Put(&key, one); err != nil {
			return fmt.Errorf("set internal %s: %w", c, err)
		}
	}
	return nil
}

// Floatings returns the public IPs currently programmed in the floating map, so
// a restarted agent can prune entries whose FloatingIPs or target Ports vanished
// while it was down.
func (m *Manager) Floatings() (map[string]bool, error) {
	out := map[string]bool{}
	var key overlayAddr128
	var ep overlayBridgeEp
	it := m.objs.Floating.Iterate()
	for it.Next(&key, &ep) {
		out[addr128ToIP(key).String()] = true
	}
	return out, it.Err()
}

// Advertisement is not a host-side operation: from_uplink answers ARP for a
// floating IP as long as it has an entry here with a live local pod (see
// floating_arp in bpf/overlay.c). Programming the map is the advertisement.
