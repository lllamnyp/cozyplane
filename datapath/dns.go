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
)

// VPC DNS steering (split-horizon resolver): a VPC pod's query to the cluster
// DNS address is re-addressed in from_pod to the node-local resolver, with the
// pod's fabric IP as the rewritten source (the per-Port handle the resolver
// keys the tenant view on); to_pod reverses the resolver's reply. Both halves
// are stateless — see dns_steer/dns_return in bpf/overlay.c. The agent
// programs the two config pieces below; the per-pod fabric_of entries ride the
// bridge lifecycle (setBridge/delBridge).

// SetClusterDNS publishes the cluster DNS ClusterIP per family (nil clears a
// family, disabling its interception).
func (m *Manager) SetClusterDNS(v4, v6 net.IP) error {
	var a4, a6 overlayAddr128
	if v4 != nil {
		a, err := addr128(v4)
		if err != nil {
			return fmt.Errorf("cluster DNS v4: %w", err)
		}
		a4 = a
	}
	if v6 != nil {
		a, err := addr128(v6)
		if err != nil {
			return fmt.Errorf("cluster DNS v6: %w", err)
		}
		a6 = a
	}
	if err := m.objs.DnsIps.Put(uint32(0), &a4); err != nil {
		return fmt.Errorf("set cluster DNS v4: %w", err)
	}
	if err := m.objs.DnsIps.Put(uint32(1), &a6); err != nil {
		return fmt.Errorf("set cluster DNS v6: %w", err)
	}
	return nil
}

// SetResolverPort publishes the node-local resolver's port; 0 disables DNS
// steering entirely (the feature gate).
func (m *Manager) SetResolverPort(port uint16) error {
	if err := m.objs.Params.Put(cfgResolverPort, uint32(port)); err != nil {
		return fmt.Errorf("set resolver port: %w", err)
	}
	return nil
}
