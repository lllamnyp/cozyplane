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
	"net/netip"
)

// SyncOrgGateways makes org_gw exactly `gateways` (VPC net -> the addresses of
// its organisation's internal Gateway, reachable on TCP 80/443) and org_gw_be
// exactly `backends` (proxy endpoint -> the Gateway address:port it serves),
// see gw_steer / gw_return in bpf/overlay.c. Both nil revokes everything,
// recorded flows (org_gw_ct) included. Over capacity an error is returned; the
// caller decides to revoke.
func (m *Manager) SyncOrgGateways(gateways map[uint32][]netip.Addr, backends map[netip.AddrPort]netip.AddrPort) error {
	want := map[overlayLocalKey]uint8{}
	for vni, ips := range gateways {
		for _, ip := range ips {
			a, err := addr128(net.IP(ip.AsSlice()))
			if err != nil {
				return fmt.Errorf("organisation gateway: %w", err)
			}
			if err := putDesired(m.objs.OrgGw, want, overlayLocalKey{Net: vni, Ip: a}, uint8(1)); err != nil {
				return err
			}
		}
	}
	proxies := map[overlayOrgGwAddr]overlayOrgGwAddr{}
	for from, to := range backends {
		f, err := addr128(net.IP(from.Addr().AsSlice()))
		if err != nil {
			return fmt.Errorf("organisation gateway proxy: %w", err)
		}
		g, err := addr128(net.IP(to.Addr().AsSlice()))
		if err != nil {
			return fmt.Errorf("organisation gateway: %w", err)
		}
		key, val := overlayOrgGwAddr{Addr: f, Port: htons(from.Port())}, overlayOrgGwAddr{Addr: g, Port: htons(to.Port())}
		if err := putDesired(m.objs.OrgGwBe, proxies, key, val); err != nil {
			return err
		}
	}
	if err := syncMap(m.objs.OrgGw, want); err != nil {
		return err
	}
	if err := syncMap(m.objs.OrgGwBe, proxies); err != nil {
		return err
	}
	if gateways == nil && backends == nil {
		return syncMap(m.objs.OrgGwCt, map[overlayOrgGwCtKey]uint32{})
	}
	return nil
}
