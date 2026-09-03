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

// Per-VPC route table (issue #6, docs/vpn.md §3.1) and the scoped forwarding
// allowlist. The route table (`vpc_routes`) directs a remote prefix, within a
// VPC's scope, to a next-hop appliance leg — the same {gw_ip, node_ip} shape as
// a gateway, delivered the same way, but LPM-keyed by {scope, prefix} so a VPC
// has a real routing table of which the NAT gateway is the default entry. The
// allowlist (`fwd_cidrs`) bounds a forwarding leg's foreign sources.

// RouteEntry is one desired route from this node's point of view: within
// `Scope` (the VPC's VNI), traffic to `CIDR` goes to the leg at `GwIP` —
// delivered locally when NodeIP is nil, else encapsulated to that node.
type RouteEntry struct {
	Scope    uint32
	CIDR     string
	NextHops []RouteNextHop
	// GwIP/NodeIP retain source compatibility for single-next-hop callers.
	GwIP   net.IP
	NodeIP net.IP
}

// RouteNextHop is one appliance leg in an ECMP route. NodeIP is nil when the
// leg is local to the programming agent.
type RouteNextHop struct {
	GwIP   net.IP
	NodeIP net.IP
}

// SyncRoutes makes the vpc_routes map exactly `desired`, pruning entries that
// vanished while this agent was down. Mirrors SyncPeerNetworks:
// diff-against-the-pinned-map, keyed by the deterministic LPM key.
func (m *Manager) SyncRoutes(desired []RouteEntry) error {
	want := map[overlayLpmKey]overlayRouteEntry{}
	for _, d := range desired {
		key, e, err := routeMapEntry(d)
		if err != nil {
			return err
		}
		want[key] = e
	}

	var key overlayLpmKey
	var val overlayRouteEntry
	var stale []overlayLpmKey
	it := m.objs.VpcRoutes.Iterate()
	for it.Next(&key, &val) {
		if _, ok := want[key]; !ok {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate vpc_routes: %w", err)
	}
	for _, k := range stale {
		if err := m.objs.VpcRoutes.Delete(k); err != nil && !isNotExist(err) {
			return err
		}
	}
	for k, v := range want {
		v := v
		if err := m.objs.VpcRoutes.Put(k, &v); err != nil {
			return err
		}
	}
	return nil
}

func routeMapEntry(d RouteEntry) (overlayLpmKey, overlayRouteEntry, error) {
	key, err := lpmKey(d.Scope, d.CIDR)
	if err != nil {
		return overlayLpmKey{}, overlayRouteEntry{}, err
	}
	nextHops := append([]RouteNextHop(nil), d.NextHops...)
	if len(nextHops) == 0 && d.GwIP != nil {
		nextHops = []RouteNextHop{{GwIP: d.GwIP, NodeIP: d.NodeIP}}
	}
	if len(nextHops) == 0 || len(nextHops) > 2 {
		return overlayLpmKey{}, overlayRouteEntry{}, fmt.Errorf("route %s has %d next-hops; expected 1 or 2", d.CIDR, len(nextHops))
	}
	e := overlayRouteEntry{Count: uint8(len(nextHops))}
	for i, nextHop := range nextHops {
		gw, err := addr128(nextHop.GwIP)
		if err != nil {
			return overlayLpmKey{}, overlayRouteEntry{}, fmt.Errorf("route next-hop IP: %w", err)
		}
		e.NextHops[i].GwIp = gw
		if nextHop.NodeIP != nil {
			n4 := nextHop.NodeIP.To4()
			if n4 == nil {
				return overlayLpmKey{}, overlayRouteEntry{}, fmt.Errorf("route node IP %q is not IPv4", nextHop.NodeIP)
			}
			e.NextHops[i].NodeIp = binary.BigEndian.Uint32(n4)
		}
	}
	return key, e, nil
}

// SetFwdCidr allows a forwarding leg (identified by its host-veth ifindex) to
// source packets from within `cidr`. Programmed per leg by the CNI at ADD, only
// when the binding declares forwardingCIDRs (the port also carries
// PortForwardScopedFlag then). Package-level, opening the pinned map — the CNI
// plugin is a short-lived process with no Manager.
func SetFwdCidr(ifindex uint32, cidr string) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "fwd_cidrs"), nil)
	if err != nil {
		return fmt.Errorf("open pinned fwd_cidrs map: %w", err)
	}
	defer m.Close()
	key, err := lpmKey(ifindex, cidr)
	if err != nil {
		return err
	}
	one := uint8(1)
	return m.Put(key, &one)
}

// ClearFwdCidrs removes every allowlist entry scoped to `ifindex` — called by
// the CNI before (re)programming a leg, so a reused ifindex never inherits a
// prior pod's forwarding grant.
func ClearFwdCidrs(ifindex uint32) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "fwd_cidrs"), nil)
	if err != nil {
		return fmt.Errorf("open pinned fwd_cidrs map: %w", err)
	}
	defer m.Close()
	var key overlayLpmKey
	var val uint8
	var stale []overlayLpmKey
	it := m.Iterate()
	for it.Next(&key, &val) {
		if key.ScopeNet == ifindex {
			stale = append(stale, key)
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate fwd_cidrs: %w", err)
	}
	for _, k := range stale {
		if err := m.Delete(&k); err != nil && !isNotExist(err) {
			return err
		}
	}
	return nil
}
