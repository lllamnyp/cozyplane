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
	"errors"
	"fmt"
	"maps"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
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

// RouteCapacity bounds compilation before candidate expansion.
func (m *Manager) RouteCapacity() uint32 { return m.objs.VpcRoutes.MaxEntries() }

// BlockRoutes closes off-VPC workload egress before route compilation or load.
func (m *Manager) BlockRoutes() error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	return m.objs.RouteGuard.Put(uint32(0), uint32(1))
}

// SyncRoutes guards the whole replacement. Preflight preserves old rows on
// rejection, but only complete success can re-enable off-VPC workload egress.
func (m *Manager) SyncRoutes(desired []RouteEntry) error {
	return m.SyncRoutesScoped(desired, nil)
}

// SyncRoutesScoped publishes complete routes and explicit denial for scopes
// whose owner exceeds its fair budget. Kernel errors keep the global gate closed.
func (m *Manager) SyncRoutesScoped(desired []RouteEntry, blocked []uint32) error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	if err := m.objs.RouteGuard.Put(uint32(0), uint32(1)); err != nil {
		return fmt.Errorf("arm route update guard: %w", err)
	}
	want := map[overlayLpmKey]overlayRouteEntry{}
	for _, d := range desired {
		if d.Scope == 0 || d.Scope >= 1<<22 {
			return fmt.Errorf("route scope outside tenant VNI range")
		}
		key, e, err := routeMapEntry(d)
		if err != nil {
			return err
		}
		if err := putDesired(m.objs.VpcRoutes, want, key, e); err != nil {
			return err
		}
	}
	cells := map[uint32]overlayRouteScopeGuard{}
	for _, scope := range blocked {
		if scope == 0 || scope >= 1<<22 {
			return fmt.Errorf("blocked scope outside tenant VNI range")
		}
		page := scope >> 12
		cell := cells[page]
		cell.Blocked[(scope>>5)&127] |= uint32(1) << (scope & 31)
		cells[page] = cell
	}
	if err := syncMap(m.objs.VpcRoutes, want); err != nil {
		return err
	}
	if err := m.syncRouteScopes(cells); err != nil {
		return err
	}
	return m.objs.RouteGuard.Put(uint32(0), uint32(0))
}

func (m *Manager) syncRouteScopes(want map[uint32]overlayRouteScopeGuard) error {
	if m.objs.RouteScopes == nil {
		return fmt.Errorf("route scope guard unavailable")
	}
	if m.routeScopeCells == nil {
		m.routeScopeCells = map[uint32]overlayRouteScopeGuard{}
	}
	put := func(page uint32, cell overlayRouteScopeGuard) error {
		if err := m.objs.RouteScopes.Put(page, cell); err != nil {
			return fmt.Errorf("write route scope guard: %w", err)
		}
		// Track successful writes even when a later cell fails, so recovery
		// removes every stale bit. Retain only nonzero cells, never history.
		if cell == (overlayRouteScopeGuard{}) {
			delete(m.routeScopeCells, page)
		} else {
			m.routeScopeCells[page] = cell
		}
		return nil
	}
	if !m.routeScopeSeeded {
		for page := uint32(0); page < 1024; page++ {
			if err := put(page, want[page]); err != nil {
				return err
			}
		}
		m.routeScopeSeeded = true
		return nil
	}
	for page, cell := range m.routeScopeCells {
		if next := want[page]; next != cell {
			if err := put(page, next); err != nil {
				return err
			}
		}
	}
	for page, cell := range want {
		if m.routeScopeCells[page] != cell {
			if err := put(page, cell); err != nil {
				return err
			}
		}
	}
	return nil
}

func routeMapEntry(d RouteEntry) (overlayLpmKey, overlayRouteEntry, error) {
	key, err := lpmKey(d.Scope, d.CIDR)
	if err != nil {
		return overlayLpmKey{}, overlayRouteEntry{}, err
	}
	nextHops := d.NextHops // immutable input; no copy before the size check
	if len(nextHops) == 0 && d.GwIP != nil {
		nextHops = []RouteNextHop{{GwIP: d.GwIP, NodeIP: d.NodeIP}}
	}
	// Zero next hops retains the explicit prefix as a blackhole until its
	// appliance becomes usable, without a second expected-prefix map.
	if len(nextHops) > 2 {
		return overlayLpmKey{}, overlayRouteEntry{}, fmt.Errorf("route %s has %d next-hops; expected at most 2", d.CIDR, len(nextHops))
	}
	e := overlayRouteEntry{Count: 1}
	if len(nextHops) == 2 {
		e.Count = 2
	}
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

// fwdCIDRKey keeps routing identity separate from source-family permission.
func fwdCIDRKey(ifindex uint32, cidr string) (overlayFwdCidrKey, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return overlayFwdCidrKey{}, fmt.Errorf("invalid forwarding CIDR")
	}
	addr, bits, family, err := cidrPolicyPrefix(ipnet)
	if err != nil {
		return overlayFwdCidrKey{}, err
	}
	return overlayFwdCidrKey{Prefixlen: 64 + bits, ScopeNet: ifindex, Family: uint32(family), Addr: addr}, nil
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
	key, err := fwdCIDRKey(ifindex, cidr)
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
	var key overlayFwdCidrKey
	var val uint8
	var stale []overlayFwdCidrKey
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

// SyncLocalForwarding updates an existing leg when its owner's grant changes,
// and restores scoped allowlists after a map recreation. Remove the old right
// before touching the allowlist; a partial update must fail closed.
func SyncLocalForwarding(netID uint32, ip net.IP, allow bool, cidrs []string) error {
	ifindex, _, found, err := GetLocal(netID, ip)
	if err != nil || !found {
		return err
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return err
	}
	return SyncVethForwarding(netID, ifindex, link.Attrs().Alias, allow, cidrs)
}

func SyncVethForwarding(netID uint32, ifindex int, expectedAlias string, allow bool, cidrs []string) error {
	return SyncEndpointForwarding([]ForwardingEndpoint{{Net: netID, Ifindex: ifindex, Alias: expectedAlias, Allow: allow, CIDRs: cidrs}})
}

type ForwardingEndpoint struct {
	Net     uint32
	Ifindex int
	Alias   string
	Allow   bool
	CIDRs   []string
}

// SyncEndpointForwarding snapshots CIDRs once, then diffs each owned scope.
// Unchanged grants perform no writes or link notifications. The shared lock
// prevents CNI writers from invalidating the snapshot during the batch.
func SyncEndpointForwarding(entries []ForwardingEndpoint) error {
	if len(entries) == 0 {
		return nil
	}
	localGrantMu.Lock()
	defer localGrantMu.Unlock()
	return withBridgeLock(func() error {
		mp, snapshotErr := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "fwd_cidrs"), nil)
		current := map[uint32]map[overlayFwdCidrKey]uint8{}
		if snapshotErr == nil {
			defer mp.Close()
			var key overlayFwdCidrKey
			var value uint8
			it := mp.Iterate()
			for it.Next(&key, &value) {
				if current[key.ScopeNet] == nil {
					current[key.ScopeNet] = map[overlayFwdCidrKey]uint8{}
				}
				current[key.ScopeNet][key] = value
			}
			snapshotErr = it.Err()
		}
		var failures []error
		for _, entry := range entries {
			if err := syncVethForwarding(entry, mp, current[uint32(entry.Ifindex)], snapshotErr); err != nil {
				failures = append(failures, fmt.Errorf("forwarding endpoint %d: %w", entry.Ifindex, err))
			}
		}
		return errors.Join(failures...)
	})
}

func syncVethForwarding(d ForwardingEndpoint, mp *ebpf.Map, current map[overlayFwdCidrKey]uint8, snapshotErr error) error {
	netID, ifindex, expectedAlias, allow, cidrs := d.Net, d.Ifindex, d.Alias, d.Allow, d.CIDRs
	rawNet, found, err := GetPortState(ifindex)
	if err != nil || !found {
		return err
	}
	if rawNet == QuarantineNet || PortNet(rawNet) != netID || rawNet&PortGatewayFlag != 0 {
		return nil
	}
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return err
	}
	if link.Type() != "veth" || link.Attrs().Alias != expectedAlias {
		return nil
	}
	aliasNet, ips, mac, ok := parseVethAlias(link.Attrs().Alias)
	if !ok || aliasNet == QuarantineNet || PortNet(aliasNet) != netID {
		return fmt.Errorf("invalid rebuild record for forwarding leg %d", ifindex)
	}
	base := rawNet &^ (PortForwardFlag | PortForwardScopedFlag)
	desired := base
	want := map[overlayFwdCidrKey]uint8{}
	var parseErr error
	if allow {
		desired |= PortForwardFlag
		if len(cidrs) > 0 {
			desired |= PortForwardScopedFlag
			for _, cidr := range cidrs {
				key, err := fwdCIDRKey(uint32(ifindex), cidr)
				if err != nil {
					parseErr = err
					break
				}
				want[key] = 1
			}
		}
	}
	if snapshotErr == nil && parseErr == nil && rawNet == desired && aliasNet == desired && maps.Equal(current, want) {
		return nil
	}
	if err := setVethAlias(link, base, ips, mac); err != nil {
		// Still revoke the active right even if durable metadata cannot be saved.
		_ = setPortNet(ifindex, base)
		return err
	}
	if err := setPortNet(ifindex, base); err != nil {
		return err
	}
	if parseErr != nil {
		return parseErr
	}
	if snapshotErr != nil {
		return snapshotErr
	}
	for key := range current {
		if _, keep := want[key]; !keep {
			if err := mp.Delete(key); err != nil && !isNotExist(err) {
				return err
			}
		}
	}
	for key, value := range want {
		if current[key] != value {
			if err := mp.Put(key, value); err != nil {
				return err
			}
		}
	}
	if err := setVethAlias(link, desired, ips, mac); err != nil {
		return err
	}
	return setPortNet(ifindex, desired)
}
