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
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

// The host veth's link alias is the rebuild record: configureHostVeth (CNI ADD)
// stores exactly the ports/locals payload there, so a restarted agent can
// re-derive the CNI-written map entries after a map-ABI recreate without any
// API dependency (default-network pods have no Port object at all). The alias
// is host-local, survives agent restarts, and dies with the veth.
//
// Format (versioned, order fixed):
//
//	cozyplane:1;net=<net-id>;gw=<0|1>;mac=<pod-iface MAC>;ips=<ip>[,<ip>]
const vethAliasPrefix = "cozyplane:1;"

// Host-side veth name prefixes (must match hostVethNameFor/gwHostVethNameFor in
// the CNI plugin and the masquerade RETURN rules in firewall.go).
const (
	podVethPrefix = "cph"
	gwVethPrefix  = "cpg"
)

// FormatVethAlias renders the rebuild record for a pod's host veth. rawNet is
// the ports-map value: the network id, with PortGatewayFlag set for a gateway
// VPC leg.
func FormatVethAlias(rawNet uint32, ips []net.IP, mac net.HardwareAddr) string {
	gw := 0
	if rawNet&PortGatewayFlag != 0 {
		gw = 1
	}
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	return fmt.Sprintf("%snet=%d;gw=%d;mac=%s;ips=%s",
		vethAliasPrefix, PortNet(rawNet), gw, mac, strings.Join(ss, ","))
}

// parseVethAlias inverts FormatVethAlias. ok is false for an empty, foreign, or
// malformed alias (a veth created by a pre-alias CNI release).
func parseVethAlias(alias string) (rawNet uint32, ips []net.IP, mac net.HardwareAddr, ok bool) {
	body, found := strings.CutPrefix(alias, vethAliasPrefix)
	if !found {
		return 0, nil, nil, false
	}
	fields := map[string]string{}
	for _, kv := range strings.Split(body, ";") {
		k, v, found := strings.Cut(kv, "=")
		if !found {
			return 0, nil, nil, false
		}
		fields[k] = v
	}
	netID, err := strconv.ParseUint(fields["net"], 10, 32)
	if err != nil {
		return 0, nil, nil, false
	}
	rawNet = uint32(netID)
	switch fields["gw"] {
	case "0":
	case "1":
		rawNet |= PortGatewayFlag
	default:
		return 0, nil, nil, false
	}
	mac, err = net.ParseMAC(fields["mac"])
	if err != nil {
		return 0, nil, nil, false
	}
	for _, s := range strings.Split(fields["ips"], ",") {
		ip := net.ParseIP(s)
		if ip == nil {
			return 0, nil, nil, false
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return 0, nil, nil, false
	}
	return rawNet, ips, mac, true
}

// SetVethAlias records the rebuild record on a host veth (CNI ADD).
func SetVethAlias(link netlink.Link, rawNet uint32, ips []net.IP, mac net.HardwareAddr) error {
	if err := netlink.LinkSetAlias(link, FormatVethAlias(rawNet, ips, mac)); err != nil {
		return fmt.Errorf("set veth alias: %w", err)
	}
	return nil
}

// RebuildStats reports what a local-state rebuild did.
type RebuildStats struct {
	Rebuilt    int      // veths whose ports/locals/bridges entries were re-put
	Reattached int      // veths whose tcx links were swapped to the fresh programs
	Pruned     int      // stale map entries removed (veth died without a CNI DEL)
	Skipped    []string // veths with no/invalid alias (pre-alias CNI) — not rebuildable
}

// RebuildLocalState re-derives the CNI-written map entries (ports, locals,
// bridges) for every local cozyplane veth from its alias record, and swaps the
// veth's tcx links to the freshly pinned programs. It runs at every agent
// start:
//
//   - after a map-ABI recreate it restores existing pods' datapath state, so an
//     upgrade across a map change is a rolling DaemonSet update, not a fleet
//     reboot (issue #7);
//   - on a compatible restart the re-puts are no-op overwrites and the
//     re-attach picks up the new release's programs, which existing pods would
//     otherwise keep missing until recreated.
//
// A veth without a valid alias is skipped (reported in Skipped) but still
// re-attached: its map state either survived (compatible restart) or is gone
// with the old maps (ABI break — the pod needs a restart either way).
// Per-veth failures are collected, not fatal: one broken veth must not stop
// the node's rebuild.
func (m *Manager) RebuildLocalState() (RebuildStats, error) {
	var stats RebuildStats
	links, err := netlink.LinkList()
	if err != nil {
		return stats, fmt.Errorf("list links: %w", err)
	}
	var errs []error
	for _, l := range links {
		name := l.Attrs().Name
		if !strings.HasPrefix(name, podVethPrefix) && !strings.HasPrefix(name, gwVethPrefix) {
			continue
		}
		idx := l.Attrs().Index

		rawNet, ips, mac, ok := parseVethAlias(l.Attrs().Alias)
		if !ok {
			stats.Skipped = append(stats.Skipped, name)
		} else if err := rebuildVeth(l, idx, rawNet, ips, mac); err != nil {
			errs = append(errs, fmt.Errorf("rebuild %s: %w", name, err))
		} else {
			stats.Rebuilt++
		}

		if err := ReattachIngress(idx, m.objs.CozyplaneFromPod); err != nil {
			errs = append(errs, fmt.Errorf("reattach %s ingress: %w", name, err))
			continue
		}
		if err := ReattachEgress(idx, m.objs.CozyplaneToPod); err != nil {
			errs = append(errs, fmt.Errorf("reattach %s egress: %w", name, err))
			continue
		}
		stats.Reattached++
	}

	pruned, err := pruneStaleLocalState()
	if err != nil {
		errs = append(errs, fmt.Errorf("prune stale entries: %w", err))
	}
	stats.Pruned = pruned

	return stats, errors.Join(errs...)
}

// pruneStaleLocalState removes ports/locals/bridges entries whose veth died
// without a CNI DEL (unclean pod death: the netns vanished, nothing cleaned
// the maps). A stale locals entry is not just a leak — if its VPC IP is later
// reallocated to a pod on another node, the dead local entry shadows the
// remote route and blackholes same-node senders.
//
// Every check is per-entry against the kernel at decision time, so a pod
// being ADDed concurrently is never falsely pruned: the CNI writes the alias
// before any map entry, hence an entry's veth+alias witness always exists by
// the time the entry does.
func pruneStaleLocalState() (int, error) {
	pruned := 0

	// locals: live iff the endpoint's ifindex is a cozyplane veth whose alias
	// vouches for (net, ip).
	lm, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "locals"), nil)
	if err != nil {
		return 0, fmt.Errorf("open pinned locals map: %w", err)
	}
	defer lm.Close()
	var lk overlayLocalKey
	var lv overlayEndpoint
	var staleLocals []overlayLocalKey
	it := lm.Iterate()
	for it.Next(&lk, &lv) {
		if !aliasVouches(int(lv.Ifindex), lk.Net, lk.Ip) {
			staleLocals = append(staleLocals, lk)
		}
	}
	if err := it.Err(); err != nil {
		return pruned, fmt.Errorf("iterate locals: %w", err)
	}
	for _, k := range staleLocals {
		if err := lm.Delete(&k); err == nil {
			pruned++
		}
	}

	// ports: live iff the ifindex is still a cozyplane veth. No net compare —
	// a severed pod's entry legitimately reads QuarantineNet, not its alias net.
	pm, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "ports"), nil)
	if err != nil {
		return pruned, fmt.Errorf("open pinned ports map: %w", err)
	}
	defer pm.Close()
	var pk, pv uint32
	var stalePorts []uint32
	it = pm.Iterate()
	for it.Next(&pk, &pv) {
		if cozyVethByIndex(int(pk)) == nil {
			stalePorts = append(stalePorts, pk)
		}
	}
	if err := it.Err(); err != nil {
		return pruned, fmt.Errorf("iterate ports: %w", err)
	}
	for _, k := range stalePorts {
		if err := pm.Delete(&k); err == nil {
			pruned++
		}
	}

	// bridges: live iff the fabric IP's host route points at a cozyplane veth
	// whose alias vouches for the bridged (net, VPC IP).
	bm, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "bridges"), nil)
	if err != nil {
		return pruned, fmt.Errorf("open pinned bridges map: %w", err)
	}
	defer bm.Close()
	var bk overlayAddr128
	var bv overlayBridgeEp
	var staleBridges []overlayAddr128
	it = bm.Iterate()
	for it.Next(&bk, &bv) {
		if !bridgeVouched(bk, bv) {
			staleBridges = append(staleBridges, bk)
		}
	}
	if err := it.Err(); err != nil {
		return pruned, fmt.Errorf("iterate bridges: %w", err)
	}
	for _, k := range staleBridges {
		if err := bm.Delete(&k); err == nil {
			pruned++
		}
	}

	return pruned, nil
}

// cozyVethByIndex returns the link at ifindex if it is a cozyplane host veth.
func cozyVethByIndex(ifindex int) netlink.Link {
	l, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil
	}
	name := l.Attrs().Name
	if !strings.HasPrefix(name, podVethPrefix) && !strings.HasPrefix(name, gwVethPrefix) {
		return nil
	}
	return l
}

// aliasVouches reports whether ifindex is a cozyplane veth whose alias record
// covers (net, addr).
func aliasVouches(ifindex int, net_ uint32, addr overlayAddr128) bool {
	l := cozyVethByIndex(ifindex)
	if l == nil {
		return false
	}
	rawNet, ips, _, ok := parseVethAlias(l.Attrs().Alias)
	if !ok || PortNet(rawNet) != net_ {
		return false
	}
	for _, ip := range ips {
		if a, err := addr128(ip); err == nil && a == addr {
			return true
		}
	}
	return false
}

// bridgeVouched reports whether a bridges entry's fabric IP still routes to a
// cozyplane veth whose alias covers the bridged (net, VPC IP).
func bridgeVouched(fabric overlayAddr128, ep overlayBridgeEp) bool {
	routes, err := netlink.RouteGet(addr128ToIP(fabric))
	if err != nil || len(routes) == 0 {
		return false
	}
	return aliasVouches(routes[0].LinkIndex, ep.Net, ep.VpcIp)
}

// rebuildVeth re-puts one veth's ports/locals entries and, for a VPC pod, its
// bridges entry (fabric IP -> {net, VPC IP}), re-derived from the veth's
// scope-link fabric route — the one host route whose destination is not a pod
// address.
func rebuildVeth(l netlink.Link, idx int, rawNet uint32, ips []net.IP, mac net.HardwareAddr) error {
	if err := SetPortNet(idx, rawNet); err != nil {
		return err
	}
	for _, ip := range ips {
		if err := SetLocal(PortNet(rawNet), ip, idx, mac); err != nil {
			return err
		}
	}
	// Only a plain VPC pod has a fabric bridge (default pods are their fabric
	// identity; a gateway VPC leg has none), and it has exactly one VPC IP.
	if PortNet(rawNet) == 0 || rawNet&PortGatewayFlag != 0 || len(ips) != 1 {
		return nil
	}
	fabric, err := fabricRouteIP(l, ips)
	if err != nil {
		return err
	}
	if fabric == "" {
		return fmt.Errorf("no fabric route on VPC pod veth")
	}
	return setBridge(fabric, ips[0].String(), PortNet(rawNet))
}

// fabricRouteIP finds the fabric IP of a VPC pod's veth: the destination of the
// gatewayless host route (/32 or /128) that is not one of the pod's addresses.
// No scope filter — a v6 device route reports scope global, not link (only v4
// host routes carry SCOPE_LINK).
func fabricRouteIP(l netlink.Link, podIPs []net.IP) (string, error) {
	routes, err := netlink.RouteList(l, netlink.FAMILY_ALL)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
next:
	for _, r := range routes {
		if r.Dst == nil || r.Gw != nil {
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); ones != bits {
			continue // fe80::/64 and friends, not a host route
		}
		if r.Dst.IP.IsLinkLocalUnicast() || r.Dst.IP.IsMulticast() {
			continue
		}
		for _, ip := range podIPs {
			if r.Dst.IP.Equal(ip) {
				continue next
			}
		}
		return r.Dst.IP.String(), nil
	}
	return "", nil
}
