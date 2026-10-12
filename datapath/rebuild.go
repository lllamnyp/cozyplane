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
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The host veth's link alias is the rebuild record: configureHostVeth (CNI ADD)
// stores exactly the ports/locals payload there, so a restarted agent can
// re-derive the CNI-written map entries after a map-ABI recreate without any
// API dependency (default-network pods have no Port object at all). The alias
// is host-local, survives agent restarts, and dies with the veth.
//
// Format (versioned, order fixed):
//
//	cozyplane:1;net=<net-id>;gw=<0|1>;fwd=<0|1>;mac=<pod-iface MAC>;ips=<ip>[,<ip>]
//
// `fwd` was added with multi-attach and is OPTIONAL on read: an alias written by
// an earlier release has no such key and parses as fwd=0, which is what it was.
// Without it a granted forwarding leg would silently lose PORT_F_FORWARD on the
// first agent restart and start dropping its own transit traffic on the RPF
// check — the failure would look like a datapath bug, hours after the change
// that caused it.
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
	if rawNet == QuarantineNet {
		return vethAliasPrefix + "revoked=1"
	}
	gw := 0
	if rawNet&PortGatewayFlag != 0 {
		gw = 1
	}
	ss := make([]string, 0, len(ips))
	for _, ip := range ips {
		ss = append(ss, ip.String())
	}
	fwd := 0
	if rawNet&PortForwardFlag != 0 {
		fwd = 1
	}
	scoped := 0
	if rawNet&PortForwardScopedFlag != 0 {
		scoped = 1
	}
	return fmt.Sprintf("%snet=%d;gw=%d;fwd=%d;scoped=%d;mac=%s;ips=%s",
		vethAliasPrefix, PortNet(rawNet), gw, fwd, scoped, mac, strings.Join(ss, ","))
}

// parseVethAlias inverts FormatVethAlias. ok is false for an empty, foreign, or
// malformed alias (a veth created by a pre-alias CNI release).
func parseVethAlias(alias string) (rawNet uint32, ips []net.IP, mac net.HardwareAddr, ok bool) {
	if alias == vethAliasPrefix+"revoked=1" || strings.HasPrefix(alias, vethAliasPrefix+"revoked=1;") {
		return QuarantineNet, nil, nil, true
	}
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
		if _, exists := fields[k]; exists {
			return 0, nil, nil, false
		}
		switch k {
		case "net", "gw", "fwd", "scoped", "mac", "ips", "container", "ifname", "port", "portuid", "s", "staged":
		default:
			return 0, nil, nil, false
		}
		fields[k] = v
	}
	netID, err := strconv.ParseUint(fields["net"], 10, 32)
	if err != nil || (netID != 0 && (netID < uint64(netid.FirstVNI) || netID > uint64(netid.LastVNI))) {
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
	switch fields["fwd"] {
	case "", "0": // absent: written before multi-attach existed
	case "1":
		rawNet |= PortForwardFlag
	default:
		return 0, nil, nil, false
	}
	switch fields["scoped"] {
	case "0":
	case "1":
		if rawNet&PortForwardFlag == 0 {
			return 0, nil, nil, false
		}
		rawNet |= PortForwardScopedFlag
	case "":
		// Legacy fwd=1 aliases cannot distinguish scoped from blanket grants.
		// Preserve the CIDR check rather than silently grant arbitrary sources.
		if rawNet&PortForwardFlag != 0 {
			rawNet |= PortForwardScopedFlag
		}
	default:
		return 0, nil, nil, false
	}
	if netID == 0 && rawNet != 0 {
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
	return withBridgeLock(func() error { return setVethAlias(link, rawNet, ips, mac) })
}

func setVethAlias(link netlink.Link, rawNet uint32, ips []net.IP, mac net.HardwareAddr) error {
	current, err := netlink.LinkByIndex(link.Attrs().Index)
	if err != nil {
		return err
	}
	if old, _, _, valid := parseVethAlias(current.Attrs().Alias); valid && old == QuarantineNet && rawNet != QuarantineNet {
		return fmt.Errorf("revoked veth requires a new sandbox")
	}
	alias := FormatVethAlias(rawNet, ips, mac)
	container, iface := VethSandbox(current.Attrs().Alias)
	alias = aliasWithSandbox(alias, container, iface)
	id := VethPortIdentity(current.Attrs().Alias)
	alias = aliasWithPortIdentity(alias, id)
	if err := netlink.LinkSetAlias(link, alias); err != nil {
		return fmt.Errorf("set veth alias: %w", err)
	}
	link.Attrs().Alias = alias
	return nil
}

func aliasWithSandbox(alias, containerID, ifName string) string {
	if containerID == "" || ifName == "" {
		return alias
	}
	return alias + ";container=" + url.QueryEscape(containerID) + ";ifname=" + url.QueryEscape(ifName)
}

func VethSandbox(alias string) (containerID, ifName string) {
	if _, _, _, valid := parseVethAlias(alias); !valid {
		return "", ""
	}
	for _, field := range strings.Split(alias, ";") {
		key, encoded, found := strings.Cut(field, "=")
		if !found {
			continue
		}
		value, err := url.QueryUnescape(encoded)
		if err != nil {
			return "", ""
		}
		switch key {
		case "container":
			containerID = value
		case "ifname":
			ifName = value
		}
	}
	return
}

func SetVethSandbox(link netlink.Link, containerID, ifName string) error {
	return withBridgeLock(func() error {
		current, err := netlink.LinkByIndex(link.Attrs().Index)
		if err != nil {
			return err
		}
		rawNet, ips, mac, valid := parseVethAlias(current.Attrs().Alias)
		if !valid {
			return fmt.Errorf("cannot record sandbox on invalid veth alias")
		}
		alias := aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(rawNet, ips, mac), containerID, ifName), VethPortIdentity(current.Attrs().Alias))
		if len(alias) > 255 {
			return fmt.Errorf("endpoint alias exceeds Linux limit")
		}
		if err := netlink.LinkSetAlias(current, alias); err != nil {
			return err
		}
		link.Attrs().Alias = alias
		return nil
	})
}

// AdoptVethPortIdentity upgrades a legacy record only while its ownership
// evidence still matches the caller's snapshot. It never activates delivery.
func AdoptVethPortIdentity(ifindex int, expectedAlias string, id PortVethIdentity) (string, error) {
	var updated string
	err := withBridgeLock(func() error {
		link, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		if link.Type() != "veth" || link.Attrs().Alias != expectedAlias {
			return fmt.Errorf("endpoint changed before ownership adoption")
		}
		raw, ips, mac, valid := parseVethAlias(expectedAlias)
		if !valid || raw == QuarantineNet || id.UID == "" {
			return fmt.Errorf("invalid endpoint ownership adoption")
		}
		if previous := VethPortIdentity(expectedAlias); previous.UID != "" && previous.UID != id.UID {
			return fmt.Errorf("endpoint belongs to another Port generation")
		}
		cid, iface := VethSandbox(expectedAlias)
		updated = aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(raw, ips, mac), cid, iface), id)
		if len(updated) > 255 {
			return fmt.Errorf("endpoint alias exceeds Linux limit")
		}
		if err := netlink.LinkSetAlias(link, updated); err != nil {
			return err
		}
		if !id.Staged && PortNet(raw) != 0 {
			for _, ip := range ips {
				idx, _, found, err := GetLocal(PortNet(raw), ip)
				if err != nil {
					return err
				}
				if found && idx == ifindex {
					if err := setLocal(PortNet(raw), ip, ifindex, mac); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
	return updated, err
}

// PodVethName is the host-side name the CNI gives a sandbox's primary veth.
// The CNI and the agent's legacy-sandbox recovery must agree on it exactly.
func PodVethName(containerID string) string {
	if len(containerID) > 11 {
		containerID = containerID[:11]
	}
	return podVethPrefix + containerID
}

// RecordLegacyVethSandbox fills the absent sandbox witness of an endpoint wired
// by a CNI release that predates it. It only touches an unchanged record that
// has no witness yet, and never activates delivery.
func RecordLegacyVethSandbox(ifindex int, expectedAlias, containerID, ifName string) error {
	if containerID == "" || ifName == "" {
		return fmt.Errorf("incomplete sandbox witness")
	}
	return withBridgeLock(func() error {
		link, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		if link.Type() != "veth" || link.Attrs().Alias != expectedAlias {
			return fmt.Errorf("endpoint changed before sandbox recovery")
		}
		raw, ips, mac, valid := parseVethAlias(expectedAlias)
		if !valid || raw == QuarantineNet {
			return fmt.Errorf("invalid endpoint for sandbox recovery")
		}
		if cid, iface := VethSandbox(expectedAlias); cid != "" || iface != "" {
			return fmt.Errorf("endpoint already records a sandbox")
		}
		alias := aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(raw, ips, mac), containerID, ifName), VethPortIdentity(expectedAlias))
		if len(alias) > 255 {
			return fmt.Errorf("endpoint alias exceeds Linux limit")
		}
		return netlink.LinkSetAlias(link, alias)
	})
}

type PortVethIdentity struct {
	UID    string
	Staged bool
}

func VethPortIdentity(alias string) (id PortVethIdentity) {
	for _, field := range strings.Split(alias, ";") {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		switch key {
		case "portuid", "port":
			id.UID, _ = url.QueryUnescape(value)
		case "staged", "s":
			id.Staged = value != "0" // malformed state must not activate locals
		}
	}
	return
}

func aliasWithPortIdentity(alias string, id PortVethIdentity) string {
	if id.UID != "" {
		alias += ";port=" + url.QueryEscape(id.UID)
	}
	if id.Staged {
		alias += ";s=1"
	}
	return alias
}

// SetEndpointVethAlias publishes sandbox, Port generation and staging together.
func SetEndpointVethAlias(link netlink.Link, rawNet uint32, ips []net.IP, mac net.HardwareAddr, containerID, ifName string, id PortVethIdentity) error {
	return withBridgeLock(func() error { return setEndpointVethAlias(link, rawNet, ips, mac, containerID, ifName, id) })
}

func setEndpointVethAlias(link netlink.Link, rawNet uint32, ips []net.IP, mac net.HardwareAddr, containerID, ifName string, id PortVethIdentity) error {
	current, err := endpointVeth(link, containerID, ifName, id)
	if err != nil {
		return err
	}
	previous := VethPortIdentity(current.Attrs().Alias)
	if previous.Staged {
		id.Staged = true
	} // only verified agent cutover activates
	alias := aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(rawNet, ips, mac), containerID, ifName), id)
	if len(alias) > 255 {
		return fmt.Errorf("endpoint alias exceeds Linux limit")
	}
	if err := netlink.LinkSetAlias(current, alias); err != nil {
		return err
	}
	link.Attrs().Alias = alias
	return nil
}

func endpointVeth(link netlink.Link, containerID, ifName string, id PortVethIdentity) (netlink.Link, error) {
	current, err := netlink.LinkByIndex(link.Attrs().Index)
	if err != nil {
		return nil, err
	}
	if current.Type() != "veth" || current.Attrs().Name != link.Attrs().Name {
		return nil, fmt.Errorf("endpoint link changed")
	}
	if old, _, _, valid := parseVethAlias(current.Attrs().Alias); valid && old == QuarantineNet {
		return nil, fmt.Errorf("revoked veth requires a new sandbox")
	}
	if previous := VethPortIdentity(current.Attrs().Alias); previous.UID != "" && previous.UID != id.UID {
		return nil, fmt.Errorf("endpoint belongs to another Port generation")
	}
	if cid, iface := VethSandbox(current.Attrs().Alias); cid != "" && (cid != containerID || iface != ifName) {
		return nil, fmt.Errorf("endpoint belongs to another sandbox")
	}
	return current, nil
}

// SetLocalStaging updates only endpoints of this Port generation and retains
// their sandbox witness. Staging removes only each matched veth's locals entry.
func SetLocalStaging(net_ uint32, ip net.IP, uid string, staged bool) error {
	return withBridgeLock(func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, link := range links {
			id := VethPortIdentity(link.Attrs().Alias)
			if uid == "" || id.UID != uid || link.Type() != "veth" {
				continue
			}
			raw, ips, mac, ok := parseVethAlias(link.Attrs().Alias)
			if !ok || raw == QuarantineNet || PortNet(raw) != net_ {
				continue
			}
			matches := false
			for _, a := range ips {
				matches = matches || a.Equal(ip)
			}
			if !matches {
				continue
			}
			id.Staged = staged
			cid, iface := VethSandbox(link.Attrs().Alias)
			alias := aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(raw, ips, mac), cid, iface), id)
			if err := netlink.LinkSetAlias(link, alias); err != nil {
				return err
			}
			if staged {
				idx, _, found, err := GetLocal(net_, ip)
				if err != nil {
					return err
				}
				if found && idx == link.Attrs().Index {
					if err := delLocal(net_, ip); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

// LocalFabricIP is a successfully rebuilt underlay endpoint, derived from an
// alias (net0) or the primary VPC leg's fabric route. It is never a claim by itself.
type LocalFabricIP struct{ Address, ContainerID, IfName string }

// EnsureLocalFromVeth programs the locals entry for (net, ip) from the local
// veth whose alias record covers it — the cutover half of staged locals: a
// migration-target CNI ADD defers its locals entry (the VM is still active
// elsewhere), and the agent calls this when the persistent Port's node
// becomes this node. Returns false when no such veth exists (the ADD hasn't
// happened here yet — it will program locals itself, seeing spec.node==self).
func EnsureLocalFromVeth(net_ uint32, ip net.IP, containerID, ifName string, portUID ...string) (bool, error) {
	ifindex, _, ok, err := vethForAddr(net_, ip, containerID, ifName)
	if err != nil || !ok {
		return false, err
	}
	err = withBridgeLock(func() error {
		link, err := netlink.LinkByIndex(ifindex)
		if err != nil {
			return err
		}
		id := VethPortIdentity(link.Attrs().Alias)
		if len(portUID) > 0 {
			if id.UID != "" && id.UID != portUID[0] {
				return fmt.Errorf("veth belongs to another Port generation")
			}
			id.UID = portUID[0]
		}
		id.Staged = false
		raw, ips, aliasMAC, valid := parseVethAlias(link.Attrs().Alias)
		if !valid || raw == QuarantineNet || PortNet(raw) != net_ || link.Type() != "veth" {
			return fmt.Errorf("veth is not active")
		}
		cid, iface := VethSandbox(link.Attrs().Alias)
		if containerID != "" && (cid != containerID || iface != ifName) {
			return fmt.Errorf("sandbox changed before cutover")
		}
		matches := false
		for _, a := range ips {
			matches = matches || a.Equal(ip)
		}
		if !matches {
			return fmt.Errorf("endpoint address changed before cutover")
		}
		if len(portUID) > 0 && VethPortIdentity(link.Attrs().Alias).UID == "" && containerID == "" {
			return fmt.Errorf("legacy cutover requires a sandbox witness")
		}
		alias := aliasWithPortIdentity(aliasWithSandbox(FormatVethAlias(raw, ips, aliasMAC), cid, iface), id)
		if err := netlink.LinkSetAlias(link, alias); err != nil {
			return err
		}
		return setLocal(net_, ip, ifindex, aliasMAC)
	})
	return err == nil, err
}

// vethForAddr finds the local host veth whose rebuild alias covers (net, ip),
// returning its ifindex and the pinned MAC. ok is false when no such veth
// exists on this node (e.g. the CNI ADD hasn't landed here).
func vethForAddr(net_ uint32, ip net.IP, containerID, ifName string) (ifindex int, mac net.HardwareAddr, ok bool, err error) {
	links, err := netlink.LinkList()
	if err != nil {
		return 0, nil, false, fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		name := l.Attrs().Name
		if !strings.HasPrefix(name, podVethPrefix) && !strings.HasPrefix(name, gwVethPrefix) {
			continue
		}
		if l.Type() != "veth" {
			continue
		}
		if containerID != "" {
			id, iface := VethSandbox(l.Attrs().Alias)
			if id != containerID || iface != ifName {
				continue
			}
		}
		rawNet, ips, amac, aok := parseVethAlias(l.Attrs().Alias)
		if !aok || PortNet(rawNet) != net_ {
			continue
		}
		for _, aip := range ips {
			if aip.Equal(ip) {
				if ok {
					return 0, nil, false, fmt.Errorf("multiple local veths for network %d address %s sandbox %s", net_, ip, containerID)
				}
				ifindex, mac, ok = l.Attrs().Index, amac, true
				break
			}
		}
	}
	return ifindex, mac, ok, nil
}

// RebuildStats reports what a local-state rebuild did.
type RebuildStats struct {
	FabricIPs  []LocalFabricIP
	Rebuilt    int      // veths whose ports/locals/bridges entries were re-put
	Reattached int      // veths whose tcx links were swapped to the fresh programs
	Pruned     int      // stale map entries removed (veth died without a CNI DEL)
	Healed     int      // veths whose mis-masked fe80::1/0 was replaced with /64
	Skipped    []string // veths with no/invalid alias (pre-alias CNI) — not rebuildable
}

// healLinkLocalGW replaces a mis-masked fe80::1/0 on a host veth with the
// intended fe80::1/64. The /0 came from an 8-byte CIDRMask on the 16-byte
// address (fixed in the CNI); its damage is the kernel's on-link route for
// ::/0 — `default dev <veth>` at metric 256, which outranks a host's RA
// default and hijacks node v6 egress. Deleting the address removes that route.
func healLinkLocalGW(l netlink.Link) (bool, error) {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
	if err != nil {
		return false, fmt.Errorf("list addrs: %w", err)
	}
	gw := net.ParseIP("fe80::1")
	for _, a := range addrs {
		if !a.IP.Equal(gw) {
			continue
		}
		if ones, _ := a.Mask.Size(); ones == 64 {
			return false, nil // already correct
		}
		if err := netlink.AddrDel(l, &a); err != nil {
			return false, fmt.Errorf("del mis-masked fe80::1: %w", err)
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{
			IPNet: &net.IPNet{IP: gw, Mask: net.CIDRMask(64, 128)},
			Flags: unix.IFA_F_NODAD,
		}); err != nil {
			return false, fmt.Errorf("re-add fe80::1/64: %w", err)
		}
		return true, nil
	}
	return false, nil
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
			if rawNet != QuarantineNet {
				containerID, ifName := VethSandbox(l.Attrs().Alias)
				if PortNet(rawNet) == 0 {
					for _, ip := range ips {
						owned, err := fabricRouteOwned(idx, ip)
						if err != nil {
							errs = append(errs, err)
							continue
						}
						if !owned {
							continue
						}
						stats.FabricIPs = append(stats.FabricIPs, LocalFabricIP{Address: ip.String(), ContainerID: containerID, IfName: ifName})
					}
				} else if fabric, err := fabricRouteIP(l); err != nil {
					errs = append(errs, err)
				} else if fabric != "" {
					stats.FabricIPs = append(stats.FabricIPs, LocalFabricIP{Address: fabric, ContainerID: containerID, IfName: ifName})
				}
			}
		}

		if healed, err := healLinkLocalGW(l); err != nil {
			errs = append(errs, fmt.Errorf("heal %s fe80::1: %w", name, err))
		} else if healed {
			stats.Healed++
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
	var pruned int
	err := withBridgeLock(func() error {
		var err error
		pruned, err = pruneStaleLocalStateLocked()
		return err
	})
	return pruned, err
}

func pruneStaleLocalStateLocked() (int, error) {
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
		link := cozyVethByIndex(int(lv.Ifindex))
		if link == nil || VethPortIdentity(link.Attrs().Alias).Staged || !aliasVouches(int(lv.Ifindex), lk.Net, lk.Ip) {
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
	owners, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "bridge_owners"), nil)
	if err != nil {
		return pruned, err
	}
	defer owners.Close()
	var owner overlayBridgeOwner
	var staleOwners []overlayAddr128
	ownerIt := owners.Iterate()
	for ownerIt.Next(&bk, &owner) {
		if err := bm.Lookup(&bk, &bv); isNotExist(err) {
			staleOwners = append(staleOwners, bk)
		} else if err != nil {
			return pruned, err
		}
	}
	if err := ownerIt.Err(); err != nil {
		return pruned, err
	}
	for _, key := range staleOwners {
		if err := owners.Delete(&key); err != nil && !isNotExist(err) {
			return pruned, err
		}
	}

	// fabric_of: the inverse of bridges — live iff its bridges counterpart
	// (just pruned above) still maps the fabric IP back to this (net, VPC IP).
	fm, err := ebpf.LoadPinnedMap(filepath.Join(PinRoot, "fabric_of"), nil)
	if err != nil {
		return pruned, fmt.Errorf("open pinned fabric_of map: %w", err)
	}
	defer fm.Close()
	var fk overlayLocalKey
	var fv overlayAddr128
	var staleFabric []overlayLocalKey
	it = fm.Iterate()
	for it.Next(&fk, &fv) {
		var ep overlayBridgeEp
		if err := bm.Lookup(&fv, &ep); err != nil || ep.Net != fk.Net || ep.VpcIp != fk.Ip {
			staleFabric = append(staleFabric, fk)
		}
	}
	if err := it.Err(); err != nil {
		return pruned, fmt.Errorf("iterate fabric_of: %w", err)
	}
	for _, k := range staleFabric {
		if err := fm.Delete(&k); err == nil {
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
	if l.Type() != "veth" {
		return nil
	}
	return l
}

// aliasVouches reports whether the entry pointing at ifindex should be kept:
// the veth must exist, and when it carries a valid alias record the record
// must cover (net, addr). A live veth WITHOUT a valid alias is kept — it was
// created by a pre-alias CNI release, and its map entries are trustworthy,
// just not re-derivable. (Pruning those on the first post-alias agent start
// broke every pre-existing pod's delivery — caught live on the dev cluster.)
func aliasVouches(ifindex int, net_ uint32, addr overlayAddr128) bool {
	l := cozyVethByIndex(ifindex)
	if l == nil {
		return false // veth gone: the entry is stale
	}
	if net_ == 0 {
		owned, err := fabricRouteOwned(ifindex, addr128ToIP(addr))
		if err != nil || !owned {
			return false
		}
	}
	rawNet, ips, _, ok := parseVethAlias(l.Attrs().Alias)
	if !ok {
		return true // pre-alias veth: benefit of the doubt
	}
	if PortNet(rawNet) != net_ {
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
// unique owned main-table fabric host route. Its address may equal the VPC IP.
func rebuildVeth(l netlink.Link, idx int, rawNet uint32, ips []net.IP, mac net.HardwareAddr) error {
	if err := SetPortNet(idx, rawNet); err != nil {
		return err
	}
	if rawNet == QuarantineNet {
		return nil // persist revocation; never restore endpoints from this link
	}
	for _, ip := range ips {
		if PortNet(rawNet) == 0 {
			if err := rebuildFabricLocal(idx, ip, mac); err != nil {
				return err
			}
			continue
		}
		if VethPortIdentity(l.Attrs().Alias).Staged {
			continue
		}
		if err := SetLocal(PortNet(rawNet), ip, idx, mac); err != nil {
			return err
		}
	}
	// Only a VPC pod has a fabric bridge (a default pod IS its fabric identity),
	// and a bridged leg carries exactly one VPC IP.
	if PortNet(rawNet) == 0 || len(ips) != 1 {
		return nil
	}
	fabric, err := fabricRouteIP(l)
	if err != nil {
		return err
	}
	if fabric == "" {
		// No fabric route: this is not the pod's PRIMARY leg, so it has no
		// bridge to rebuild. A gateway's VPC leg never had one, and with
		// multi-attach neither does a secondary attachment — there is one
		// fabric handle per pod and entry 0 owns it (docs/multi-attach.md).
		//
		// The route's presence is the signal, deliberately, and the gateway
		// FLAG is not: a forwarding attachment carries that flag and may
		// perfectly well be the primary leg, so testing the flag here would
		// silently skip rebuilding a bridge that exists — the pod would come
		// back from an agent restart unreachable on its own status.podIP.
		return nil
	}
	// Heal the fabric IP's permanent neighbour (pods ADDed by a pre-neighbour
	// CNI release lack it, and node-originated traffic — kubelet probes, DNS
	// resolver replies — dies in FAILED ARP/NDP without it). Idempotent.
	if err := addFabricNeigh(fabric, l.Attrs().Name, mac); err != nil {
		return err
	}
	return withBridgeLock(func() error { return setBridge(fabric, ips[0].String(), l.Attrs().Name, PortNet(rawNet)) })
}

// fabricRouteIP finds the fabric IP of a VPC pod's veth: the destination of the
// gatewayless main-table host route (/32 or /128). VPC CNI installs no separate
// main-table VPC-address route, so the fabric IP may equal the VPC address.
// Require effective route ownership and refuse multiple distinct candidates.
// No scope filter — a v6 device route reports scope global, not link (only v4
// host routes carry SCOPE_LINK).
func fabricRouteIP(l netlink.Link) (string, error) {
	routes, err := netlink.RouteList(l, netlink.FAMILY_ALL)
	if err != nil {
		return "", fmt.Errorf("list routes: %w", err)
	}
	fabric := ""
	for _, r := range routes {
		if r.Dst == nil || r.Gw != nil || r.Table != unix.RT_TABLE_MAIN || r.Type != unix.RTN_UNICAST || r.LinkIndex != l.Attrs().Index || len(r.MultiPath) != 0 {
			continue
		}
		if ones, bits := r.Dst.Mask.Size(); ones != bits {
			continue // fe80::/64 and friends, not a host route
		}
		if r.Dst.IP.IsLinkLocalUnicast() || r.Dst.IP.IsMulticast() {
			continue
		}
		owned, err := fabricRouteOwned(l.Attrs().Index, r.Dst.IP)
		if err != nil {
			return "", fmt.Errorf("check fabric route ownership: %w", err)
		}
		if !owned {
			continue
		}
		address := r.Dst.IP.String()
		if fabric != "" && fabric != address {
			return "", fmt.Errorf("ambiguous fabric host routes on %s", l.Attrs().Name)
		}
		fabric = address
	}
	return fabric, nil
}
