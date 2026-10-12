package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Pool clients share a route-based interface, while CHILD_SA policies still bind
// each authenticated client to its assigned VIP and its own optional prefixes.
// Per-peer interfaces would overwrite the common pool route on every load.
func groupXfrmPeers(peers []peer) ([]peer, error) {
	groups := make(map[uint32]int, len(peers))
	var result []peer
	for _, p := range peers {
		if p.IfID == 0 {
			return nil, fmt.Errorf("IPsec if_id must be nonzero")
		}
		if index, found := groups[p.IfID]; found {
			previous := &result[index]
			if p.AddressPool == "" || p.AddressPool != previous.AddressPool || !slices.Equal(normalizeSelectors(p.LocalCIDRs), normalizeSelectors(previous.LocalCIDRs)) {
				return nil, fmt.Errorf("IPsec if_id reused across independent policies")
			}
			previous.RemoteCIDRs = normalizeSelectors(append(append([]string(nil), previous.RemoteCIDRs...), p.RemoteCIDRs...))
			if len(previous.RemoteCIDRs) > vpnlimits.RoutePrefixes {
				return nil, fmt.Errorf("IPsec route capacity exceeded")
			}
			continue
		}
		groups[p.IfID] = len(result)
		p.RemoteCIDRs = normalizeSelectors(p.RemoteCIDRs)
		result = append(result, p)
	}
	return result, nil
}

func normalizeSelectors(cidrs []string) []string {
	result := make([]string, 0, len(cidrs))
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil {
			result = append(result, prefix.Masked().String())
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func configuredPeers(cfg config) ([]peer, error) {
	pools := make(map[string]string, len(cfg.Pools))
	for _, pool := range cfg.Pools {
		if len(pool.CIDR) > vpnlimits.RoutePrefixBytes {
			return nil, fmt.Errorf("IPsec pool exceeds size budget")
		}
		prefix, err := netip.ParsePrefix(pool.CIDR)
		if err != nil || prefix.Addr().Is4In6() || !prefix.Addr().IsGlobalUnicast() || prefix.Bits() == 0 {
			return nil, fmt.Errorf("IPsec pool must be a unicast prefix")
		}
		if _, exists := pools[pool.Name]; exists {
			return nil, fmt.Errorf("duplicate IPsec pool name")
		}
		pools[pool.Name] = prefix.Masked().String()
	}
	result := append([]peer(nil), cfg.Peers...)
	for i := range result {
		p := &result[i]
		if cfg.LocalID != "" {
			p.LocalID = cfg.LocalID
		} else if cfg.Credentials != nil {
			p.LocalID = cfg.Credentials.LocalID
		}
		if p.AddressPool != "" {
			pool, exists := pools[p.AddressPool]
			if !exists {
				return nil, fmt.Errorf("IPsec peer references an unavailable pool")
			}
			p.poolCIDR = pool
			if !slices.Contains(normalizeSelectors(p.RemoteCIDRs), pool) {
				return nil, fmt.Errorf("IPsec peer is missing its pool route")
			}
		}
	}
	return result, nil
}

const xfrmDeviceAlias = "cozyplane-vpn-ipsec"

const (
	xfrmProbeName         = "cpxfrmprobe"
	xfrmProbeID    uint32 = 0xcb1
	xfrmProbeAlias        = "cozyplane-vpn-ipsec-probe"
)

// Recover only this daemon's exact throwaway probe, including the older
// unmarked form. A collision with a foreign device must never delete it.
func closeXfrmProbe() error {
	dev, err := netlink.LinkByName(xfrmProbeName)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	if err != nil {
		return err
	}
	xfrm, ok := dev.(*netlink.Xfrmi)
	if !ok || xfrm.Ifid != xfrmProbeID || (dev.Attrs().Alias != "" && dev.Attrs().Alias != xfrmProbeAlias) {
		return fmt.Errorf("XFRM probe name belongs to a foreign device")
	}
	if err := netlink.LinkSetDown(dev); err != nil {
		return err
	}
	return netlink.LinkDel(dev)
}

func protectRemotePrefixes(peers []peer) error {
	seen := make(map[string]bool)
	for _, p := range peers {
		for _, raw := range p.RemoteCIDRs {
			prefix, err := netlink.ParseIPNet(raw)
			if err != nil {
				return fmt.Errorf("invalid IPsec route prefix")
			}
			if seen[prefix.String()] {
				continue
			}
			seen[prefix.String()] = true
			if len(seen) > vpnlimits.RoutePrefixes {
				return fmt.Errorf("IPsec route capacity exceeded")
			}
			if err := netlink.RouteReplace(&netlink.Route{Dst: prefix, Table: unix.RT_TABLE_MAIN, Type: unix.RTN_BLACKHOLE, Protocol: unix.RTPROT_STATIC}); err != nil {
				return fmt.Errorf("protect IPsec route: %w", err)
			}
		}
	}
	return nil
}

func protectDeviceRoutes(device netlink.Link) error {
	routes, err := netlink.RouteList(device, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("list IPsec routes: %w", err)
	}
	var failures []error
	for _, route := range routes {
		// Connected/local/link-local routes describe the interface itself;
		// only the daemon's unicast remote-prefix routes require protection.
		if route.Dst == nil || route.Protocol == unix.RTPROT_KERNEL || route.Type != unix.RTN_UNICAST || !route.Dst.IP.IsGlobalUnicast() {
			continue
		}
		if err := netlink.RouteReplace(&netlink.Route{Dst: route.Dst, Table: unix.RT_TABLE_MAIN, Priority: route.Priority, Type: unix.RTN_BLACKHOLE, Protocol: unix.RTPROT_STATIC}); err != nil {
			failures = append(failures, fmt.Errorf("protect retired IPsec route: %w", err))
		}
	}
	return errors.Join(failures...)
}

// This daemon is the only route-based IPsec owner in its dedicated appliance
// namespace. Nonzero if_ids belong to it; policy-based (if_id=0) state is left
// alone. Close devices first, then revoke SAs/policies, then remove routes by
// deleting devices. Repeating this after SIGKILL also clears orphaned SAs.
func closePreviousXfrm() error {
	links, err := netlink.LinkList()
	if err != nil {
		return err
	}
	var owned []netlink.Link
	var failures []error
	for _, link := range links {
		xfrm, ok := link.(*netlink.Xfrmi)
		if !ok || link.Attrs().Name != fmt.Sprintf("ipsec%d", xfrm.Ifid) || (link.Attrs().Alias != "" && link.Attrs().Alias != xfrmDeviceAlias) {
			continue
		}
		owned = append(owned, link)
		if err := protectDeviceRoutes(link); err != nil {
			failures = append(failures, err)
		}
		if err := netlink.LinkSetDown(link); err != nil {
			failures = append(failures, fmt.Errorf("close XFRM interface: %w", err))
		}
	}
	if err := closeXfrmProbe(); err != nil {
		failures = append(failures, err)
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		failures = append(failures, fmt.Errorf("list XFRM state: %w", err))
	} else {
		for _, state := range states {
			if state.Ifid != 0 {
				if err := netlink.XfrmStateDel(&state); err != nil {
					failures = append(failures, fmt.Errorf("revoke XFRM state: %w", err))
				}
			}
		}
	}
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		failures = append(failures, fmt.Errorf("list XFRM policy: %w", err))
	} else {
		for _, policy := range policies {
			if policy.Ifid != 0 {
				if err := netlink.XfrmPolicyDel(&policy); err != nil {
					failures = append(failures, fmt.Errorf("revoke XFRM policy: %w", err))
				}
			}
		}
	}
	// Keep closed devices if revocation failed, so a retry retains their identity.
	if len(failures) == 0 {
		for _, link := range owned {
			if err := netlink.LinkDel(link); err != nil {
				failures = append(failures, fmt.Errorf("remove XFRM interface: %w", err))
			}
		}
	}
	return errors.Join(failures...)
}

func validateXfrmDevice(dev netlink.Link, ifID uint32) error {
	xfrm, ok := dev.(*netlink.Xfrmi)
	if !ok || xfrm.Ifid != ifID || ifID == 0 {
		return fmt.Errorf("XFRM interface type or if_id mismatch")
	}
	if alias := dev.Attrs().Alias; alias != "" && alias != xfrmDeviceAlias {
		return fmt.Errorf("XFRM interface belongs to another owner")
	}
	return nil
}
