package datapath

import (
	"github.com/vishvananda/netlink"
	"net"
)

// PrepareEndpointHooks fences a reused ifindex before installing tc hooks,
// without allowing a stale ADD to quarantine another sandbox or Port owner.
func PrepareEndpointHooks(link netlink.Link, containerID, ifName string, id PortVethIdentity) error {
	return withBridgeLock(func() error {
		if _, err := endpointVeth(link, containerID, ifName, id); err != nil {
			return err
		}
		return setPortNet(link.Attrs().Index, QuarantineNet)
	})
}

// ConfigureEndpoint replaces a forwarding grant without exposing a partial
// allowlist or racing the agent's grant writer. Errors retain disabled
// forwarding; quarantined endpoints cannot be reactivated by an ADD retry.
func ConfigureEndpoint(link netlink.Link, rawNet uint32, ips []net.IP, mac net.HardwareAddr, containerID, ifName string, id PortVethIdentity, cidrs []string) error {
	return withBridgeLock(func() error {
		base := rawNet &^ (PortForwardFlag | PortForwardScopedFlag)
		if _, err := endpointVeth(link, containerID, ifName, id); err != nil {
			return err
		}
		idx := link.Attrs().Index
		if err := setPortNet(idx, QuarantineNet); err != nil {
			return err
		}
		if err := setEndpointVethAlias(link, base, ips, mac, containerID, ifName, id); err != nil {
			return err
		}
		if err := ClearFwdCidrs(uint32(idx)); err != nil {
			return err
		}
		if rawNet&PortForwardScopedFlag != 0 {
			for _, cidr := range cidrs {
				if err := SetFwdCidr(uint32(idx), cidr); err != nil {
					return err
				}
			}
		}
		if err := setVethAlias(link, rawNet, ips, mac); err != nil {
			return err
		}
		for _, ip := range ips {
			if err := setLocal(PortNet(rawNet), ip, idx, mac); err != nil {
				return err
			}
		}
		return setPortNet(idx, rawNet)
	})
}
