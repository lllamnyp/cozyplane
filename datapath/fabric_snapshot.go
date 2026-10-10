package datapath

import (
	"fmt"
	"strings"

	"github.com/vishvananda/netlink"
)

// SnapshotLocalFabricIPs reads current host-owned endpoints without rebuilding
// maps or reattaching hooks. The host lock excludes partial CNI publication.
func SnapshotLocalFabricIPs() ([]LocalFabricIP, error) {
	var out []LocalFabricIP
	err := withBridgeLock(func() error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}
		for _, current := range links {
			attrs := current.Attrs()
			if current.Type() != "veth" || !strings.HasPrefix(attrs.Name, podVethPrefix) {
				continue
			}
			raw, ips, _, valid := parseVethAlias(attrs.Alias)
			if !valid || raw == QuarantineNet {
				continue
			}
			containerID, ifName := VethSandbox(attrs.Alias)
			if PortNet(raw) == 0 {
				for _, ip := range ips {
					owned, err := fabricRouteOwned(attrs.Index, ip)
					if err != nil {
						return err
					}
					if owned {
						out = append(out, LocalFabricIP{Address: ip.String(), ContainerID: containerID, IfName: ifName})
					}
				}
			} else {
				address, err := fabricRouteIP(current)
				if err != nil {
					return fmt.Errorf("inspect local fabric route: %w", err)
				}
				if address != "" {
					out = append(out, LocalFabricIP{Address: address, ContainerID: containerID, IfName: ifName})
				}
			}
		}
		return nil
	})
	return out, err
}
