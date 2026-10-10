package datapath

import (
	"errors"
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The caller has already claimed this fabric address for its sandbox. Replace
// a lingering sandbox's host route instead of accepting an unrelated EEXIST.
func EnsureFabricHostRoute(ifindex int, ip net.IP) error {
	if ip == nil || ifindex <= 0 {
		return fmt.Errorf("fabric route requires an address and interface")
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return withBridgeLock(func() error {
		return netlink.RouteReplace(&netlink.Route{LinkIndex: ifindex, Scope: netlink.SCOPE_LINK, Dst: &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}})
	})
}

func fabricRouteOwned(ifindex int, ip net.IP) (bool, error) {
	routes, err := netlink.RouteGet(ip)
	if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Multipath/ambiguous routing is not proof of an endpoint's ownership.
	return len(routes) == 1 && routes[0].LinkIndex == ifindex && routes[0].Gw == nil && len(routes[0].MultiPath) == 0, nil
}

func rebuildFabricLocal(ifindex int, ip net.IP, mac net.HardwareAddr) error {
	return withBridgeLock(func() error {
		owned, err := fabricRouteOwned(ifindex, ip)
		if err != nil {
			return err
		}
		if owned {
			return setLocal(0, ip, ifindex, mac)
		}
		current, _, found, err := GetLocal(0, ip)
		if err != nil {
			return err
		}
		if found && current == ifindex {
			return delLocal(0, ip)
		}
		return nil
	})
}
