//go:build linux

package datapath

import (
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestRebuildFabricRouteMayEqualVPCAddress(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("requires an isolated Linux network namespace with NET_ADMIN")
	}
	for _, address := range []string{"203.0.113.187", "fd00:187::10"} {
		t.Run(address, func(t *testing.T) {
			veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cp187-host"}, PeerName: "cp187-peer"}
			if err := netlink.LinkAdd(veth); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = netlink.LinkDel(veth) })
			for _, name := range []string{"cp187-host", "cp187-peer"} {
				link, err := netlink.LinkByName(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := netlink.LinkSetUp(link); err != nil {
					t.Fatal(err)
				}
			}
			// Use the actual route installation called by AddBridge. VPC CNI
			// intentionally installs no separate main-table VPC-address route.
			if err := addFabricRoute(address, "cp187-host"); err != nil {
				t.Fatal(err)
			}
			link, err := netlink.LinkByName("cp187-host")
			if err != nil {
				t.Fatal(err)
			}
			fabric, err := fabricRouteIP(link)
			if err != nil || fabric != address {
				t.Fatalf("live bridge route equal to VPC address was lost: fabric=%q err=%v", fabric, err)
			}
			secondary := "203.0.113.188"
			if address == "fd00:187::10" {
				secondary = "fd00:187::11"
			}
			if err := addFabricRoute(secondary, "cp187-host"); err != nil {
				t.Fatal(err)
			}
			if fabric, err = fabricRouteIP(link); err == nil || fabric != "" {
				t.Fatalf("ambiguous host routes guessed a fabric allocation: %q %v", fabric, err)
			}
			if err := delFabricRoute(secondary, "cp187-host"); err != nil {
				t.Fatal(err)
			}
			secondaryRoute, err := fabricRoute(secondary, link.Attrs().Index)
			if err != nil {
				t.Fatal(err)
			}
			secondaryRoute.Table = 20187
			if err := netlink.RouteReplace(secondaryRoute); err != nil {
				t.Fatal(err)
			}
			if fabric, err = fabricRouteIP(link); err != nil || fabric != address {
				t.Fatalf("non-main-table route displaced the fabric allocation: %q %v", fabric, err)
			}
			if err := delFabricRoute(address, "cp187-host"); err != nil {
				t.Fatal(err)
			}
			if fabric, err = fabricRouteIP(link); err != nil || fabric != "" {
				t.Fatalf("missing fabric route adopted another table: %q %v", fabric, err)
			}
		})
	}
}
