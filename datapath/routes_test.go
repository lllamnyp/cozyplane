package datapath

import (
	"net"
	"testing"
)

func TestRouteMapEntryECMP(t *testing.T) {
	_, value, err := routeMapEntry(RouteEntry{
		Scope: 100, CIDR: "10.20.0.0/16",
		NextHops: []RouteNextHop{
			{GwIP: net.ParseIP("10.0.0.10")},
			{GwIP: net.ParseIP("10.0.0.11"), NodeIP: net.ParseIP("192.0.2.11")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.Count != 2 || value.NextHops[0].NodeIp != 0 || value.NextHops[1].NodeIp == 0 {
		t.Fatalf("unexpected ECMP value: %+v", value)
	}
}

// Only a VPN route that names its appliance may carry the boundary exception.
func TestRouteMapEntryVPNFlag(t *testing.T) {
	leg := []RouteNextHop{{GwIP: net.ParseIP("10.0.0.10")}}
	for _, tc := range []struct {
		name string
		in   RouteEntry
		want uint8
	}{
		{"VPN route", RouteEntry{Scope: 100, CIDR: "10.250.0.1/32", NextHops: leg, VPN: true}, routeFlagVPN},
		{"gateway route", RouteEntry{Scope: 100, CIDR: "10.20.0.0/16", NextHops: leg}, 0},
		{"blackholed VPN route", RouteEntry{Scope: 100, CIDR: "10.250.0.1/32", VPN: true}, 0},
	} {
		_, value, err := routeMapEntry(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		if value.Flags != tc.want {
			t.Errorf("%s: flags = %d, want %d", tc.name, value.Flags, tc.want)
		}
	}
}

func TestRouteMapEntryRejectsMoreThanTwoNextHops(t *testing.T) {
	nextHops := []RouteNextHop{{GwIP: net.ParseIP("10.0.0.10")}, {GwIP: net.ParseIP("10.0.0.11")}, {GwIP: net.ParseIP("10.0.0.12")}}
	if _, _, err := routeMapEntry(RouteEntry{Scope: 100, CIDR: "10.20.0.0/16", NextHops: nextHops}); err == nil {
		t.Fatal("route with more than two next-hops was accepted")
	}
}
