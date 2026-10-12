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

func TestRouteMapEntryRejectsMoreThanTwoNextHops(t *testing.T) {
	nextHops := []RouteNextHop{{GwIP: net.ParseIP("10.0.0.10")}, {GwIP: net.ParseIP("10.0.0.11")}, {GwIP: net.ParseIP("10.0.0.12")}}
	if _, _, err := routeMapEntry(RouteEntry{Scope: 100, CIDR: "10.20.0.0/16", NextHops: nextHops}); err == nil {
		t.Fatal("route with more than two next-hops was accepted")
	}
}
