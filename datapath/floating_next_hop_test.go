package datapath

import (
	"net"
	"testing"
)

func TestFloatingNextHopConfiguration(t *testing.T) {
	for _, raw := range []string{"", "172.20.255.254"} {
		if err := New().SetFloatingNextHopIPv4(raw); err != nil {
			t.Fatalf("valid next hop %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"invalid", "fd00::1", "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255"} {
		if err := New().SetFloatingNextHopIPv4(raw); err == nil {
			t.Fatalf("accepted invalid next hop %q", raw)
		}
	}
}

func TestFloatingNextHopSelection(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("172.20.0.0/16")
	first := net.ParseIP("172.20.0.1")
	router := net.ParseIP("172.20.255.254")
	routeGateway := net.ParseIP("172.20.0.254")
	for _, tc := range []struct {
		name                      string
		gateway, configured, want net.IP
		fail                      bool
	}{
		{"legacy connected default", nil, nil, first, false},
		{"configured connected router", nil, router, router, false},
		{"FIB gateway has priority", routeGateway, router, routeGateway, false},
		{"wrong interface fails closed", nil, net.ParseIP("10.40.0.1"), nil, true},
		{"network address rejected", nil, net.ParseIP("172.20.0.0"), nil, true},
		{"broadcast rejected", nil, net.ParseIP("172.20.255.255"), nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := floatingNextHop(subnet, first, tc.gateway, tc.configured)
			if tc.fail {
				if err == nil {
					t.Fatal("expected invalid next hop")
				}
				return
			}
			if err != nil || !actual.Equal(tc.want) {
				t.Fatalf("got %v, %v; want %v", actual, err, tc.want)
			}
		})
	}
}
