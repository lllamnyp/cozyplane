package main

import (
	"strings"
	"testing"
)

func TestRenderFRRActiveActive(t *testing.T) {
	got, err := renderFRR(routingConfig{
		LocalASN: 64520, PeerASN: 64521, BFD: true,
		PeerAddresses:  []string{"10.250.0.1", "2001:db8::1"},
		AdvertiseCIDRs: []string{"10.20.0.0/16", "2001:db8:20::/64"},
	}, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"router bgp 64520", "bgp router-id 192.0.2.10", "neighbor 10.250.0.1 remote-as 64521",
		"neighbor 10.250.0.1 bfd", "address-family ipv6 unicast", "network 2001:db8:20::/64",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FRR config missing %q:\n%s", want, got)
		}
	}
}

func TestRenderFRRRejectsInvalidASN(t *testing.T) {
	if _, err := renderFRR(routingConfig{PeerAddresses: []string{"192.0.2.1"}}, "192.0.2.10"); err == nil {
		t.Fatal("invalid ASNs were accepted")
	}
}
