package main

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestApplianceRejectsInvalidPeerBeforeKernelOrDNS(t *testing.T) {
	key := wgtypes.Key{1}.String()
	for _, p := range []peer{
		{PublicKey: "secret-canary-" + strings.Repeat("A", 128<<10)},
		{PublicKey: key, Endpoint: "secret-canary-" + strings.Repeat("a", 128<<10) + ":51820"},
		{PublicKey: key, PresharedKey: "secret-canary-" + strings.Repeat("A", 128<<10)},
		{PublicKey: key, Keepalive: 65536},
		{PublicKey: key, AllowedIPs: make([]string, 4097)},
		{PublicKey: key, AllowedIPs: []string{strings.Repeat("a", 128<<10)}},
	} {
		out, routes, err := buildPeers([]peer{p})
		if err == nil || out != nil || routes != nil {
			t.Fatal("invalid peer yielded kernel config")
		}
		if len(err.Error()) > 1024 || strings.Contains(err.Error(), "secret-canary") {
			t.Fatal("sensitive input in rejection")
		}
	}
	out, routes, err := buildPeers([]peer{{PublicKey: key, PresharedKey: wgtypes.Key{2}.String(), Endpoint: "[2001:db8::1]:65535", Keepalive: 65535, AllowedIPs: []string{"203.0.113.0/24", "2001:db8:20::/64"}}})
	if err != nil || len(out) != 1 || len(routes) != 2 || out[0].Endpoint.Port != 65535 {
		t.Fatalf("valid peer boundaries refused: %v", err)
	}
}
