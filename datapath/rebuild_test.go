/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package datapath

import (
	"net"
	"testing"
)

func TestVethAliasRoundtrip(t *testing.T) {
	mac, _ := net.ParseMAC("02:a1:b2:c3:d4:e5")
	tests := []struct {
		name   string
		rawNet uint32
		ips    []net.IP
	}{
		{"default dual-stack", 0, []net.IP{net.ParseIP("10.244.1.7"), net.ParseIP("fd00:10:244:1::7")}},
		{"vpc v4", 102, []net.IP{net.ParseIP("10.70.0.2")}},
		{"vpc v6", 100, []net.IP{net.ParseIP("fd00:70::3")}},
		{"gateway leg", 102 | PortGatewayFlag, []net.IP{net.ParseIP("10.70.0.1")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			alias := FormatVethAlias(tc.rawNet, tc.ips, mac)
			rawNet, ips, gotMAC, ok := parseVethAlias(alias)
			if !ok {
				t.Fatalf("parse failed for %q", alias)
			}
			if rawNet != tc.rawNet {
				t.Fatalf("rawNet: got %#x, want %#x", rawNet, tc.rawNet)
			}
			if gotMAC.String() != mac.String() {
				t.Fatalf("mac: got %s, want %s", gotMAC, mac)
			}
			if len(ips) != len(tc.ips) {
				t.Fatalf("ips: got %v, want %v", ips, tc.ips)
			}
			for i := range ips {
				if !ips[i].Equal(tc.ips[i]) {
					t.Fatalf("ip[%d]: got %s, want %s", i, ips[i], tc.ips[i])
				}
			}
		})
	}
}

func TestParseVethAliasRejects(t *testing.T) {
	mac, _ := net.ParseMAC("02:a1:b2:c3:d4:e5")
	for _, alias := range []string{
		"",                       // pre-alias CNI
		"some other alias",       // foreign
		"cozyplane:2;net=1;gw=0", // future version — don't guess
		"cozyplane:1;net=x;gw=0;mac=02:a1:b2:c3:d4:e5;ips=10.0.0.1",     // bad net
		"cozyplane:1;net=1;gw=2;mac=02:a1:b2:c3:d4:e5;ips=10.0.0.1",     // bad gw
		"cozyplane:1;net=1;gw=0;mac=nope;ips=10.0.0.1",                  // bad mac
		"cozyplane:1;net=1;gw=0;mac=02:a1:b2:c3:d4:e5;ips=",             // no ips
		"cozyplane:1;net=1;gw=0;mac=02:a1:b2:c3:d4:e5;ips=10.0.0.1,bad", // bad ip
	} {
		if _, _, _, ok := parseVethAlias(alias); ok {
			t.Errorf("parseVethAlias(%q) accepted, want reject", alias)
		}
	}
	// Sanity: the canonical form is accepted.
	if _, _, _, ok := parseVethAlias(FormatVethAlias(7, []net.IP{net.ParseIP("10.0.0.1")}, mac)); !ok {
		t.Fatal("canonical alias rejected")
	}
}
