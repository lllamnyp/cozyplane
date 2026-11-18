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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func testAddr(cidr string, flags, scope int) netlink.Addr {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	n.IP = ip
	return netlink.Addr{IPNet: n, Flags: flags, Scope: scope}
}

// TestMasqAddr checks the masquerade source is the link's first global, primary, non-host-prefix address.
func TestMasqAddr(t *testing.T) {
	universe, link := int(netlink.SCOPE_UNIVERSE), int(netlink.SCOPE_LINK)
	cases := []struct {
		name  string
		addrs []netlink.Addr
		want  string
	}{
		{"none", nil, ""},
		{"the subnet address", []netlink.Addr{testAddr("10.20.100.12/24", 0, universe)}, "10.20.100.12"},
		{"a /32 before it is skipped", []netlink.Addr{testAddr("10.20.100.10/32", 0, universe), testAddr("10.20.100.12/24", 0, universe)}, "10.20.100.12"},
		{"only a /32", []netlink.Addr{testAddr("172.18.250.10/32", 0, universe)}, ""},
		{"a secondary is skipped", []netlink.Addr{testAddr("10.0.0.9/24", unix.IFA_F_SECONDARY, universe), testAddr("10.0.1.9/24", 0, universe)}, "10.0.1.9"},
		{"link-local is skipped", []netlink.Addr{testAddr("169.254.1.1/16", 0, link), testAddr("10.0.0.5/24", 0, universe)}, "10.0.0.5"},
		{"v6 link-local and deprecated are skipped", []netlink.Addr{
			testAddr("fe80::1/64", 0, link),
			testAddr("2001:db8::1/64", unix.IFA_F_DEPRECATED, universe),
			testAddr("2001:db8::2/64", 0, universe),
		}, "2001:db8::2"},
		{"a /128 is skipped", []netlink.Addr{testAddr("2001:db8::9/128", 0, universe)}, ""},
	}
	for _, c := range cases {
		got := masqAddr(c.addrs)
		if (got == nil && c.want != "") || (got != nil && got.String() != c.want) {
			t.Errorf("%s: masqAddr = %v, want %q", c.name, got, c.want)
		}
	}
}

// TestMasqEligible checks which links can carry masqueraded pod traffic.
func TestMasqEligible(t *testing.T) {
	up := net.FlagUp
	cases := []struct {
		l    linkInfo
		want bool
	}{
		{linkInfo{Flags: up, Type: "device", Ether: true}, true},
		{linkInfo{Flags: up, Type: "vlan", Ether: true}, true},
		{linkInfo{Flags: up, Type: "bridge", Ether: true}, true},
		{linkInfo{Flags: up, Type: "bond", Ether: true}, true},
		{linkInfo{Flags: 0, Type: "device", Ether: true}, false},
		{linkInfo{Flags: up | net.FlagLoopback, Type: "device", Ether: false}, false},
		{linkInfo{Flags: up, Type: "dummy", Ether: true}, false},
		{linkInfo{Flags: up, Type: "veth", Ether: true}, true},
		{linkInfo{Flags: up, Type: "geneve", Ether: true}, false},
		{linkInfo{Flags: up, Type: "vxlan", Ether: true}, false},
		{linkInfo{Flags: up, Type: "wireguard", Ether: false}, false},
	}
	for _, c := range cases {
		if got := masqEligible(c.l); got != c.want {
			t.Errorf("masqEligible(%+v) = %v, want %v", c.l, got, c.want)
		}
	}
}
