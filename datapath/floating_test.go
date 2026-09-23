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
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	loIdx     = 1
	uplinkIdx = 2 // eth0, the default route link; from_uplink already here
	vlanIdx   = 3 // a secondary NIC
	otherIdx  = 4
)

func ipNetOf(t *testing.T, s string) *net.IPNet {
	t.Helper()
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", s, err)
	}
	n.IP = ip // as the kernel reports it: the address, with the prefix's mask
	return n
}

// The taxonomy of external addresses, and where the floating machinery binds
// for each.
func TestFloatFactsBindLink(t *testing.T) {
	for _, tc := range []struct {
		name    string
		facts   floatFacts
		want    int
		wantErr bool
	}{{
		name:  "routed via a gateway on the default uplink",
		facts: floatFacts{RouteLink: uplinkIdx, RouteGw: net.ParseIP("10.0.0.1"), DefaultUplink: uplinkIdx},
		want:  0,
	}, {
		// The router forwards the address to us over the secondary NIC, so it
		// arrives there and from_uplink must be attached there. Leaving it
		// unbound egresses the default, spoof-guarded NIC with a foreign source.
		name:  "routed via a gateway on a secondary NIC",
		facts: floatFacts{RouteLink: vlanIdx, RouteGw: net.ParseIP("10.20.0.1"), DefaultUplink: uplinkIdx},
		want:  vlanIdx,
	}, {
		name:  "on-link on the default uplink",
		facts: floatFacts{RouteLink: uplinkIdx, DefaultUplink: uplinkIdx},
		want:  0,
	}, {
		name:  "on-link on a secondary NIC",
		facts: floatFacts{RouteLink: vlanIdx, DefaultUplink: uplinkIdx},
		want:  vlanIdx,
	}, {
		name:  "FIB named no link",
		facts: floatFacts{RouteLink: 0, DefaultUplink: uplinkIdx},
		want:  0,
	}, {
		// A cloud NATs the public address onto the instance's own private one.
		name: "node-owned, on the default uplink",
		facts: floatFacts{
			RouteLink: loIdx, RouteLocal: true,
			OwnerLink: uplinkIdx, OwnerUsable: true, DefaultUplink: uplinkIdx,
		},
		want: 0,
	}, {
		name: "node-owned, on a secondary NIC",
		facts: floatFacts{
			RouteLink: loIdx, RouteLocal: true,
			OwnerLink: otherIdx, OwnerUsable: true, DefaultUplink: uplinkIdx,
		},
		want: otherIdx,
	}, {
		name: "local but owned by no link",
		facts: floatFacts{
			RouteLink: loIdx, RouteLocal: true,
			OwnerLink: 0, DefaultUplink: uplinkIdx,
		},
		wantErr: true,
	}, {
		// A VIP on lo, a dummy, or a down link: nothing arrives there, and
		// binding it would black-hole every reply on the node.
		name: "local, owner cannot carry wire traffic",
		facts: floatFacts{
			RouteLink: loIdx, RouteLocal: true,
			OwnerLink: loIdx, OwnerUsable: false, DefaultUplink: uplinkIdx,
		},
		wantErr: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.facts.bindLink()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("bindLink() = %d, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("bindLink() error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("bindLink() = %d, want %d", got, tc.want)
			}
		})
	}
}

// lo must never be selected, whatever else is true: nothing arrives on it.
func TestFloatFactsNeverBindsLoopback(t *testing.T) {
	for _, f := range []floatFacts{
		{RouteLink: loIdx, RouteLocal: true, OwnerLink: uplinkIdx, OwnerUsable: true, DefaultUplink: uplinkIdx},
		{RouteLink: loIdx, RouteLocal: true, OwnerLink: otherIdx, OwnerUsable: true, DefaultUplink: uplinkIdx},
		{RouteLink: loIdx, RouteLocal: true, OwnerLink: loIdx, OwnerUsable: false, DefaultUplink: uplinkIdx},
	} {
		got, err := f.bindLink()
		if err != nil {
			continue // refusing is always acceptable
		}
		if got == loIdx {
			t.Fatalf("bindLink() selected the loopback for %+v", f)
		}
	}
}

// The owner lookup is the costly step, so it must be made only when the FIB
// says the address is ours.
func TestFactsForAndNeedsOwner(t *testing.T) {
	local := factsFor(netlink.Route{LinkIndex: loIdx, Type: unix.RTN_LOCAL}, uplinkIdx)
	if !local.RouteLocal || !local.needsOwner() {
		t.Fatalf("RTN_LOCAL route: RouteLocal=%v needsOwner=%v, want both true", local.RouteLocal, local.needsOwner())
	}
	// The single-NIC LB-ingress case: on-link on the default uplink, by far the
	// most common, and it must cost nothing beyond the route lookup.
	onLink := factsFor(netlink.Route{LinkIndex: uplinkIdx, Type: unix.RTN_UNICAST}, uplinkIdx)
	if onLink.RouteLocal || onLink.needsOwner() {
		t.Fatal("on-link route asked for an owner lookup")
	}
	gw := factsFor(netlink.Route{LinkIndex: vlanIdx, Gw: net.ParseIP("10.20.0.1"), Type: unix.RTN_UNICAST}, uplinkIdx)
	if gw.needsOwner() || gw.RouteGw == nil {
		t.Fatal("gateway route mis-read")
	}
}

func TestCarriesWire(t *testing.T) {
	for _, tc := range []struct {
		name string
		l    linkInfo
		want bool
	}{
		{"up ethernet", linkInfo{Flags: net.FlagUp, Type: "device"}, true},
		{"loopback", linkInfo{Flags: net.FlagUp | net.FlagLoopback, Type: "device"}, false},
		{"dummy", linkInfo{Flags: net.FlagUp, Type: "dummy"}, false},
		{"down", linkInfo{Flags: 0, Type: "device"}, false},
	} {
		if got := carriesWire(tc.l); got != tc.want {
			t.Errorf("%s: carriesWire = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestOwnerFromAddrs(t *testing.T) {
	ip := net.ParseIP("10.20.0.16")
	up := linkInfo{Flags: net.FlagUp, Type: "device"}
	links := map[int]linkInfo{
		loIdx:     {Flags: net.FlagUp | net.FlagLoopback, Type: "device"},
		uplinkIdx: up,
		vlanIdx:   up,
		otherIdx:  {Flags: net.FlagUp, Type: "dummy"},
	}
	addr := func(idx int, s string) netlink.Addr {
		return netlink.Addr{IPNet: ipNetOf(t, s), LinkIndex: idx}
	}

	if idx, usable := ownerFromAddrs([]netlink.Addr{addr(vlanIdx, "10.20.0.16/24")}, links, ip); idx != vlanIdx || !usable {
		t.Errorf("usable owner = %d,%v; want %d,true", idx, usable, vlanIdx)
	}
	// Configured only on lo: reported, so the error can name it, but not usable.
	if idx, usable := ownerFromAddrs([]netlink.Addr{addr(loIdx, "10.20.0.16/32")}, links, ip); idx != loIdx || usable {
		t.Errorf("lo owner = %d,%v; want %d,false", idx, usable, loIdx)
	}
	// A dummy is reported the same way — never as usable.
	if idx, usable := ownerFromAddrs([]netlink.Addr{addr(otherIdx, "10.20.0.16/32")}, links, ip); idx != otherIdx || usable {
		t.Errorf("dummy owner = %d,%v; want %d,false", idx, usable, otherIdx)
	}
	// A usable owner wins over an unusable one whatever the dump order.
	for _, order := range [][]netlink.Addr{
		{addr(loIdx, "10.20.0.16/32"), addr(vlanIdx, "10.20.0.16/24")},
		{addr(vlanIdx, "10.20.0.16/24"), addr(loIdx, "10.20.0.16/32")},
	} {
		if idx, usable := ownerFromAddrs(order, links, ip); idx != vlanIdx || !usable {
			t.Errorf("mixed owners = %d,%v; want %d,true", idx, usable, vlanIdx)
		}
	}
	if idx, _ := ownerFromAddrs([]netlink.Addr{addr(vlanIdx, "10.20.0.99/24")}, links, ip); idx != 0 {
		t.Errorf("no owner = %d, want 0", idx)
	}
}

// The next-hop derivation. A host prefix covers only the address itself, so
// treating it as a subnet yields VIP+1 — not a router — and black-holes every
// reply on the node, since the floating slot is global.
func TestCoveringSubnet(t *testing.T) {
	ip := net.ParseIP("10.20.0.16")
	addrs := func(ss ...string) []netlink.Addr {
		var out []netlink.Addr
		for _, s := range ss {
			out = append(out, netlink.Addr{IPNet: ipNetOf(t, s)})
		}
		return out
	}

	if n, nh := coveringSubnet(addrs("10.20.0.16/32"), ip); n != nil || nh != nil {
		t.Errorf("host prefix alone = %v,%v; want nil,nil", n, nh)
	}
	// The address configured with a real prefix IS its own covering subnet.
	if n, nh := coveringSubnet(addrs("10.20.0.16/24"), ip); n == nil || n.String() != "10.20.0.0/24" || !nh.Equal(net.ParseIP("10.20.0.1")) {
		t.Errorf("own /24 = %v,%v; want 10.20.0.0/24,10.20.0.1", n, nh)
	}
	// A /32 secondary alongside a real prefix: the prefix wins, either order.
	for _, a := range [][]netlink.Addr{
		addrs("10.20.0.16/32", "10.20.0.5/24"),
		addrs("10.20.0.5/24", "10.20.0.16/32"),
	} {
		n, nh := coveringSubnet(a, ip)
		if n == nil || n.String() != "10.20.0.0/24" || !nh.Equal(net.ParseIP("10.20.0.1")) {
			t.Errorf("mixed prefixes = %v,%v; want 10.20.0.0/24,10.20.0.1", n, nh)
		}
	}
	// Longest covering prefix wins.
	if n, _ := coveringSubnet(addrs("10.20.0.5/16", "10.20.0.5/24"), ip); n == nil || n.String() != "10.20.0.0/24" {
		t.Errorf("longest prefix = %v, want 10.20.0.0/24", n)
	}
	if n, _ := coveringSubnet(addrs("10.30.0.5/24"), ip); n != nil {
		t.Errorf("non-covering prefix = %v, want nil", n)
	}
	// A routed pool anchors on the gateway, which is on the link's subnet even
	// though the address itself is not.
	if n, _ := coveringSubnet(addrs("10.20.0.5/24"), net.ParseIP("10.20.0.1")); n == nil || n.String() != "10.20.0.0/24" {
		t.Errorf("gateway anchor = %v, want 10.20.0.0/24", n)
	}
}

func TestFloatRebind(t *testing.T) {
	on := func(idx int) floatBinding { return floatBinding{ifindex: idx, nh: 1, base: 2, mask: 3} }
	if !floatRebind(on(vlanIdx), on(otherIdx)) {
		t.Error("moving the slot between two links is a rebind")
	}
	if floatRebind(on(vlanIdx), on(vlanIdx)) {
		t.Error("same link is not a rebind")
	}
	if floatRebind(floatBinding{}, on(vlanIdx)) {
		t.Error("first bind is not a rebind")
	}
}

// The slot holds a link AND its next-hop and subnet. Two addresses can share a
// link and resolve different next-hops; keying the "already configured" check on
// the link alone silently kept the first address's next-hop for the second.
func TestFloatNeedsProgram(t *testing.T) {
	cur := floatBinding{ifindex: vlanIdx, nh: 0x0100140a, base: 0x0000140a, mask: 0x00ffffff}

	if floatNeedsProgram(cur, cur) {
		t.Error("an identical binding must not be re-programmed")
	}
	otherNH := cur
	otherNH.nh = 0xfe00140a
	if !floatNeedsProgram(cur, otherNH) {
		t.Error("same link, different next-hop must be re-programmed")
	}
	otherNet := cur
	otherNet.mask = 0x0000ffff
	if !floatNeedsProgram(cur, otherNet) {
		t.Error("same link, different subnet must be re-programmed")
	}
	otherLink := cur
	otherLink.ifindex = otherIdx
	if !floatNeedsProgram(cur, otherLink) {
		t.Error("a different link must be re-programmed")
	}
	// ...but a next-hop change on one link is not a link re-bind, so it must not
	// warn about contention.
	if floatRebind(cur, otherNH) {
		t.Error("same link is not a re-bind, even when the next-hop changes")
	}
}

func TestOwnerFromAddrsNilIPNet(t *testing.T) {
	links := map[int]linkInfo{uplinkIdx: {Flags: net.FlagUp, Type: "device"}}
	ip := net.ParseIP("10.20.0.16")
	// netlink.Addr embeds *net.IPNet; a row parsed from a message carrying
	// neither IFA_ADDRESS nor IFA_LOCAL leaves it nil, and a.IP dereferences it.
	nilRow := netlink.Addr{LinkIndex: uplinkIdx}
	if idx, _ := ownerFromAddrs([]netlink.Addr{nilRow}, links, ip); idx != 0 {
		t.Fatalf("nil IPNet row = %d, want 0", idx)
	}
	// And it must not hide a real owner sitting behind it in the dump.
	real := netlink.Addr{IPNet: ipNetOf(t, "10.20.0.16/24"), LinkIndex: uplinkIdx}
	for _, order := range [][]netlink.Addr{{nilRow, real}, {real, nilRow}} {
		if idx, usable := ownerFromAddrs(order, links, ip); idx != uplinkIdx || !usable {
			t.Errorf("with a nil row = %d,%v; want %d,true", idx, usable, uplinkIdx)
		}
	}
}

func TestRouteLookupErr(t *testing.T) {
	if err := routeLookupErr("10.20.0.16", 1, nil); err != nil {
		t.Errorf("a resolved route is not an error: %v", err)
	}
	empty := routeLookupErr("10.20.0.16", 0, nil)
	if empty == nil {
		t.Fatal("an empty FIB answer must be an error")
	}
	if strings.Contains(empty.Error(), "%!w") {
		t.Errorf("empty answer wraps a nil error: %q", empty.Error())
	}
	sentinel := errors.New("boom")
	wrapped := routeLookupErr("10.20.0.16", 0, sentinel)
	if !errors.Is(wrapped, sentinel) {
		t.Errorf("a real failure must stay unwrappable: %v", wrapped)
	}
}
