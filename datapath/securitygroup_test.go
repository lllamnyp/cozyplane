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

func cidr(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// TestUnionContaining is the #11 regression: the sg_cidr LPM returns only the
// longest-matching entry, so a narrower prefix from an unrelated group must not
// shadow a broader one. The compiler precomputes the union by propagating a
// containing rule's groups down into every entry it covers.
func TestUnionContaining(t *testing.T) {
	// group 1 admits 10.0.0.0/8; group 2 admits the narrower 10.1.0.0/16.
	// A client in 10.1.x.x matches the /16 (longest) — its bitmap must carry
	// BOTH groups, or a pod that is only in group 1 loses admission.
	items := []cidrGroup{
		{scope: 100, proto: 6, port: 80, cidr: cidr("10.0.0.0/8"), groups: 1 << 1},
		{scope: 100, proto: 6, port: 80, cidr: cidr("10.1.0.0/16"), groups: 1 << 2},
	}
	got := unionContaining(items)
	if got[0] != (1 << 1) {
		t.Errorf("the /8 entry should carry only its own group, got %#b", got[0])
	}
	// The /16 must gain group 1 from the containing /8.
	if got[1] != (1<<1 | 1<<2) {
		t.Errorf("the /16 entry must union the containing /8's group: got %#b want %#b", got[1], 1<<1|1<<2)
	}
}

func TestUnionContainingScoping(t *testing.T) {
	// Containment must not cross a tier: different net, proto, or port are
	// separate LPM lookups, so their prefixes never shadow each other.
	base := cidrGroup{scope: 100, proto: 6, port: 80, cidr: cidr("10.0.0.0/8"), groups: 1 << 1}
	for _, tc := range []struct {
		name string
		e    cidrGroup
	}{
		{"other net", cidrGroup{scope: 200, proto: 6, port: 80, cidr: cidr("10.1.0.0/16"), groups: 1 << 2}},
		{"other proto", cidrGroup{scope: 100, proto: 17, port: 80, cidr: cidr("10.1.0.0/16"), groups: 1 << 2}},
		{"other port", cidrGroup{scope: 100, proto: 6, port: 53, cidr: cidr("10.1.0.0/16"), groups: 1 << 2}},
	} {
		got := unionContaining([]cidrGroup{base, tc.e})
		if got[1] != (1 << 2) {
			t.Errorf("%s: must not inherit across tiers, got %#b", tc.name, got[1])
		}
	}
}

func TestUnionContainingV6AndFamilies(t *testing.T) {
	// v6 containment works, and families never cross (a v4 /8 does not contain a
	// v6 range).
	items := []cidrGroup{
		{scope: 100, proto: 6, port: 0, cidr: cidr("2001:db8::/32"), groups: 1 << 1},
		{scope: 100, proto: 6, port: 0, cidr: cidr("2001:db8:1::/48"), groups: 1 << 2},
		{scope: 100, proto: 6, port: 0, cidr: cidr("10.0.0.0/8"), groups: 1 << 3},
	}
	got := unionContaining(items)
	if got[1] != (1<<1 | 1<<2) {
		t.Errorf("v6 /48 must union the containing /32: got %#b", got[1])
	}
	if got[2] != (1 << 3) {
		t.Errorf("the v4 range must not inherit from a v6 prefix: got %#b", got[2])
	}
}

// Equal CIDRs from different groups already union via the map's |=; this
// confirms unionContaining does not double-count or miss them.
func TestUnionContainingEqual(t *testing.T) {
	items := []cidrGroup{
		{scope: 100, proto: 6, port: 80, cidr: cidr("10.1.0.0/16"), groups: 1 << 1},
		{scope: 100, proto: 6, port: 80, cidr: cidr("10.1.0.0/16"), groups: 1 << 2},
	}
	got := unionContaining(items)
	for i := range got {
		if got[i] != (1<<1 | 1<<2) {
			t.Errorf("equal CIDRs must union both ways: entry %d got %#b", i, got[i])
		}
	}
}
