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

package v1alpha1

import (
	"cmp"
	"net/netip"
	"slices"
)

// CIDRsOverlap reports whether any CIDR in a overlaps any CIDR in b.
// Unparsable entries are ignored (validation rejects them elsewhere).
//
// This is the address-space invariant behind two rules: overlapping VPCs can
// coexist (isolation is by overlay, not address space) but can never *peer* —
// peered traffic is routed natively, and one address cannot mean two things
// on a shared path.
func CIDRsOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	prefixes := make([]netip.Prefix, 0, len(b))
	for _, value := range b {
		if prefix, err := overlapPrefix(value); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return cmp.Compare(a.Bits(), b.Bits()) // containing prefix first
	})
	// CIDR intervals are either disjoint or nested. Keep only disjoint intervals,
	// so the preceding start and the next start suffice to test any overlap.
	disjoint := prefixes[:0]
	for _, prefix := range prefixes {
		if len(disjoint) == 0 || !disjoint[len(disjoint)-1].Contains(prefix.Addr()) {
			disjoint = append(disjoint, prefix)
		}
	}
	for _, as := range a {
		an, err := overlapPrefix(as)
		if err != nil {
			continue
		}
		i, _ := slices.BinarySearchFunc(disjoint, an.Addr(), func(prefix netip.Prefix, addr netip.Addr) int {
			return prefix.Addr().Compare(addr)
		})
		if i < len(disjoint) && an.Contains(disjoint[i].Addr()) || i > 0 && disjoint[i-1].Contains(an.Addr()) {
			return true
		}
	}
	return false
}

func overlapPrefix(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	// net.IPNet.Contains treats mapped IPv4 networks as IPv4 networks too.
	if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix, nil
}
