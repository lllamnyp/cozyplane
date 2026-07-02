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

import "net"

// CIDRsOverlap reports whether any CIDR in a overlaps any CIDR in b.
// Unparsable entries are ignored (validation rejects them elsewhere).
//
// This is the address-space invariant behind two rules: overlapping VPCs can
// coexist (isolation is by overlay, not address space) but can never *peer* —
// peered traffic is routed natively, and one address cannot mean two things
// on a shared path.
func CIDRsOverlap(a, b []string) bool {
	for _, as := range a {
		_, an, err := net.ParseCIDR(as)
		if err != nil {
			continue
		}
		for _, bs := range b {
			_, bn, err := net.ParseCIDR(bs)
			if err != nil {
				continue
			}
			if an.Contains(bn.IP) || bn.Contains(an.IP) {
				return true
			}
		}
	}
	return false
}
