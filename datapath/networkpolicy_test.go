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

import "testing"

// covers reports whether a port is matched by any prefix in the set.
func covers(pps []npPortPrefix, port uint16) bool {
	for _, pp := range pps {
		span := uint32(1) << (16 - pp.bits)
		if uint32(port) >= uint32(pp.port) && uint32(port) < uint32(pp.port)+span {
			return true
		}
	}
	return false
}

func TestNPPortPrefixes(t *testing.T) {
	// The any-port rule is a single /0.
	pps := npPortPrefixes(0, 0)
	if len(pps) != 1 || pps[0].bits != 0 {
		t.Fatalf("any-port = %+v, want one /0", pps)
	}
	// An exact port is a single /16.
	pps = npPortPrefixes(53, 53)
	if len(pps) != 1 || pps[0].bits != 16 || pps[0].port != 53 {
		t.Fatalf("exact port = %+v, want one /16 at 53", pps)
	}
	// Ranges: exact coverage, no leakage, sane entry counts.
	for _, r := range [][2]uint16{
		{8000, 8999}, {1, 65535}, {1024, 1024}, {32768, 65535},
		{1, 2}, {5, 11}, {65534, 65535},
	} {
		pps := npPortPrefixes(r[0], r[1])
		if len(pps) > 31 {
			t.Fatalf("range %v decomposed into %d prefixes (>31)", r, len(pps))
		}
		// Probe the boundaries and a sweep around them.
		for p := uint32(1); p <= 65535; p++ {
			inRange := uint16(p) >= r[0] && uint16(p) <= r[1]
			if covers(pps, uint16(p)) != inRange {
				t.Fatalf("range %v: port %d coverage mismatch (want %v): %+v", r, p, inRange, pps)
			}
		}
	}
}
