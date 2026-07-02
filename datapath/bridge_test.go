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

// The bridge's per-pod id is the fabric IP's offset within the node pod CIDR:
// unique (fabric IPs are unique) and collision-free without any allocator, so
// two same-node pods sharing a VPC IP still get distinct tables/marks.
func TestFabricOffset(t *testing.T) {
	cases := []struct {
		fabricIP, podCIDR string
		want              uint32
		wantErr           bool
	}{
		{"10.244.1.8", "10.244.1.0/24", 8, false},
		{"10.244.1.10", "10.244.1.0/24", 10, false},
		{"10.244.2.0", "10.244.2.0/24", 0, false},
		{"10.244.3.255", "10.244.3.0/24", 255, false},
		// A /23 node CIDR: offset spans the low 9 bits, still within the id space.
		{"10.244.3.5", "10.244.2.0/23", 261, false},
		{"not-an-ip", "10.244.1.0/24", 0, true},
		{"10.244.1.8", "bad-cidr", 0, true},
	}
	for _, tc := range cases {
		got, err := fabricOffset(tc.fabricIP, tc.podCIDR)
		if tc.wantErr {
			if err == nil {
				t.Errorf("fabricOffset(%q,%q) = nil error, want error", tc.fabricIP, tc.podCIDR)
			}
			continue
		}
		if err != nil {
			t.Errorf("fabricOffset(%q,%q): %v", tc.fabricIP, tc.podCIDR, err)
			continue
		}
		if got != tc.want {
			t.Errorf("fabricOffset(%q,%q) = %d, want %d", tc.fabricIP, tc.podCIDR, got, tc.want)
		}
	}
}

// Distinct fabric offsets must yield distinct fwmarks and tables (the property
// that lets the bridge deliver same-node same-VPC-IP pods correctly), and the
// ip-rule priority must sort before the main table (32766) or the main table's
// default route would shadow the mark rule.
func TestBridgeMarkAndPrioritySpace(t *testing.T) {
	seen := map[uint32]bool{}
	for off := uint32(0); off < 4096; off++ {
		mark := off << bridgeMarkShift
		if mark&^uint32(bridgeMarkMask) != 0 {
			t.Fatalf("offset %d mark 0x%x escapes the bridge mask 0x%x", off, mark, bridgeMarkMask)
		}
		if seen[mark] {
			t.Fatalf("offset %d produced a duplicate mark 0x%x", off, mark)
		}
		seen[mark] = true
		if prio := bridgeRuleBase + int(off); prio >= 32766 {
			t.Fatalf("offset %d rule priority %d does not sort before the main table", off, prio)
		}
	}
	// The mark bits must avoid kube-proxy's 0x4000/0x8000.
	if bridgeMarkMask&0xC000 != 0 {
		t.Errorf("bridge mask 0x%x overlaps kube-proxy marks 0x4000/0x8000", bridgeMarkMask)
	}
}
