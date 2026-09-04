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
	"slices"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPlanTCX(t *testing.T) {
	tests := []struct {
		name      string
		attached  []ebpf.ProgramID
		want      ebpf.ProgramID
		wantKeep  int
		wantStale []int
	}{
		{
			// The steady state: our program is already the only one here.
			// Nothing is attached, nothing is detached.
			name:      "already current",
			attached:  []ebpf.ProgramID{42},
			want:      42,
			wantKeep:  0,
			wantStale: nil,
		},
		{
			// A plain agent restart. One link, running the previous
			// generation: adopt it and swap the program. Attaching a second
			// link here is what split the datapath on dev4.
			name:      "one stale link is adopted, not stacked",
			attached:  []ebpf.ProgramID{7},
			want:      42,
			wantKeep:  0,
			wantStale: nil,
		},
		{
			// Already split (an agent that restarted before this fix): keep
			// the first — it is the one that runs first, so it is the one
			// whose verdicts matter — and detach the rest.
			name:      "two generations: keep one, detach the other",
			attached:  []ebpf.ProgramID{7, 42},
			want:      42,
			wantKeep:  0,
			wantStale: []int{1},
		},
		{
			name:      "three of ours collapse to one",
			attached:  []ebpf.ProgramID{7, 9, 11},
			want:      42,
			wantKeep:  0,
			wantStale: []int{1, 2},
		},
		{
			// Our program is attached, but behind an older one. The older link
			// runs first and would keep winning, so it must go.
			name:      "current sits behind a stale link",
			attached:  []ebpf.ProgramID{7, 42},
			want:      42,
			wantKeep:  0,
			wantStale: []int{1},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := planTCX(tc.attached, tc.want)
			if got.current != tc.wantKeep {
				t.Errorf("current = %d, want %d", got.current, tc.wantKeep)
			}
			if !slices.Equal(got.stale, tc.wantStale) {
				t.Errorf("stale = %v, want %v", got.stale, tc.wantStale)
			}
			// Whatever the input, exactly one of our links survives.
			if 1+len(got.stale) != len(tc.attached) {
				t.Errorf("kept %d + detached %d != %d attached — a link would be orphaned",
					1, len(got.stale), len(tc.attached))
			}
			// The survivor is never also in the detach list.
			if slices.Contains(got.stale, got.current) {
				t.Errorf("survivor %d is also marked stale", got.current)
			}
		})
	}
}

// A peer CNI sharing the veth programs its endpoint after CNI ADD returns, so
// the order we established at attach time is not the order that survives. These
// are the states the reconciler has to tell apart, and the rule is not
// symmetric: a VPC leg needs our terminal verdicts FIRST, the default network
// needs the peer's load-balancing and conntrack to see the packet first.
func TestTCXOrderOK(t *testing.T) {
	tests := []struct {
		name      string
		ours      int
		n         int
		wantFirst bool
		want      bool
	}{{
		// Nobody else is here. There is no "before" or "after" to be in.
		name: "alone on a VPC leg", ours: 0, n: 1, wantFirst: true, want: true,
	}, {
		name: "alone on the default network", ours: 0, n: 1, wantFirst: false, want: true,
	}, {
		name: "VPC leg, we run first", ours: 0, n: 2, wantFirst: true, want: true,
	}, {
		// The state that costs isolation: the peer sees the tenant address
		// before our verdict, and an overlapping address reads as a fabric one.
		name: "VPC leg, the peer got ahead of us", ours: 1, n: 2, wantFirst: true, want: false,
	}, {
		name: "default network, we run last", ours: 1, n: 2, wantFirst: false, want: true,
	}, {
		// Here being first is the defect: we would rewrite before the peer's
		// conntrack and service load-balancing ever saw the packet.
		name: "default network, we got ahead of the peer", ours: 0, n: 2, wantFirst: false, want: false,
	}, {
		name: "default network, stuck in the middle of three", ours: 1, n: 3, wantFirst: false, want: false,
	}, {
		name: "VPC leg, third of three", ours: 2, n: 3, wantFirst: true, want: false,
	}, {
		// Not attached. Not an ordering fault, but Cilium has been seen to leave
		// a stale pin behind while replacing a hook's list, and this loop is the
		// only one that revisits a live veth — so it must not call this fine.
		name: "not attached at all", ours: -1, n: 1, wantFirst: true, want: false,
	}, {
		name: "not attached, default network", ours: -1, n: 2, wantFirst: false, want: false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tcxOrderOK(tc.ours, tc.n, tc.wantFirst); got != tc.want {
				t.Errorf("tcxOrderOK(%d, %d, %v) = %v, want %v",
					tc.ours, tc.n, tc.wantFirst, got, tc.want)
			}
		})
	}
}

// Being alone must never ask for a repair, whichever end we would otherwise
// want: a reconciler that moved a lone link would detach and re-attach it every
// tick, opening an unclassified window each time for nothing.
func TestTCXOrderAloneNeverMoves(t *testing.T) {
	for _, wantFirst := range []bool{true, false} {
		if !tcxOrderOK(0, 1, wantFirst) {
			t.Errorf("a lone link with wantFirst=%v was judged out of order", wantFirst)
		}
	}
}

func TestPlanTCXEmpty(t *testing.T) {
	// No links of ours: the caller must take the fresh-attach path, so there is
	// no survivor to point at.
	got := planTCX(nil, 42)
	if got.current != -1 {
		t.Errorf("current = %d, want -1 (nothing to adopt)", got.current)
	}
	if len(got.stale) != 0 {
		t.Errorf("stale = %v, want empty", got.stale)
	}
}
