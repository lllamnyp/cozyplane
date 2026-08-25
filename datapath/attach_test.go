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
