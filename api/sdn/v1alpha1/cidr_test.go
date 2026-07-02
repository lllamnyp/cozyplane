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

import "testing"

func TestCIDRsOverlap(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want bool
	}{
		{"disjoint", []string{"10.10.0.0/24"}, []string{"10.20.0.0/24"}, false},
		{"identical", []string{"10.10.0.0/24"}, []string{"10.10.0.0/24"}, true},
		{"a contains b", []string{"10.0.0.0/8"}, []string{"10.10.0.0/24"}, true},
		{"b contains a", []string{"10.10.0.0/24"}, []string{"10.0.0.0/8"}, true},
		{"partial lists overlap", []string{"10.10.0.0/24", "10.30.0.0/24"}, []string{"10.20.0.0/24", "10.30.0.0/25"}, true},
		{"empty never overlaps", nil, []string{"10.10.0.0/24"}, false},
		{"garbage ignored", []string{"not-a-cidr"}, []string{"10.10.0.0/24"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CIDRsOverlap(tc.a, tc.b); got != tc.want {
				t.Errorf("CIDRsOverlap(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
