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

package main

import "testing"

func TestInvalidMembershipDoesNotBecomeLegacyAllowOrWorld(t *testing.T) {
	for _, ids := range [][]int32{{0}, {-1}, {63}, {64}, {65537}, {1, 63}, {1, 0}} {
		if got := securityGroupMembership(ids); got != 1 {
			t.Errorf("membership %v => %x, want pending bit0", ids, got)
		}
	}
	if got := securityGroupMembership(nil); got != 0 {
		t.Errorf("unselected membership %x", got)
	}
	if got := securityGroupMembership([]int32{1, 62}); got != (uint64(1)<<1)|(uint64(1)<<62) {
		t.Errorf("valid membership changed: %x", got)
	}
}
