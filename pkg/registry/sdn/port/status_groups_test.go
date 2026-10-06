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

package port

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestStatusGroupsCannotBecomeWorld(t *testing.T) {
	s := NewStatusStrategy(NewStrategy(nil))
	for _, tc := range []struct {
		groups []int32
		valid  bool
	}{{nil, true}, {[]int32{0}, true}, {[]int32{1, 62}, true}, {[]int32{0, 1}, false}, {[]int32{-1}, false}, {[]int32{63}, false}, {[]int32{64}, false}, {[]int32{65537}, false}} {
		port := &sdn.Port{Status: sdn.PortStatus{Groups: tc.groups}}
		if errs := s.ValidateUpdate(context.Background(), port, port.DeepCopy()); (len(errs) == 0) != tc.valid {
			t.Errorf("groups %v errors %v valid %v", tc.groups, errs, tc.valid)
		}
	}
}
