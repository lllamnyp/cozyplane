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

package securitygroup

import (
	"context"
	"math"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestStatusRejectsWorldAndInvalidIDs(t *testing.T) {
	s := NewStatusStrategy(NewStrategy(nil, nil))
	for _, id := range []int32{-1, 0, 1, 62, 63, 64, 65537, math.MaxInt32} {
		obj := &sdn.SecurityGroup{Status: sdn.SecurityGroupStatus{ID: id}}
		valid := id >= 0 && id <= 62
		if errs := s.ValidateUpdate(context.Background(), obj, obj.DeepCopy()); (len(errs) == 0) != valid {
			t.Fatalf("ID %d errors %v valid %v", id, errs, valid)
		}
	}
}
