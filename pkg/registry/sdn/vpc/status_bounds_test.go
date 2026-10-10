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

package vpc

import (
	"context"
	"math"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestStatusRejectsReservedVNI(t *testing.T) {
	s := NewStatusStrategy(NewStrategy(nil))
	for _, vni := range []int32{-1, 0, 99, 100, (1 << 22) - 1, 1 << 22, 1 << 23, math.MaxInt32} {
		obj := &sdn.VPC{Status: sdn.VPCStatus{VNI: vni}}
		valid := vni == 0 || (vni >= 100 && vni < 1<<22)
		if errs := s.ValidateUpdate(context.Background(), obj, obj.DeepCopy()); (len(errs) == 0) != valid {
			t.Fatalf("VNI %d errors %v valid %v", vni, errs, valid)
		}
	}
}
