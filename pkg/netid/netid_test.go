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

package netid

import (
	"math"
	"testing"
)

func TestIdentifiersCannotSetReservedFlags(t *testing.T) {
	for _, v := range []int32{-1, 0, 99, 100, LastVNI, 1 << 22, 1 << 23, math.MaxInt32} {
		valid := v >= 100 && v <= (1<<22)-1
		if ValidVNI(v) != valid || (VNI(v) != 0) != valid {
			t.Fatalf("VNI %d validated %v converted %d", v, ValidVNI(v), VNI(v))
		}
		if valid && int32(VNI(v)) != v {
			t.Fatal("VNI changed")
		}
	}
	for _, v := range []int32{-1, 0, 1, 62, 63, 64, 65537, math.MaxInt32} {
		valid := v >= 1 && v <= 62
		if ValidGroup(v) != valid || (Group(v) != 0) != valid {
			t.Fatalf("group %d validated %v converted %d", v, ValidGroup(v), Group(v))
		}
		if valid && int32(Group(v)) != v {
			t.Fatal("group changed")
		}
	}
}
