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
	"math"
	"net"
	"strings"
	"testing"
)

func TestInvalidIfindexRejectedBeforeMapAccess(t *testing.T) {
	for _, idx := range []int{-1, 0, math.MaxInt32 + 1} {
		for _, err := range []error{SetPortNet(idx, 100), DelPortNet(idx), SetLocal(100, net.ParseIP("10.0.0.2"), idx, nil)} {
			if err == nil || !strings.Contains(err.Error(), "invalid interface index") {
				t.Errorf("index %d reached map access: %v", idx, err)
			}
		}
		_, _, err := GetPortNet(idx)
		if err == nil || !strings.Contains(err.Error(), "invalid interface index") {
			t.Errorf("index %d reached get map: %v", idx, err)
		}
		_, subnet, _ := net.ParseCIDR("10.0.0.0/24")
		if _, err := extEgressVal(idx, subnet, nil); err == nil {
			t.Errorf("invalid external index %d accepted", idx)
		}
	}
}

func TestMalformedPolicyCIDRRejectedBeforeMapAccess(t *testing.T) {
	bad := &net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.IPMask{255, 0, 255, 0}}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("malformed CIDR reached map access: %v", r)
		}
	}()
	m := &Manager{}
	for _, err := range []error{m.SyncSGCidr([]SGCidr{{CIDR: bad}}), m.SyncSGEgressCidr([]SGEgressCidr{{CIDR: bad}}), m.SyncNPCidrs([]NPCidr{{CIDR: bad}}), m.SyncHFAllows([]HFAllow{{CIDR: bad}})} {
		if err == nil {
			t.Error("noncontiguous mask accepted")
		}
	}
}
