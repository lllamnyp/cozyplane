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

import (
	"math"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestGatewayProjectionRejectsReservedVNI(t *testing.T) {
	for _, vni := range []int32{-1, 0, 99, 1 << 22, 1 << 23, math.MaxInt32} {
		vpcs := []*sdnv1alpha1.VPC{vpcObj("test", "vpc", vni)}
		gws := []*sdnv1alpha1.VPCGateway{gwObj("test", "gateway", "vpc", true, 0)}
		if got := desiredVPCIngress(gws, vpcs); len(got) != 0 {
			t.Fatalf("reserved VNI %d admitted: %v", vni, got)
		}
		gws[0].Status.NATAddress = "10.0.0.1"
		if got := desiredVPCNAT(gws, vpcs); len(got) != 0 {
			t.Fatalf("reserved VNI %d got NAT: %v", vni, got)
		}
	}
}

func TestPortClaimsAndBoundariesRejectReservedVNI(t *testing.T) {
	for _, vni := range []int32{-1, 1, 99, 1 << 22, 1 << 23, math.MaxInt32} {
		name := sdn.PortName(vni, "10.0.0.2")
		if got, ok := vniFromPortName(name); ok {
			t.Errorf("port %s admitted network %d", name, got)
		}
		vpc := vpcObj("test", "vpc", vni)
		if _, _, _, err := compileBoundaries([]*sdnv1alpha1.VPC{vpc}, nil); err == nil {
			t.Errorf("boundary admitted VNI %d", vni)
		}
	}
}
