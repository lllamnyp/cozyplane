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
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func half(ns, name, localVPC, peerNS, peerVPC string) *sdnv1alpha1.VPCPeering {
	return &sdnv1alpha1.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.VPCPeeringSpec{
			VPCRef:  sdnv1alpha1.LocalVPCRef{Name: localVPC},
			PeerRef: sdnv1alpha1.VPCRef{Namespace: peerNS, Name: peerVPC},
		},
	}
}

// vniTable returns a vni lookup over "namespace/name" keys.
func vniTable(m map[string]uint32) func(namespace, name string) (uint32, bool) {
	return func(namespace, name string) (uint32, bool) {
		v, ok := m[namespace+"/"+name]
		return v, ok
	}
}

// The datapath contract: a pair is programmed iff both halves exist, mutually
// reference each other, and both VPCs have VNIs. Everything else stays out of
// the peers map.
func TestDesiredPeerPairs(t *testing.T) {
	vnis := vniTable(map[string]uint32{
		"team-a/vpc-a": 100,
		"team-b/vpc-b": 101,
		"team-c/vpc-c": 102,
	})

	cases := []struct {
		name     string
		peerings []*sdnv1alpha1.VPCPeering
		want     map[[2]uint32]bool
	}{
		{
			name: "mutual match programs one normalized pair",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"), // higher VNI listed first
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
			},
			want: map[[2]uint32]bool{{100, 101}: true},
		},
		{
			name: "a lone half programs nothing (pending request)",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "non-reciprocal references do not match",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
				// team-b consents to vpc-c, not vpc-a.
				half("team-b", "to-c", "vpc-b", "team-c", "vpc-c"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "missing VNI keeps the pair unprogrammed",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-x", "vpc-a", "team-x", "vpc-x"), // vpc-x has no VNI
				half("team-x", "to-a", "vpc-x", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "duplicate grants collapse to one pair",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b-1", "vpc-a", "team-b", "vpc-b"),
				half("team-a", "to-b-2", "vpc-a", "team-b", "vpc-b"),
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{{100, 101}: true},
		},
		{
			name: "independent peerings program independent pairs",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
				half("team-b", "to-c", "vpc-b", "team-c", "vpc-c"),
				half("team-c", "to-b", "vpc-c", "team-b", "vpc-b"),
			},
			// Pairwise, non-transitive: a<->b and b<->c, never a<->c.
			want: map[[2]uint32]bool{{100, 101}: true, {101, 102}: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := desiredPeerPairs(tc.peerings, vnis)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for pair := range tc.want {
				if !got[pair] {
					t.Errorf("missing pair %v (got %v)", pair, got)
				}
			}
		})
	}
}
