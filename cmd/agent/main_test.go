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

// vpcTable returns a VPC lookup over "namespace/name" keys.
func vpcTable(m map[string]*sdnv1alpha1.VPC) func(namespace, name string) *sdnv1alpha1.VPC {
	return func(namespace, name string) *sdnv1alpha1.VPC {
		return m[namespace+"/"+name]
	}
}

func vpcWith(vni int32, cidrs ...string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		Spec:   sdnv1alpha1.VPCSpec{CIDRs: cidrs},
		Status: sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

func gatewayPort(name, ip, node, nodeIP string, gateway bool) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       sdnv1alpha1.PortSpec{IP: ip, Node: node, NodeIP: nodeIP, Gateway: gateway},
	}
}

// The gateways-map contract: one entry per VNI with a gateway Port, local
// (nil nodeIP) when the Port is on this node, remote otherwise; non-gateway
// Ports and unparsable names contribute nothing.
func TestDesiredGateways(t *testing.T) {
	ports := []*sdnv1alpha1.Port{
		gatewayPort("v101.10-70-0-1", "10.70.0.1", "self", "10.4.0.1", true),
		gatewayPort("v102.10-71-0-1", "10.71.0.1", "other", "10.4.0.2", true),
		gatewayPort("v101.10-70-0-2", "10.70.0.2", "other", "10.4.0.2", false), // tenant port: ignored
		gatewayPort("bogus", "10.72.0.1", "self", "10.4.0.1", true),            // unparsable name: ignored
	}
	got := desiredGateways(ports, "self")
	if len(got) != 2 {
		t.Fatalf("got %d gateways, want 2: %+v", len(got), got)
	}
	if gw := got[101]; gw.nodeIP != nil || gw.ip.String() != "10.70.0.1" {
		t.Errorf("vni 101 = %+v, want local 10.70.0.1", gw)
	}
	if gw := got[102]; gw.nodeIP == nil || gw.nodeIP.String() != "10.4.0.2" {
		t.Errorf("vni 102 = %+v, want remote via 10.4.0.2", gw)
	}
}

// desiredFloating programs only floating IPs whose target tenant IP is realized
// by a live Port on THIS node, carrying the target IP and the Port's VNI. A
// remote target, an unassigned address, or a target with no live Port here all
// contribute nothing.
func TestDesiredFloating(t *testing.T) {
	ports := []*sdnv1alpha1.Port{
		vpcPort("v101.10-0-0-5", "team-a", "vpc-a", "10.0.0.5", "self"),
		vpcPort("v101.10-0-0-6", "team-a", "vpc-a", "10.0.0.6", "other"),
	}
	fips := []*sdnv1alpha1.FloatingIP{
		floatingIPObj("team-a", "web", "vpc-a", "10.0.0.5", "203.0.113.7"),   // local target: programmed
		floatingIPObj("team-a", "api", "vpc-a", "10.0.0.6", "203.0.113.8"),   // target on another node: skipped
		floatingIPObj("team-a", "unset", "vpc-a", "10.0.0.5", ""),            // no address yet: skipped
		floatingIPObj("team-a", "nopod", "vpc-a", "10.0.0.9", "203.0.113.9"), // no live Port: skipped
	}
	got := desiredFloating(fips, ports, "self")
	if len(got) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(got), got)
	}
	if v, ok := got["203.0.113.7"]; !ok || v.vpcIP != "10.0.0.5" || v.vni != 101 {
		t.Errorf("203.0.113.7 = %+v (ok=%v), want {10.0.0.5 101}", v, ok)
	}
}

func vpcPort(name, ns, vpc, ip, node string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: ns, Name: vpc},
			IP:     ip,
			Node:   node,
		},
	}
}

func floatingIPObj(ns, name, vpc, target, address string) *sdnv1alpha1.FloatingIP {
	return &sdnv1alpha1.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.FloatingIPSpec{
			VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc},
			Target: target,
		},
		Status: sdnv1alpha1.FloatingIPStatus{Address: address},
	}
}

func TestVNIFromPortName(t *testing.T) {
	cases := []struct {
		name string
		vni  uint32
		ok   bool
	}{
		{"v101.10-70-0-1", 101, true},
		{"v1.10-244-0-5", 1, true},
		{"bogus", 0, false},
		{"v.10-70-0-1", 0, false},
		{"vx.10-70-0-1", 0, false},
		{"v0.10-70-0-1", 0, false},
	}
	for _, tc := range cases {
		vni, ok := vniFromPortName(tc.name)
		if vni != tc.vni || ok != tc.ok {
			t.Errorf("vniFromPortName(%q) = (%d,%v), want (%d,%v)", tc.name, vni, ok, tc.vni, tc.ok)
		}
	}
}

// The datapath contract: a pair is programmed iff both halves exist, mutually
// reference each other, both VPCs have VNIs, and their CIDRs are disjoint.
// Everything else stays out of the peers map.
func TestDesiredPeerPairs(t *testing.T) {
	vnis := vpcTable(map[string]*sdnv1alpha1.VPC{
		"team-a/vpc-a": vpcWith(100, "10.10.0.0/24"),
		"team-b/vpc-b": vpcWith(101, "10.20.0.0/24"),
		"team-c/vpc-c": vpcWith(102, "10.30.0.0/24"),
		// vpc-d overlaps vpc-a: the two may coexist, but never peer.
		"team-d/vpc-d": vpcWith(103, "10.10.0.0/16"),
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
		{
			name: "overlapping CIDRs never peer, even mutually matched",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-d", "vpc-a", "team-d", "vpc-d"),
				half("team-d", "to-a", "vpc-d", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			links := desiredPeerLinks(tc.peerings, vnis)
			got := map[[2]uint32]bool{}
			for _, l := range links {
				got[[2]uint32{l.a, l.b}] = true
			}
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

// A live peering also programs delivery entries (each side's CIDR resolves to
// the other from its own scope) — the datapath fact that makes peered pods
// findable under net-scoped delivery.
func TestDesiredPeerLinksCarryCIDRs(t *testing.T) {
	vnis := vpcTable(map[string]*sdnv1alpha1.VPC{
		"team-a/vpc-a": vpcWith(100, "10.10.0.0/24"),
		"team-b/vpc-b": vpcWith(101, "10.20.0.0/24"),
	})
	links := desiredPeerLinks([]*sdnv1alpha1.VPCPeering{
		half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
	}, vnis)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.a != 100 || l.b != 101 || l.cidrA != "10.10.0.0/24" || l.cidrB != "10.20.0.0/24" {
		t.Errorf("link = %+v, want {100 101 10.10.0.0/24 10.20.0.0/24}", l)
	}
}
