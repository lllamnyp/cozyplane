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
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
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

// desiredFloating programs every floating IP whose target has a live Port
// ANYWHERE in the cluster — not just here (docs/floating-ha.md). The announcer
// must be able to resolve an address whose pod is on another node in order to
// forward to it, so the mapping is cluster-wide; what is node-specific is the
// announcement, not the mapping. An unassigned address, or a target with no live
// Port at all, still contributes nothing.
func TestDesiredFloating(t *testing.T) {
	ports := []*sdnv1alpha1.Port{
		vpcPort("v101.10-0-0-5", "team-a", "vpc-a", "10.0.0.5", "self"),
		vpcPort("v101.10-0-0-6", "team-a", "vpc-a", "10.0.0.6", "other"),
	}
	fips := []*sdnv1alpha1.FloatingIP{
		floatingIPObj("team-a", "web", "vpc-a", "10.0.0.5", "203.0.113.7"),   // target here
		floatingIPObj("team-a", "api", "vpc-a", "10.0.0.6", "203.0.113.8"),   // target elsewhere: still programmed
		floatingIPObj("team-a", "unset", "vpc-a", "10.0.0.5", ""),            // no address yet: skipped
		floatingIPObj("team-a", "nopod", "vpc-a", "10.0.0.9", "203.0.113.9"), // no live Port: skipped
	}
	got := desiredFloating(fips, ports)
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if v, ok := got["203.0.113.7"]; !ok || v.vpcIP != "10.0.0.5" || v.vni != 101 || v.node != "self" {
		t.Errorf("203.0.113.7 = %+v (ok=%v), want {10.0.0.5 101 self}", v, ok)
	}
	// The decisive one: a target on another node is programmed here too, and
	// carries that node — from_uplink needs it to forward over the overlay.
	if v, ok := got["203.0.113.8"]; !ok || v.vpcIP != "10.0.0.6" || v.node != "other" {
		t.Errorf("203.0.113.8 = %+v (ok=%v), want {10.0.0.6 101 other}", v, ok)
	}
}

func readyNode(name string, pools string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name, Annotations: map[string]string{poolsAnnotation: pools}},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		},
	}
}

func pool(name string, cidrs ...string) *sdnv1alpha1.ExternalPool {
	return &sdnv1alpha1.ExternalPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       sdnv1alpha1.ExternalPoolSpec{CIDRs: cidrs},
	}
}

// The election's core promise: the announcer is chosen from the nodes that can
// SERVE the pool, independently of where the target pod runs. (Every agent agrees
// structurally — announcerFor takes no "self", so agreement is not something the
// nodes could disagree about.)
func TestAnnouncerFor(t *testing.T) {
	idx := newNodePoolIndex()
	idx.set(readyNode("node0", "public"))
	idx.set(readyNode("node1", "public"))
	idx.set(readyNode("node2", "public"))
	pools := []*sdnv1alpha1.ExternalPool{pool("public", "203.0.113.0/24")}
	v := floatingView{vpcIP: "10.0.0.5", vni: 101, node: "node2"}

	if got := announcerFor("203.0.113.7", v, idx, pools, true); got != "node0" && got != "node1" && got != "node2" {
		t.Fatalf("elected a node that does not exist: %q", got)
	}

	// A node that cannot serve the pool must never win, however the hash falls:
	// attracting an address to a node with no path to that L2 is a black hole.
	only := newNodePoolIndex()
	only.set(readyNode("node0", "public"))
	only.set(readyNode("node1", "")) // no servable pools
	for _, addr := range []string{"203.0.113.7", "203.0.113.8", "203.0.113.9", "203.0.113.10"} {
		if got := announcerFor(addr, v, only, pools, true); got != "node0" {
			t.Errorf("%s elected %q, want node0 (the only node serving the pool)", addr, got)
		}
	}

	// NotReady is the same as gone.
	down := newNodePoolIndex()
	down.set(readyNode("node0", "public"))
	notReady := readyNode("node1", "public")
	notReady.Status.Conditions[0].Status = corev1.ConditionFalse
	down.set(notReady)
	if got := announcerFor("203.0.113.7", v, down, pools, true); got != "node0" {
		t.Errorf("elected %q, want node0 (node1 is NotReady)", got)
	}

	// No eligible node (a routed pool, say) falls back to the target's own node —
	// the pre-HA behaviour. So does --floating-ha=false.
	empty := newNodePoolIndex()
	if got := announcerFor("203.0.113.7", v, empty, pools, true); got != "node2" {
		t.Errorf("elected %q, want the target's node (node2) when nothing is eligible", got)
	}
	if got := announcerFor("203.0.113.7", v, idx, pools, false); got != "node2" {
		t.Errorf("elected %q, want the target's node (node2) with HA off", got)
	}
}

// Rendezvous hashing spreads addresses across announcers, and — the property that
// matters — re-homes only the lost node's addresses when a node goes away, rather
// than reshuffling the fleet the way a modulo would.
func TestAnnouncerStability(t *testing.T) {
	pools := []*sdnv1alpha1.ExternalPool{pool("public", "203.0.113.0/24")}
	v := floatingView{vpcIP: "10.0.0.5", vni: 101, node: "node0"}
	all := newNodePoolIndex()
	for _, n := range []string{"node0", "node1", "node2"} {
		all.set(readyNode(n, "public"))
	}
	fewer := newNodePoolIndex()
	for _, n := range []string{"node0", "node1"} {
		fewer.set(readyNode(n, "public"))
	}

	var addrs []string
	for i := 1; i < 60; i++ {
		addrs = append(addrs, fmt.Sprintf("203.0.113.%d", i))
	}
	before := map[string]string{}
	spread := map[string]int{}
	for _, a := range addrs {
		before[a] = announcerFor(a, v, all, pools, true)
		spread[before[a]]++
	}
	if len(spread) < 3 {
		t.Errorf("addresses landed on %d nodes, want all 3 used: %v", len(spread), spread)
	}
	// Drop node2: every address it did NOT hold must stay exactly where it was.
	for _, a := range addrs {
		after := announcerFor(a, v, fewer, pools, true)
		if before[a] != "node2" && after != before[a] {
			t.Errorf("%s moved from %s to %s when an unrelated node left", a, before[a], after)
		}
		if after == "node2" {
			t.Errorf("%s still elected the departed node2", a)
		}
	}
}

func TestPoolOf(t *testing.T) {
	pools := []*sdnv1alpha1.ExternalPool{
		pool("public", "203.0.113.0/24"),
		pool("other", "198.51.100.0/24", "2001:db8::/64"),
	}
	for addr, want := range map[string]string{
		"203.0.113.7":  "public",
		"198.51.100.1": "other",
		"2001:db8::1":  "other",
		"192.0.2.1":    "", // in no pool
		"not-an-ip":    "",
	} {
		if got := poolOf(addr, pools); got != want {
			t.Errorf("poolOf(%s) = %q, want %q", addr, got, want)
		}
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
