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
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func TestNodeCIDRFor(t *testing.T) {
	const (
		v4 = "10.244.1.0/24"
		v6 = "fd00:10:244:1::/64"
	)
	tests := []struct {
		name    string
		cidrs   []string
		single  string
		wantV6  bool
		expect  string
		wantErr bool
	}{
		{name: "v4 vpc, dual-stack node", cidrs: []string{v4, v6}, wantV6: false, expect: v4},
		{name: "v6 vpc, dual-stack node", cidrs: []string{v4, v6}, wantV6: true, expect: v6},
		{name: "v4 vpc, v4-only node", cidrs: []string{v4}, wantV6: false, expect: v4},
		// The decoupling: a v6 VPC on a v4-only node falls back to the v4 fabric
		// CIDR instead of erroring — east-west VPC traffic keys on the VPC IP.
		{name: "v6 vpc, v4-only node falls back", cidrs: []string{v4}, wantV6: true, expect: v4},
		{name: "v4 vpc, v6-only node falls back", cidrs: []string{v6}, wantV6: false, expect: v6},
		{name: "single PodCIDR fallback field", single: v4, wantV6: true, expect: v4},
		{name: "no CIDRs at all errors", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &datapath.AgentState{PodCIDR: tc.single, PodCIDRs: tc.cidrs}
			got, err := nodeCIDRFor(state, tc.wantV6)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expect {
				t.Fatalf("got %q, want %q", got, tc.expect)
			}
		})
	}
}

// These tests use sdnfake.NewSimpleClientset (not the newer NewClientset): the
// server-side-apply-aware fake needs an OpenAPI schema for typed conversion that
// isn't wired for our generated types, so Create fails there. The simple tracker
// is the right fit for exercising plugin logic.

func TestParseVPCRef(t *testing.T) {
	cases := []struct {
		anno, podNS  string
		wantNS, want string
	}{
		// bare name: owner namespace defaults to the pod's namespace.
		{"tenant-a", "team-a", "team-a", "tenant-a"},
		// explicit owner namespace.
		{"shared/db", "team-a", "shared", "db"},
		// the pod's namespace is irrelevant once an owner is named.
		{"shared/db", "team-b", "shared", "db"},
		// only the first slash splits; the rest is the (unusual) name.
		{"a/b/c", "ns", "a", "b/c"},
	}
	for _, c := range cases {
		gotNS, got := parseVPCRef(c.anno, c.podNS)
		if gotNS != c.wantNS || got != c.want {
			t.Errorf("parseVPCRef(%q,%q) = (%q,%q), want (%q,%q)",
				c.anno, c.podNS, gotNS, got, c.wantNS, c.want)
		}
	}
}

func TestPortName(t *testing.T) {
	// Names are keyed by the globally-unique VNI so they stay unique across
	// namespaces; the IP's separators (v4 dots, v6 colons) become dashes so the
	// name is a valid DNS-1123 object name.
	if got := portName(100, "10.10.0.2"); got != "v100.10-10-0-2" {
		t.Fatalf("portName = %q, want v100.10-10-0-2", got)
	}
	if got := portName(100, "fd00:a::2"); got != "v100.fd00-a--2" {
		t.Fatalf("portName v6 = %q, want v100.fd00-a--2", got)
	}
}

func TestNextIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.2"},
		{"10.0.0.255", "10.0.1.0"},
		{"10.0.255.255", "10.1.0.0"},
		// v6 must increment in the full 16-byte width, not collapse to an empty
		// address (the To4()-first bug: cloneIP(nil) is length-0, not nil).
		{"fd00:a::1", "fd00:a::2"},
		{"fd00:a::ffff", "fd00:a::1:0"},
		{"2001:db8::", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := nextIP(net.ParseIP(c.in)).String(); got != c.want {
			t.Errorf("nextIP(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func newVPC(ns, name string, vni int32, cidr string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{cidr}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

func TestClaimIP_FirstAddressAndPortShape(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.5", "team-a", "app-1", "uid-1", "")
	if err != nil {
		t.Fatalf("claimIP: %v", err)
	}
	// The first allocatable address is network+2 (.0 network, .1 reserved gw).
	if ip.String() != "10.10.0.2" {
		t.Fatalf("first IP = %s, want 10.10.0.2", ip)
	}
	if port.Name != "v100.10-10-0-2" {
		t.Errorf("port name = %q, want v100.10-10-0-2", port.Name)
	}
	if port.Spec.IP != "10.10.0.2" || port.Spec.FabricIP != "10.244.0.5" {
		t.Errorf("port spec ip/fabric = %q/%q", port.Spec.IP, port.Spec.FabricIP)
	}
	if port.Spec.VPCRef != (sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "tenant-a"}) {
		t.Errorf("port vpcRef = %+v", port.Spec.VPCRef)
	}
	if port.Spec.Node != "node1" || port.Spec.NodeIP != "192.0.2.1" {
		t.Errorf("port node/nodeIP = %q/%q", port.Spec.Node, port.Spec.NodeIP)
	}
	for k, want := range map[string]string{
		sdnv1alpha1.LabelVPCNamespace: "team-a",
		sdnv1alpha1.LabelVPC:          "tenant-a",
		sdnv1alpha1.LabelPodNamespace: "team-a",
		sdnv1alpha1.LabelPodName:      "app-1",
		sdnv1alpha1.LabelPodUID:       "uid-1",
	} {
		if port.Labels[k] != want {
			t.Errorf("label %q = %q, want %q", k, port.Labels[k], want)
		}
	}
	// The sever finalizer is what makes revocation replayable: deletion waits
	// for the node agent's acknowledgement.
	if len(port.Finalizers) != 1 || port.Finalizers[0] != sdnv1alpha1.FinalizerSever {
		t.Errorf("finalizers = %v, want [%s]", port.Finalizers, sdnv1alpha1.FinalizerSever)
	}
}

func TestClaimIP_IPv6(t *testing.T) {
	// A v6 VPC CIDR must allocate natively: network+2 in the full 16-byte width,
	// a v6-safe Port name, and the v6 address (not a truncated/empty one) in spec.
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant6", 200, "fd00:a::/64")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.5", "team-a", "app6", "uid-6", "")
	if err != nil {
		t.Fatalf("claimIP v6: %v", err)
	}
	if ip.String() != "fd00:a::2" {
		t.Fatalf("first v6 IP = %s, want fd00:a::2", ip)
	}
	if port.Name != "v200.fd00-a--2" {
		t.Errorf("port name = %q, want v200.fd00-a--2", port.Name)
	}
	// The fabric IP stays v4 (from the node pod CIDR underlay) even for a v6 pod.
	if port.Spec.IP != "fd00:a::2" || port.Spec.FabricIP != "10.244.0.5" {
		t.Errorf("port spec ip/fabric = %q/%q", port.Spec.IP, port.Spec.FabricIP)
	}
}

func TestClaimIP_SkipsUsedAddresses(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.5", "team-a", "app-1", "uid-1", ""); err != nil {
		t.Fatalf("first attachPort: %v", err)
	}
	ip, _, _, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.6", "team-a", "app-2", "uid-2", "")
	if err != nil {
		t.Fatalf("second attachPort: %v", err)
	}
	if ip.String() != "10.10.0.3" {
		t.Fatalf("second IP = %s, want 10.10.0.3 (skipping the claimed .2)", ip)
	}
}

func TestClaimIP_RetriesOnNameCollision(t *testing.T) {
	// A Port already holds the name the first candidate (.2) would take, but
	// without the VPC labels and IP — i.e. a concurrent claimant that won the
	// name. attachPort must collide on AlreadyExists and advance to .3.
	collide := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-10-0-2"}}
	client := sdnfake.NewSimpleClientset(collide)
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.5", "team-a", "app-1", "uid-1", "")
	if err != nil {
		t.Fatalf("claimIP: %v", err)
	}
	if ip.String() != "10.10.0.3" || port.Name != "v100.10-10-0-3" {
		t.Fatalf("after collision got %s / %q, want 10.10.0.3 / v100.10-10-0-3", ip, port.Name)
	}
}

func TestClaimIP_ExhaustionErrors(t *testing.T) {
	// /30 has only .2 allocatable after reserving .0/.1; pre-claim it and .3.
	mk := func(name, ip string) *sdnv1alpha1.Port {
		return &sdnv1alpha1.Port{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				sdnv1alpha1.LabelVPCNamespace: "team-a",
				sdnv1alpha1.LabelVPC:          "tenant-a",
			}},
			Spec: sdnv1alpha1.PortSpec{IP: ip},
		}
	}
	client := sdnfake.NewSimpleClientset(mk("v200.10-0-0-2", "10.0.0.2"), mk("v200.10-0-0-3", "10.0.0.3"))
	vpc := newVPC("team-a", "tenant-a", 200, "10.0.0.0/30")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(client, vpc, "team-a", state, "10.244.0.5", "team-a", "app-1", "uid-1", ""); err == nil {
		t.Fatal("attachPort on exhausted VPC = nil error, want exhaustion error")
	}
}

func TestRequireVPCBinding(t *testing.T) {
	binding := func(ns, vpcNS, vpcName string) *sdnv1alpha1.VPCBinding {
		return &sdnv1alpha1.VPCBinding{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName, Namespace: ns},
			Spec:       sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName}},
		}
	}

	cases := []struct {
		name              string
		objs              []*sdnv1alpha1.VPCBinding
		podNS, vNS, vName string
		wantAllow         bool
	}{
		{"no binding is denied", nil, "team-a", "team-a", "tenant-a", false},
		{"matching binding allows", []*sdnv1alpha1.VPCBinding{binding("team-a", "team-a", "tenant-a")}, "team-a", "team-a", "tenant-a", true},
		{"same-namespace still needs a binding", nil, "team-a", "team-a", "tenant-a", false},
		{"different VPC name is denied", []*sdnv1alpha1.VPCBinding{binding("team-a", "team-a", "other")}, "team-a", "team-a", "tenant-a", false},
		{"different owner namespace is denied", []*sdnv1alpha1.VPCBinding{binding("team-a", "shared", "tenant-a")}, "team-a", "team-a", "tenant-a", false},
		{"binding in another namespace does not count", []*sdnv1alpha1.VPCBinding{binding("team-b", "team-a", "tenant-a")}, "team-a", "team-a", "tenant-a", false},
		{"cross-namespace grant allows", []*sdnv1alpha1.VPCBinding{binding("team-a", "shared", "db")}, "team-a", "shared", "db", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := make([]runtime.Object, 0, len(c.objs))
			for _, o := range c.objs {
				objs = append(objs, o)
			}
			client := sdnfake.NewSimpleClientset(objs...)
			err := requireVPCBinding(client, c.podNS, c.vNS, c.vName)
			if c.wantAllow && err != nil {
				t.Fatalf("want allowed, got error: %v", err)
			}
			if !c.wantAllow && err == nil {
				t.Fatal("want denied, got nil error")
			}
		})
	}
}
