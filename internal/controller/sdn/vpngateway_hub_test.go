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

package sdn

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// TestVPNAttachmentAnnotations covers the hub attachment contract
// (docs/vpn.md §3.3): a single-VPC gateway keeps the legacy AnnotationVPC, a
// hub switches wholesale to AnnotationNetworks (primary first), and the two
// annotations are never both set.
func TestVPNAttachmentAnnotations(t *testing.T) {
	t.Run("single VPC uses AnnotationVPC", func(t *testing.T) {
		gw := &sdnv1alpha1.VPNGateway{}
		gw.Spec.VPCRef.Name = "vpc-a"

		got := vpnAttachmentAnnotations(gw)
		if len(got) != 1 || got[sdnv1alpha1.AnnotationVPC] != "vpc-a" {
			t.Fatalf("annotations = %#v, want exactly {AnnotationVPC: vpc-a}", got)
		}
	})

	t.Run("hub uses AnnotationNetworks in ref order", func(t *testing.T) {
		gw := &sdnv1alpha1.VPNGateway{}
		gw.Spec.VPCRef.Name = "vpc-a"
		gw.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}, {Name: "vpc-c"}}

		got := vpnAttachmentAnnotations(gw)
		if len(got) != 1 {
			t.Fatalf("annotations = %#v, want exactly one entry", got)
		}
		if _, ok := got[sdnv1alpha1.AnnotationVPC]; ok {
			t.Fatalf("AnnotationVPC must not be set alongside AnnotationNetworks: %#v", got)
		}
		raw, ok := got[sdnv1alpha1.AnnotationNetworks]
		if !ok {
			t.Fatalf("annotations = %#v, want AnnotationNetworks set", got)
		}
		var entries []struct {
			VPC string `json:"vpc"`
		}
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			t.Fatalf("AnnotationNetworks did not decode: %v (%s)", err, raw)
		}
		want := []string{"vpc-a", "vpc-b", "vpc-c"}
		if len(entries) != len(want) {
			t.Fatalf("entries = %+v, want %v", entries, want)
		}
		for i, name := range want {
			if entries[i].VPC != name {
				t.Fatalf("entries[%d] = %q, want %q (primary-first order matters)", i, entries[i].VPC, name)
			}
		}
	})

	t.Run("deployment pod template follows the same rule and keeps the checksum", func(t *testing.T) {
		r := &VPNGatewayReconciler{Config: VPNGatewayConfig{Image: "example.invalid/cozyplane:test"}}

		single := &sdnv1alpha1.VPNGateway{}
		single.Name, single.Namespace = "gateway", "tenant"
		single.Spec.VPCRef.Name = "vpc-a"
		dep := r.deployment(single, backendWireGuard, "checksum")
		ann := dep.Spec.Template.ObjectMeta.Annotations
		if ann[sdnv1alpha1.AnnotationVPC] != "vpc-a" {
			t.Fatalf("single-VPC pod annotations = %#v, want AnnotationVPC=vpc-a", ann)
		}
		if ann[vpnConfigChecksumAnnotation] != "checksum" {
			t.Fatalf("single-VPC pod annotations missing checksum: %#v", ann)
		}

		hub := &sdnv1alpha1.VPNGateway{}
		hub.Name, hub.Namespace = "gateway", "tenant"
		hub.Spec.VPCRef.Name = "vpc-a"
		hub.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}}
		dep = r.deployment(hub, backendWireGuard, "checksum")
		ann = dep.Spec.Template.ObjectMeta.Annotations
		if _, ok := ann[sdnv1alpha1.AnnotationVPC]; ok {
			t.Fatalf("hub pod annotations must not carry AnnotationVPC: %#v", ann)
		}
		if ann[sdnv1alpha1.AnnotationNetworks] == "" {
			t.Fatalf("hub pod annotations missing AnnotationNetworks: %#v", ann)
		}
		if ann[vpnConfigChecksumAnnotation] != "checksum" {
			t.Fatalf("hub pod annotations missing checksum: %#v", ann)
		}
	})
}

// TestVPNBindingName covers the forwarding-grant binding naming rule: the
// primary VPC keeps the historical `<gw>-vpn` name so existing gateways are
// untouched, an additional VPC gets `<gw>-vpn-<vpc>`, and a name that would
// exceed the 63-character object-name limit is hashed down deterministically.
func TestVPNBindingName(t *testing.T) {
	if got := vpnBindingName("gateway", "vpc", true); got != "gateway-vpn" {
		t.Fatalf("primary = %q, want gateway-vpn", got)
	}
	if got := vpnBindingName("gateway", "vpc-b", false); got != "gateway-vpn-vpc-b" {
		t.Fatalf("additional short = %q, want gateway-vpn-vpc-b", got)
	}

	longGateway := strings.Repeat("g", 40)
	longVPC := strings.Repeat("v", 40)
	otherVPC := strings.Repeat("w", 40)

	name := vpnBindingName(longGateway, longVPC, false)
	if len(name) > 63 {
		t.Fatalf("long name len = %d, want <= 63 (%q)", len(name), name)
	}
	if again := vpnBindingName(longGateway, longVPC, false); again != name {
		t.Fatalf("vpnBindingName is not deterministic: %q != %q", again, name)
	}
	if other := vpnBindingName(longGateway, otherVPC, false); other == name {
		t.Fatalf("different VPC produced the same binding name %q", name)
	}
}

// TestForbiddenRemoteCIDRServedVPC covers the hub constraint (docs/vpn.md
// §3.3): a remote CIDR overlapping a served VPC's own prefix is refused,
// whichever side contains the other, and a malformed CIDR is refused outright.
func TestForbiddenRemoteCIDRServedVPC(t *testing.T) {
	r := &VPNGatewayReconciler{}
	servedCIDRs := mustParseCIDRs("10.250.0.0/24")

	tests := []struct {
		name string
		cidr string
		want string
	}{
		{"exact match", "10.250.0.0/24", "served VPC"},
		{"narrower subset", "10.250.0.128/25", "served VPC"},
		{"englobing supernet", "10.0.0.0/8", "served VPC"},
		{"disjoint", "10.251.0.0/24", ""},
		{"malformed", "not-a-cidr", "not a CIDR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.forbiddenRemoteCIDR(tt.cidr, servedCIDRs); got != tt.want {
				t.Fatalf("forbiddenRemoteCIDR(%q) = %q, want %q", tt.cidr, got, tt.want)
			}
		})
	}
}

// TestServedVPCCIDRs covers the hub constraint's disjointness check: served
// VPCs' own CIDRs must be pairwise disjoint, a single VPC's own v4/v6 CIDRs
// never "overlap" each other, and a malformed VPC CIDR is skipped rather than
// treated as an overlap.
func TestServedVPCCIDRs(t *testing.T) {
	t.Run("disjoint VPCs", func(t *testing.T) {
		vpcs := []*sdnv1alpha1.VPC{
			vpcWithCIDRs("tenant", "vpc-a", 100, "10.10.0.0/24"),
			vpcWithCIDRs("tenant", "vpc-b", 101, "10.20.0.0/24"),
		}
		cidrs, overlap := servedVPCCIDRs(vpcs)
		if overlap != "" {
			t.Fatalf("overlap = %q, want none", overlap)
		}
		if len(cidrs) != 2 {
			t.Fatalf("cidrs = %v, want 2 entries", cidrs)
		}
	})

	t.Run("overlapping VPCs are reported by name", func(t *testing.T) {
		vpcs := []*sdnv1alpha1.VPC{
			vpcWithCIDRs("tenant", "vpc-a", 100, "10.250.0.0/24"),
			vpcWithCIDRs("tenant", "vpc-b", 101, "10.250.0.0/16"),
		}
		_, overlap := servedVPCCIDRs(vpcs)
		if !strings.Contains(overlap, "vpc-a") || !strings.Contains(overlap, "vpc-b") {
			t.Fatalf("overlap = %q, want it to name both vpc-a and vpc-b", overlap)
		}
	})

	t.Run("one VPC with v4 and v6 CIDRs", func(t *testing.T) {
		vpcs := []*sdnv1alpha1.VPC{
			vpcWithCIDRs("tenant", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"),
		}
		cidrs, overlap := servedVPCCIDRs(vpcs)
		if overlap != "" {
			t.Fatalf("overlap = %q, want none", overlap)
		}
		if len(cidrs) != 2 {
			t.Fatalf("cidrs = %v, want 2 entries", cidrs)
		}
	})

	t.Run("malformed CIDR is skipped, not reported as an overlap", func(t *testing.T) {
		vpcs := []*sdnv1alpha1.VPC{
			vpcWithCIDRs("tenant", "vpc-a", 100, "not-a-cidr", "10.10.0.0/24"),
		}
		cidrs, overlap := servedVPCCIDRs(vpcs)
		if overlap != "" {
			t.Fatalf("overlap = %q, want none", overlap)
		}
		if len(cidrs) != 1 {
			t.Fatalf("cidrs = %v, want exactly the well-formed entry", cidrs)
		}
	})
}

// TestUnionVPCCIDRsAndRoutingConfig covers what an active-active hub
// advertises over BGP: unionVPCCIDRs dedups and sorts every served VPC's
// prefixes, routingConfigFor carries that union as AdvertiseCIDRs only in
// active-active mode, and is nil otherwise.
func TestUnionVPCCIDRsAndRoutingConfig(t *testing.T) {
	vpcs := []*sdnv1alpha1.VPC{
		vpcWithCIDRs("tenant", "vpc-b", 101, "10.20.0.0/24", "10.10.0.0/24"),
		vpcWithCIDRs("tenant", "vpc-a", 100, "10.10.0.0/24", "10.5.0.0/24"),
	}

	union := unionVPCCIDRs(vpcs)
	want := []string{"10.10.0.0/24", "10.20.0.0/24", "10.5.0.0/24"} // deduped, lexicographically sorted
	if len(union) != len(want) {
		t.Fatalf("unionVPCCIDRs = %v, want %v", union, want)
	}
	for i, cidr := range want {
		if union[i] != cidr {
			t.Fatalf("unionVPCCIDRs = %v, want %v", union, want)
		}
	}

	gwHA := &sdnv1alpha1.VPNGateway{}
	gwHA.Name, gwHA.Namespace = "gateway", "tenant"
	gwHA.Spec.VPCRef.Name = "vpc-a"
	gwHA.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{}
	gwHA.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeActiveActive, ActiveActive: &sdnv1alpha1.VPNGatewayActiveActive{
		LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"10.250.0.1"}, BFD: true,
	}}
	cfg := routingConfigFor(gwHA, vpcs)
	if cfg == nil {
		t.Fatal("routingConfigFor = nil, want a config for active-active HA")
	}
	if len(cfg.AdvertiseCIDRs) != len(union) {
		t.Fatalf("AdvertiseCIDRs = %v, want the same union %v", cfg.AdvertiseCIDRs, union)
	}
	for i, cidr := range union {
		if cfg.AdvertiseCIDRs[i] != cidr {
			t.Fatalf("AdvertiseCIDRs = %v, want the same union %v", cfg.AdvertiseCIDRs, union)
		}
	}

	gwPlain := &sdnv1alpha1.VPNGateway{}
	gwPlain.Name, gwPlain.Namespace = "gateway", "tenant"
	gwPlain.Spec.VPCRef.Name = "vpc-a"
	gwPlain.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{}
	if cfg := routingConfigFor(gwPlain, vpcs); cfg != nil {
		t.Fatalf("routingConfigFor = %+v, want nil without active-active HA", cfg)
	}
}

// TestConnectionRoutes covers route rendering toward one served VPC's leg
// Port(s): only connections with remote CIDRs produce a route, and the
// rendered CIDRs/Ports never alias the caller's slices.
func TestConnectionRoutes(t *testing.T) {
	conns := []sdnv1alpha1.VPNConnection{
		{ObjectMeta: metav1.ObjectMeta{Name: "site-a"}, Spec: sdnv1alpha1.VPNConnectionSpec{
			RemoteCIDRs: []string{"10.251.0.0/24", "10.252.0.0/24"},
		}},
		{ObjectMeta: metav1.ObjectMeta{Name: "site-b"}}, // no RemoteCIDRs: contributes no route
	}
	ports := []string{"p0", "p1"}

	routes := connectionRoutes(conns, ports)
	if len(routes) != 1 {
		t.Fatalf("routes = %+v, want exactly one route", routes)
	}
	route := routes[0]
	if len(route.CIDRs) != 2 || route.CIDRs[0] != "10.251.0.0/24" || route.CIDRs[1] != "10.252.0.0/24" {
		t.Fatalf("route.CIDRs = %v, want a copy of site-a's remote CIDRs", route.CIDRs)
	}
	if route.Port != "p0" {
		t.Fatalf("route.Port = %q, want p0", route.Port)
	}
	if len(route.Ports) != 2 || route.Ports[0] != "p0" || route.Ports[1] != "p1" {
		t.Fatalf("route.Ports = %v, want [p0 p1]", route.Ports)
	}

	// The returned slices must be independent copies: mutating the inputs
	// afterward must not reach back into the already-rendered route.
	conns[0].Spec.RemoteCIDRs[0] = "mutated"
	ports[0] = "mutated"
	if route.CIDRs[0] != "10.251.0.0/24" {
		t.Fatalf("route.CIDRs aliases the connection's RemoteCIDRs backing array: %v", route.CIDRs)
	}
	if route.Ports[0] != "p0" {
		t.Fatalf("route.Ports aliases the vpcPorts backing array: %v", route.Ports)
	}
}

// hubLegPort is one served VPC's leg Port for an appliance pod — the fixture
// resolveVPCLegPorts and ensureBindings tests seed the fake client with.
func hubLegPort(name, vpcNS, vpcName, podNS, podName, ip string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				sdnv1alpha1.LabelVPCNamespace: vpcNS,
				sdnv1alpha1.LabelVPC:          vpcName,
			},
		},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef:       sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName},
			PodNamespace: podNS,
			PodName:      podName,
			IP:           ip,
		},
	}
}

// TestResolveVPCLegPorts covers resolving one additional served VPC's leg
// Ports for exactly the appliances already selected in the primary VPC, in
// the same order — and treating a not-yet-minted leg as "not ready" (nil),
// per docs/vpn.md §3.3.
func TestResolveVPCLegPorts(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace = "gateway", "tenant"
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "vpc-b", Namespace: "tenant"}}
	appliances := []applianceResolution{
		{PodName: "gateway-vpn-0"},
		{PodName: "gateway-vpn-1"},
	}

	t.Run("returns exactly the given appliances' leg ports, in order", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
			hubLegPort("vpc-b-leg-1", "tenant", "vpc-b", "tenant", "gateway-vpn-1", "10.20.0.2"),
			hubLegPort("vpc-b-leg-0", "tenant", "vpc-b", "tenant", "gateway-vpn-0", "10.20.0.1"),
		).Build()
		r := &VPNGatewayReconciler{Client: c}

		got := r.resolveVPCLegPorts(context.Background(), gw, vpc, appliances)
		if len(got) != 2 || got[0] != "vpc-b-leg-0" || got[1] != "vpc-b-leg-1" {
			t.Fatalf("resolveVPCLegPorts = %v, want [vpc-b-leg-0 vpc-b-leg-1] in appliance order", got)
		}
	})

	t.Run("a missing leg reports not-ready as nil", func(t *testing.T) {
		c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(
			hubLegPort("vpc-b-leg-0", "tenant", "vpc-b", "tenant", "gateway-vpn-0", "10.20.0.1"),
			// gateway-vpn-1's leg has not been minted yet.
		).Build()
		r := &VPNGatewayReconciler{Client: c}

		if got := r.resolveVPCLegPorts(context.Background(), gw, vpc, appliances); got != nil {
			t.Fatalf("resolveVPCLegPorts = %v, want nil when a leg is missing", got)
		}
	})
}

// TestEnsureBindingsPrunesStale covers the forwarding-grant reconciliation:
// exactly one VPCBinding per currently served VPC exists afterward, each
// carrying the scoped forwarding grant, and a binding for a VPC no longer
// served is deleted (docs/vpn.md §3.3).
func TestEnsureBindingsPrunesStale(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace = "gateway", "tenant"
	gw.Spec.VPCRef.Name = "vpc-a"
	gw.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}}

	stale := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{
		Name:      "gateway-vpn-vpc-stale",
		Namespace: "tenant",
		Labels:    map[string]string{vpnGatewayLabel: "gateway"},
	}}
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(stale).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}

	servedVPCs := []*sdnv1alpha1.VPC{
		{ObjectMeta: metav1.ObjectMeta{Name: "vpc-a", Namespace: "tenant"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "vpc-b", Namespace: "tenant"}},
	}
	if err := r.ensureBindings(context.Background(), gw, servedVPCs, []string{"10.251.0.0/24"}); err != nil {
		t.Fatalf("ensureBindings: %v", err)
	}

	var list sdnv1alpha1.VPCBindingList
	if err := c.List(context.Background(), &list, client.InNamespace("tenant"),
		client.MatchingLabels{vpnGatewayLabel: "gateway"}); err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	want := map[string]bool{
		vpnBindingName("gateway", "vpc-a", true):  true,
		vpnBindingName("gateway", "vpc-b", false): true,
	}
	got := map[string]bool{}
	for i := range list.Items {
		b := &list.Items[i]
		got[b.Name] = true
		if !b.Spec.AllowForwarding {
			t.Errorf("binding %q AllowForwarding = false, want true", b.Name)
		}
		if len(b.Spec.ForwardingCIDRs) != 1 || b.Spec.ForwardingCIDRs[0] != "10.251.0.0/24" {
			t.Errorf("binding %q ForwardingCIDRs = %v, want [10.251.0.0/24]", b.Name, b.Spec.ForwardingCIDRs)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("bindings after ensureBindings = %v, want exactly %v", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing expected binding %q", name)
		}
	}
	if got[stale.Name] {
		t.Errorf("stale binding %q was not pruned", stale.Name)
	}
}
