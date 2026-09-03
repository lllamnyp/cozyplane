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
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// This file reproduces the "Revue sécurité — posture attaquant" scenarios from
// the hub-managed-VPNGateway plan (docs/vpn.md §3.3): for each, it plays the
// attacker's move against the controller/validation code and confirms the
// defense holds. See per-test comments for the scenario each covers.

// ---------------------------------------------------------------------------
// Scenario 1: a remote site sends a decrypted packet whose source spoofs a
// member of a served VPC. The datapath drop is enforced in bpf/overlay.c
// cozyplane_from_pod (fwd_cidrs / PORT_F_FWD_SCOPED, ~l.5238-5266): a foreign
// source on a SCOPED forwarding leg is admitted only when it matches
// VPCBinding.forwardingCIDRs; everything else is TC_ACT_SHOT. That defense is
// only as good as two controller invariants, both reproduced here: (a) a
// served VPC binding's ForwardingCIDRs is never widened beyond the accepted
// remote CIDRs, and (b) an empty grant is never rendered as AllowForwarding
// (which cmd/cni's requireVPCBinding would otherwise read as an unscoped,
// blanket-admit leg — see the "pre-existing" note in the final report).
// ---------------------------------------------------------------------------

// TestEnsureBindingsNeverGrantsBlanketForwarding attacks the "no accepted
// remote CIDRs yet" window (gateway just created, or every remoteCIDR was just
// stripped by the deny-set): ensureBindings must render AllowForwarding=false
// with no ForwardingCIDRs for every served VPC, never a blanket grant.
func TestEnsureBindingsNeverGrantsBlanketForwarding(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{}
	gw.Name, gw.Namespace = "gateway", "tenant"
	gw.Spec.VPCRef.Name = "vpc-a"
	gw.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}}

	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}

	servedVPCs := []*sdnv1alpha1.VPC{
		{ObjectMeta: metav1.ObjectMeta{Name: "vpc-a", Namespace: "tenant"}},
		{ObjectMeta: metav1.ObjectMeta{Name: "vpc-b", Namespace: "tenant"}},
	}
	// fwdCIDRs empty: no connection is Ready yet / every remoteCIDR was denied.
	if err := r.ensureBindings(context.Background(), gw, servedVPCs, nil); err != nil {
		t.Fatalf("ensureBindings: %v", err)
	}

	var list sdnv1alpha1.VPCBindingList
	if err := c.List(context.Background(), &list, client.InNamespace("tenant"),
		client.MatchingLabels{vpnGatewayLabel: "gateway"}); err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("bindings = %d, want 2 (one per served VPC)", len(list.Items))
	}
	for _, b := range list.Items {
		if b.Spec.AllowForwarding {
			t.Errorf("binding %q AllowForwarding = true with no accepted remote CIDRs — blanket grant", b.Name)
		}
		if len(b.Spec.ForwardingCIDRs) != 0 {
			t.Errorf("binding %q ForwardingCIDRs = %v, want empty", b.Name, b.Spec.ForwardingCIDRs)
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario 2: grant widening through remoteCIDRs. A tenant declares a
// remoteCIDR equal to, inside, or enclosing a served VPC's own prefix (v4 or
// v6), or equal to ANOTHER served VPC's prefix in a multi-VPC hub, trying to
// smuggle that prefix into forwardingCIDRs / status.routes.
// ---------------------------------------------------------------------------

// TestForbiddenRemoteCIDRGrantWidening attacks forbiddenRemoteCIDR directly
// with the exact/narrower/enclosing v4 and v6 shapes, plus a CIDR that only
// matches the OTHER served VPC in a two-VPC hub (A+C) — the case a
// single-served-VPC deny-set test cannot exercise.
func TestForbiddenRemoteCIDRGrantWidening(t *testing.T) {
	r := &VPNGatewayReconciler{}
	// Hub serves vpc-a (v4+v6) and vpc-c — servedCIDRs is the union the
	// Reconcile loop actually computes (servedVPCCIDRs over both VPCs).
	vpcs := []*sdnv1alpha1.VPC{
		vpcWithCIDRs("tenant", "vpc-a", 100, "10.250.0.0/24", "fd00:250::/64"),
		vpcWithCIDRs("tenant", "vpc-c", 102, "10.252.0.0/24"),
	}
	servedCIDRs, overlap := servedVPCCIDRs(vpcs)
	if overlap != "" {
		t.Fatalf("fixture VPCs unexpectedly overlap: %s", overlap)
	}

	tests := []struct {
		name string
		cidr string
		want string
	}{
		{"exact match of served VPC-A", "10.250.0.0/24", "served VPC"},
		{"narrower subset inside VPC-A", "10.250.0.128/25", "served VPC"},
		{"englobing supernet over VPC-A", "10.0.0.0/8", "served VPC"},
		{"IPv6 exact match of served VPC-A", "fd00:250::/64", "served VPC"},
		{"IPv6 englobing supernet over VPC-A", "fd00::/16", "served VPC"},
		{"exact match of the OTHER served VPC (VPC-C)", "10.252.0.0/24", "served VPC"},
		{"narrower subset inside VPC-C", "10.252.0.128/25", "served VPC"},
		{"disjoint remote site is allowed", "203.0.113.0/24", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.forbiddenRemoteCIDR(tt.cidr, servedCIDRs); got != tt.want {
				t.Fatalf("forbiddenRemoteCIDR(%q) = %q, want %q", tt.cidr, got, tt.want)
			}
		})
	}
}

// TestFilterForbiddenCIDRsStripsWideningAttemptsFromEveryDownstreamConsumer
// reproduces the end-to-end attack: a VPNConnection declares a mix of a
// legitimate remote site and several grant-widening CIDRs. It confirms the
// widening CIDRs never reach unionRemoteCIDRs (the forwarding grant) nor
// connectionRoutes (status.routes / vpc_routes) — only filterForbiddenCIDRs's
// rejected list sees them, surfaced via the RemoteCIDRsAccepted condition.
func TestFilterForbiddenCIDRsStripsWideningAttemptsFromEveryDownstreamConsumer(t *testing.T) {
	r := &VPNGatewayReconciler{}
	vpcs := []*sdnv1alpha1.VPC{
		vpcWithCIDRs("tenant", "vpc-a", 100, "10.250.0.0/24"),
		vpcWithCIDRs("tenant", "vpc-c", 102, "10.252.0.0/24"),
	}
	servedCIDRs, overlap := servedVPCCIDRs(vpcs)
	if overlap != "" {
		t.Fatalf("fixture VPCs unexpectedly overlap: %s", overlap)
	}

	conns := []sdnv1alpha1.VPNConnection{
		{ObjectMeta: metav1.ObjectMeta{Name: "attacker-site"}, Spec: sdnv1alpha1.VPNConnectionSpec{
			RemoteCIDRs: []string{
				"203.0.113.0/24",  // legitimate remote site: must survive
				"10.250.0.0/24",   // == served VPC-A: must be stripped
				"10.0.0.0/8",      // englobes VPC-A: must be stripped
				"10.252.0.128/25", // inside served VPC-C: must be stripped
			},
		}},
	}

	rejected := r.filterForbiddenCIDRs(conns, servedCIDRs)
	if len(rejected) != 3 {
		t.Fatalf("rejected = %v, want exactly 3 widening attempts stripped", rejected)
	}

	fwdCIDRs := unionRemoteCIDRs(conns)
	if len(fwdCIDRs) != 1 || fwdCIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("unionRemoteCIDRs (forwarding grant) = %v, want only [203.0.113.0/24]", fwdCIDRs)
	}
	for _, forbidden := range []string{"10.250.0.0/24", "10.0.0.0/8", "10.252.0.128/25"} {
		for _, got := range fwdCIDRs {
			if got == forbidden {
				t.Fatalf("forwarding grant leaked a widening CIDR: %v", fwdCIDRs)
			}
		}
	}

	// Routes toward each served VPC's leg must carry only the surviving CIDR.
	for _, vpcPorts := range [][]string{{"leg-a-0"}, {"leg-c-0"}} {
		routes := connectionRoutes(conns, vpcPorts)
		if len(routes) != 1 || len(routes[0].CIDRs) != 1 || routes[0].CIDRs[0] != "203.0.113.0/24" {
			t.Fatalf("connectionRoutes(%v) = %+v, want a single route carrying only 203.0.113.0/24", vpcPorts, routes)
		}
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: inter-VPC transit through the hub. A pod in served VPC-A must
// not be able to reach served VPC-B through the appliance — only remoteCIDRs
// (external sites) are ever routed, never a served VPC's own prefix, in
// either direction. Enforced by construction: connectionRoutes only ever
// copies conns[i].Spec.RemoteCIDRs (never a VPC's Spec.CIDRs), and those are
// stripped of every served-VPC prefix by filterForbiddenCIDRs *before* any
// route is built (traced in Reconcile: filterForbiddenCIDRs at l.285, before
// the per-servedVPC connectionRoutes loop at l.395-404). cmd/agent/main.go
// resolveRoutes further scopes each route entry to a single VNI, derived from
// the leg Port's own name (vniFromPortName) — a route entry can never mix legs
// from two VPCs, so even a malformed route could not cross-deliver.
// ---------------------------------------------------------------------------

// TestNoInterVPCTransitRoutes attacks the transit path directly: a connection
// declares remoteCIDRs equal to a served VPC's own CIDR (an attempt to make a
// VPC-A pod's egress through the tunnel land back inside VPC-B's own prefix).
// After the deny-set runs, no route toward ANY served VPC's leg carries that
// prefix, and a connection left with no surviving remote CIDRs contributes no
// route at all.
func TestNoInterVPCTransitRoutes(t *testing.T) {
	r := &VPNGatewayReconciler{}
	vpcs := []*sdnv1alpha1.VPC{
		vpcWithCIDRs("tenant", "vpc-a", 100, "10.250.0.0/24"),
		vpcWithCIDRs("tenant", "vpc-b", 101, "10.251.0.0/24"),
	}
	servedCIDRs, overlap := servedVPCCIDRs(vpcs)
	if overlap != "" {
		t.Fatalf("fixture VPCs unexpectedly overlap: %s", overlap)
	}

	conns := []sdnv1alpha1.VPNConnection{
		{ObjectMeta: metav1.ObjectMeta{Name: "transit-attempt"}, Spec: sdnv1alpha1.VPNConnectionSpec{
			RemoteCIDRs: []string{"10.251.0.0/24"}, // == served VPC-B's own CIDR, only prefix declared
		}},
	}
	rejected := r.filterForbiddenCIDRs(conns, servedCIDRs)
	if len(rejected) != 1 {
		t.Fatalf("rejected = %v, want the VPC-B transit attempt stripped", rejected)
	}

	// Every served VPC's route set (as Reconcile builds it, per-VPC in served
	// order) must now be empty: the connection has no remote CIDRs left.
	for _, legPorts := range [][]string{{"leg-a-0"}, {"leg-b-0"}} {
		if routes := connectionRoutes(conns, legPorts); len(routes) != 0 {
			t.Fatalf("connectionRoutes(%v) = %+v, want no routes (VPC-B transit must not surface as a route)", legPorts, routes)
		}
	}
	if got := nonEmptyRouteConns(conns); len(got) != 0 {
		t.Fatalf("nonEmptyRouteConns = %+v, want none — routesReady must not count a fully-denied connection", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: served VPCs with overlapping CIDRs must hold the gateway
// Pending("VPCCIDRsOverlap") and realize NOTHING — no binding, no workload, no
// route — beyond the status write. Reproduced as a full Reconcile() run
// against a fake client (docs/vpn.md §3.3; traced order in Reconcile:
// servedVPCCIDRs/overlap check at l.268-271 returns via reportUnready before
// connectionsFor, ensureBindings, or ensureApplianceWorkload ever run).
// ---------------------------------------------------------------------------

// TestReconcileOverlappingServedVPCsCreatesNothing attacks the hub by naming
// two served VPCs whose prefixes overlap (10.250.0.0/24 inside
// 10.250.0.0/16) and asserts Reconcile stops at Pending/VPCCIDRsOverlap
// without creating a single VPCBinding, Deployment, StatefulSet, or FloatingIP.
func TestReconcileOverlappingServedVPCsCreatesNothing(t *testing.T) {
	scheme := gatewayScheme(t) // sdn + client-go (apps/v1, core/v1)
	vpcA := vpcWithCIDRs("tenant", "vpc-a", 100, "10.250.0.0/24")
	vpcB := vpcWithCIDRs("tenant", "vpc-b", 101, "10.250.0.0/16") // overlaps vpc-a

	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}}
	gw.Spec.VPCRef.Name = "vpc-a"
	gw.Spec.AdditionalVPCRefs = []sdnv1alpha1.LocalVPCRef{{Name: "vpc-b"}}
	gw.Spec.WireGuard = &sdnv1alpha1.VPNGatewayWireGuard{}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, vpcA, vpcB).
		WithStatusSubresource(&sdnv1alpha1.VPNGateway{}).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/cozyplane:test"}}

	key := types.NamespacedName{Namespace: "tenant", Name: "gateway"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	got := &sdnv1alpha1.VPNGateway{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get VPNGateway: %v", err)
	}
	if got.Status.Phase != sdnv1alpha1.VPNGatewayPhasePending {
		t.Fatalf("phase = %q, want Pending", got.Status.Phase)
	}
	cond := meta.FindStatusCondition(got.Status.Conditions, sdnv1alpha1.VPNGatewayConditionApplianceReady)
	if cond == nil || cond.Reason != "VPCCIDRsOverlap" {
		t.Fatalf("ApplianceReady condition = %+v, want reason VPCCIDRsOverlap", cond)
	}
	if len(got.Status.Routes) != 0 {
		t.Fatalf("status.routes = %+v, want none", got.Status.Routes)
	}

	var bindings sdnv1alpha1.VPCBindingList
	if err := c.List(context.Background(), &bindings, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings.Items) != 0 {
		t.Fatalf("VPCBindings created = %d, want 0 (overlap must realize nothing)", len(bindings.Items))
	}

	var deployments appsv1.DeploymentList
	if err := c.List(context.Background(), &deployments, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list deployments: %v", err)
	}
	if len(deployments.Items) != 0 {
		t.Fatalf("Deployments created = %d, want 0", len(deployments.Items))
	}

	var secrets corev1.SecretList
	if err := c.List(context.Background(), &secrets, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(secrets.Items) != 0 {
		t.Fatalf("Secrets created = %d, want 0 (no keypair/config material for an unrealized gateway)", len(secrets.Items))
	}

	var fips sdnv1alpha1.FloatingIPList
	if err := c.List(context.Background(), &fips, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list floating IPs: %v", err)
	}
	if len(fips.Items) != 0 {
		t.Fatalf("FloatingIPs created = %d, want 0", len(fips.Items))
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: deleting the gateway must prune ALL of its forwarding-grant
// bindings by label, not just the legacy `<gw>-vpn` name — otherwise an
// additional VPC's grant would survive gateway deletion.
// ---------------------------------------------------------------------------

// TestTeardownOwnedPrunesAllLabelledBindingsOnly attacks a stale-grant window
// at gateway deletion: seeds two bindings labelled for this gateway (the
// legacy-named primary and a hub additional-VPC binding with a name teardown
// cannot guess) plus one unrelated binding without the label, then calls
// teardownOwned and asserts exactly the labelled two are gone and the
// unrelated one survives untouched.
func TestTeardownOwnedPrunesAllLabelledBindingsOnly(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant"}}

	primary := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{
		Name: "gateway-vpn", Namespace: "tenant", Labels: map[string]string{vpnGatewayLabel: "gateway"},
	}}
	additional := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{
		Name: "gateway-vpn-vpc-b", Namespace: "tenant", Labels: map[string]string{vpnGatewayLabel: "gateway"},
	}}
	unrelated := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{
		Name: "other-tenant-binding", Namespace: "tenant", // no vpnGatewayLabel at all
	}}

	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(primary, additional, unrelated).Build()
	r := &VPNGatewayReconciler{Client: c, Scheme: scheme}

	if err := r.teardownOwned(context.Background(), gw); err != nil {
		t.Fatalf("teardownOwned: %v", err)
	}

	var list sdnv1alpha1.VPCBindingList
	if err := c.List(context.Background(), &list, client.InNamespace("tenant")); err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].Name != unrelated.Name {
		names := make([]string, len(list.Items))
		for i, b := range list.Items {
			names[i] = b.Name
		}
		t.Fatalf("bindings after teardownOwned = %v, want only %q to survive", names, unrelated.Name)
	}
}
