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
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	localsdnv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func vpcWithCIDRs(ns, name string, vni int32, cidrs ...string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: cidrs},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

func gwClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(gatewayScheme(t)). // registers client-go (Services/EndpointSlices) + sdn
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.VPCGateway{}, &corev1.Service{}, &sdnv1alpha1.NATGateway{},
			&sdnv1alpha1.RouteTable{}, &sdnv1alpha1.Route{}).
		Build()
}

// reconcileGateway runs the VPCGateway controller once and returns the gateway.
func reconcileGateway(t *testing.T, c client.Client, ns, name string) *sdnv1alpha1.VPCGateway {
	t.Helper()
	r := &VPCGatewayReconciler{Client: c, Scheme: gatewayScheme(t)}
	key := types.NamespacedName{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	gw := &sdnv1alpha1.VPCGateway{}
	if err := c.Get(context.Background(), key, gw); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	return gw
}

// egressScheme registers client-go, sdn and the local group.
func egressScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := gatewayScheme(t)
	if err := localsdnv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add local scheme: %v", err)
	}
	return s
}

func egressClient(t *testing.T, s *runtime.Scheme, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.VPCGateway{}, &corev1.Service{}, &sdnv1alpha1.NATGateway{},
			&sdnv1alpha1.RouteTable{}, &sdnv1alpha1.Route{}, &localsdnv1alpha1.NATPortBlock{}).
		Build()
}

// nat.enabled becomes a NATGateway the gateway owns, mirroring its claims, and a
// default RouteTable for a VPC that has none (docs/vpc-egress.md §7).
func TestGatewayNATEnabledCreatesEgressObjects(t *testing.T) {
	gw := natGateway("team-a", "door", "vpc-a")
	gw.Spec.NAT.AddressClaimName = "c4"
	gw.Spec.LoadBalancerClass = "metallb"
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"), gw)
	got := reconcileGateway(t, c, "team-a", "door")

	ngw := &sdnv1alpha1.NATGateway{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, ngw); err != nil {
		t.Fatalf("no NATGateway: %v", err)
	}
	if !metav1.IsControlledBy(ngw, got) {
		t.Error("the NATGateway must be owned by the VPCGateway")
	}
	if ngw.Spec.VPCRef.Name != "vpc-a" || ngw.Spec.AddressClaimName != "c4" || ngw.Spec.LoadBalancerClass != "metallb" {
		t.Errorf("NATGateway spec = %+v, want the gateway's VPC, claim and class", ngw.Spec)
	}
	rt := &sdnv1alpha1.RouteTable{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, rt); err != nil {
		t.Fatalf("no default RouteTable: %v", err)
	}
	if !rt.Spec.Default || rt.Spec.VPCRef.Name != "vpc-a" {
		t.Errorf("RouteTable spec = %+v, want the VPC's default table", rt.Spec)
	}
	// No address yet: no route, so a family without one still reaches the pod.
	var routes sdnv1alpha1.RouteList
	if err := c.List(context.Background(), &routes, client.InNamespace("team-a")); err != nil {
		t.Fatal(err)
	}
	if len(routes.Items) != 0 {
		t.Errorf("routes before any address = %d, want 0", len(routes.Items))
	}
}

// Once the NAT gateway holds an address, the family gets its default route, and
// the gateway's status mirrors the address.
func TestGatewayDefaultRouteFollowsNATGatewayAddress(t *testing.T) {
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"), natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")
	ngw := &sdnv1alpha1.NATGateway{}
	key := types.NamespacedName{Namespace: "team-a", Name: "door"}
	if err := c.Get(context.Background(), key, ngw); err != nil {
		t.Fatal(err)
	}
	ngw.Status.Address = "203.0.113.5"
	if err := c.Status().Update(context.Background(), ngw); err != nil {
		t.Fatal(err)
	}
	got := reconcileGateway(t, c, "team-a", "door")
	if got.Status.NATAddress != "203.0.113.5" || got.Status.NATAddress6 != "" {
		t.Errorf("mirrored addresses = %q/%q, want 203.0.113.5/empty", got.Status.NATAddress, got.Status.NATAddress6)
	}
	r := &sdnv1alpha1.Route{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door-default-ipv4"}, r); err != nil {
		t.Fatalf("no v4 default route: %v", err)
	}
	if r.Spec.Destination != "0.0.0.0/0" || r.Spec.RouteTableRef.Name != "door" ||
		r.Spec.Target.NATGateway == nil || r.Spec.Target.NATGateway.Name != "door" {
		t.Errorf("v4 default route = %+v", r.Spec)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door-default-ipv6"}, &sdnv1alpha1.Route{}); err == nil {
		t.Error("the v6 family has no address and must have no route (it keeps the gateway pod)")
	}
}

// A VPC that already has a default table gets the default routes in it; the
// transition creates no second table.
func TestGatewayUsesExistingDefaultTable(t *testing.T) {
	user := &sdnv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: "main", Namespace: "team-a"},
		Spec:       sdnv1alpha1.RouteTableSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "vpc-a"}, Default: true},
	}
	ngw := &sdnv1alpha1.NATGateway{}
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"), natGateway("team-a", "door", "vpc-a"), user)
	reconcileGateway(t, c, "team-a", "door")
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, &sdnv1alpha1.RouteTable{}); err == nil {
		t.Error("a VPC with a default table must not get a second one")
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, ngw); err != nil {
		t.Fatal(err)
	}
	ngw.Status.Address = "203.0.113.5"
	if err := c.Status().Update(context.Background(), ngw); err != nil {
		t.Fatal(err)
	}
	reconcileGateway(t, c, "team-a", "door")
	r := &sdnv1alpha1.Route{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door-default-ipv4"}, r); err != nil {
		t.Fatal(err)
	}
	if r.Spec.RouteTableRef.Name != "main" {
		t.Errorf("default route table = %q, want the VPC's default table main", r.Spec.RouteTableRef.Name)
	}
}

// A losing (non-exclusive) gateway realizes nothing.
func TestGatewayNonExclusiveLoserCreatesNothing(t *testing.T) {
	winner := natGateway("team-a", "first", "vpc-a")
	winner.CreationTimestamp = metav1.NewTime(time.Now().Add(-time.Hour))
	loser := natGateway("team-a", "second", "vpc-a")
	loser.CreationTimestamp = metav1.NewTime(time.Now())
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"), winner, loser)
	reconcileGateway(t, c, "team-a", "second")
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "second"}, &sdnv1alpha1.NATGateway{}); err == nil {
		t.Error("the losing gateway must create no NATGateway")
	}
}

// Disabling NAT deletes what the gateway created, including a NAT Service a
// VPCGateway owned before NAT gateways existed.
func TestGatewayNATDisabledDeletesEgressObjects(t *testing.T) {
	gw := natGateway("team-a", "door", "vpc-a")
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"), gw)
	got := reconcileGateway(t, c, "team-a", "door")
	legacy := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "door-v4-x", Namespace: "team-a",
			Labels: map[string]string{vpcGatewayLabel: "door", addressFamilyLabel: "IPv4"}},
	}
	if err := controllerutil.SetControllerReference(got, legacy, gatewayScheme(t)); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	got.Spec.NAT.Enabled = false
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatal(err)
	}
	reconcileGateway(t, c, "team-a", "door")
	for _, o := range []client.Object{&sdnv1alpha1.NATGateway{}, &sdnv1alpha1.RouteTable{}} {
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, o); err == nil {
			t.Errorf("%T survived nat.enabled=false", o)
		}
	}
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(legacy), &corev1.Service{}); err == nil {
		t.Error("the legacy NAT Service survived nat.enabled=false")
	}
}

// Conditions must carry the fields metav1.Condition requires. A bare append
// left LastTransitionTime zero: kubectl renders a blank transition time, an
// age computation is wrong, and the object would be rejected outright if the
// kind ever went back to CRD-served — where lastTransitionTime is required.
func TestGatewayConditionsAreWellFormed(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"))
	gw := reconcileGateway(t, c, "team-a", "door")

	if len(gw.Status.Conditions) == 0 {
		t.Fatal("gateway reported no conditions")
	}
	seen := map[string]int{}
	for _, cond := range gw.Status.Conditions {
		seen[cond.Type]++
		if cond.LastTransitionTime.IsZero() {
			t.Errorf("condition %q has no LastTransitionTime", cond.Type)
		}
		if cond.Reason == "" {
			t.Errorf("condition %q has no Reason", cond.Type)
		}
	}
	for typ, n := range seen {
		if n > 1 {
			t.Errorf("condition %q appears %d times; conditions are a map by type", typ, n)
		}
	}
	for _, want := range []string{
		sdnv1alpha1.VPCGatewayConditionVPCResolved,
		sdnv1alpha1.VPCGatewayConditionExclusive,
		sdnv1alpha1.VPCGatewayConditionNATReady,
	} {
		if meta.FindStatusCondition(gw.Status.Conditions, want) == nil {
			t.Errorf("condition %q is missing", want)
		}
	}
}

// A settled gateway must stop writing status, or every reconcile is an API
// write and the controller never converges. This is what gwStatusEqual is for,
// and it must keep holding now that the ordering belongs to
// meta.SetStatusCondition rather than to the call order.
func TestGatewayStatusConvergesAcrossReconciles(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")
	first := reconcileGateway(t, c, "team-a", "door")
	second := reconcileGateway(t, c, "team-a", "door")

	if first.ResourceVersion != second.ResourceVersion {
		t.Errorf("status rewritten on a no-op reconcile: %s -> %s",
			first.ResourceVersion, second.ResourceVersion)
	}
}

// status must be seeded from the object's existing conditions, not built fresh,
// or meta.SetStatusCondition treats every condition as new on every write that
// does change something — silently re-stamping LastTransitionTime on conditions
// that did not themselves transition.
func TestGatewayUnrelatedConditionKeepsTransitionTimeOnPartialChange(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")

	got := &sdnv1alpha1.VPCGateway{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	past := metav1.NewTime(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
	vr := meta.FindStatusCondition(got.Status.Conditions, sdnv1alpha1.VPCGatewayConditionVPCResolved)
	if vr == nil {
		t.Fatal("VPCResolved condition missing after first reconcile")
	}
	vr.LastTransitionTime = past
	if err := c.Status().Update(context.Background(), got); err != nil {
		t.Fatalf("backdate VPCResolved: %v", err)
	}

	// An earlier-named gateway on the same VPC flips "door" from exclusive to
	// conflicted on the next reconcile — VPCResolved is untouched by this.
	if err := c.Create(context.Background(), natGateway("team-a", "aaa", "vpc-a")); err != nil {
		t.Fatalf("create conflicting gateway: %v", err)
	}
	second := reconcileGateway(t, c, "team-a", "door")

	exclusive := meta.FindStatusCondition(second.Status.Conditions, sdnv1alpha1.VPCGatewayConditionExclusive)
	if exclusive == nil || exclusive.Status != metav1.ConditionFalse {
		t.Fatal("Exclusive should have transitioned to False")
	}
	if exclusive.LastTransitionTime.Equal(&past) {
		t.Fatal("test is broken: Exclusive should be the condition that transitions, not the backdated one")
	}

	vpcResolved := meta.FindStatusCondition(second.Status.Conditions, sdnv1alpha1.VPCGatewayConditionVPCResolved)
	if vpcResolved == nil {
		t.Fatal("VPCResolved condition missing after second reconcile")
	}
	if !vpcResolved.LastTransitionTime.Equal(&past) {
		t.Errorf("VPCResolved LastTransitionTime = %v, want unchanged %v — a sibling condition's transition must not touch it",
			vpcResolved.LastTransitionTime, past)
	}
}
