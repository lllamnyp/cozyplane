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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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
		WithStatusSubresource(&sdnv1alpha1.VPCGateway{}, &corev1.Service{}).
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

// natServiceForFamily returns the gateway's owned NAT Service of a family
// ("IPv4"/"IPv6"), or nil.
func natServiceForFamily(t *testing.T, c client.Client, ns, gwName, family string) *corev1.Service {
	t.Helper()
	var list corev1.ServiceList
	if err := c.List(context.Background(), &list, client.InNamespace(ns), client.MatchingLabels{
		vpcGatewayLabel:    gwName,
		addressFamilyLabel: family,
	}); err != nil {
		t.Fatalf("list NAT services: %v", err)
	}
	if len(list.Items) == 0 {
		return nil
	}
	return &list.Items[0]
}

func allNATServices(t *testing.T, c client.Client, ns, gwName string) []corev1.Service {
	t.Helper()
	var list corev1.ServiceList
	if err := c.List(context.Background(), &list, client.InNamespace(ns),
		client.MatchingLabels{vpcGatewayLabel: gwName}); err != nil {
		t.Fatalf("list NAT services: %v", err)
	}
	return list.Items
}

// assignAndReconcile writes an LB ingress address onto the gateway's family Service
// (simulating the LB implementation) and reconciles again.
func assignAndReconcile(t *testing.T, c client.Client, ns, gwName, family, ip string) *sdnv1alpha1.VPCGateway {
	t.Helper()
	svc := natServiceForFamily(t, c, ns, gwName, family)
	if svc == nil {
		t.Fatalf("no %s NAT service to assign an address to", family)
	}
	assignServiceAddress(t, c, svc, ip)
	return reconcileGateway(t, c, ns, gwName)
}

// A v4 VPC's gateway owns exactly one v4 LoadBalancer Service (delegated via
// service-proxy-name), and its assigned address becomes the v4 NAT identity.
func TestGatewayV4VPCDrawsV4Service(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door") // creates the Service

	svc := natServiceForFamily(t, c, "team-a", "door", "IPv4")
	if svc == nil {
		t.Fatal("no v4 NAT Service was created")
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("Service type = %q, want LoadBalancer", svc.Spec.Type)
	}
	if svc.Labels[serviceProxyNameLabel] != serviceProxyNameValue {
		t.Error("NAT Service must carry service-proxy-name (every proxy must skip its datapath)")
	}
	if len(svc.Spec.IPFamilies) != 1 || svc.Spec.IPFamilies[0] != corev1.IPv4Protocol {
		t.Errorf("Service ipFamilies = %v, want [IPv4]", svc.Spec.IPFamilies)
	}
	if natServiceForFamily(t, c, "team-a", "door", "IPv6") != nil {
		t.Error("a v4-only VPC must own no v6 NAT Service")
	}

	gw := assignAndReconcile(t, c, "team-a", "door", "IPv4", "203.0.113.5")
	if gw.Status.NATAddress != "203.0.113.5" || gw.Status.NATAddress6 != "" {
		t.Errorf("NAT identity = (%q, %q), want (203.0.113.5, \"\")", gw.Status.NATAddress, gw.Status.NATAddress6)
	}
}

// A v6 VPC's gateway owns a v6 Service and wears the v6 address it is assigned.
func TestGatewayV6VPCDrawsV6Service(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "fd00:10::/64"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")

	svc := natServiceForFamily(t, c, "team-a", "door", "IPv6")
	if svc == nil {
		t.Fatal("no v6 NAT Service was created")
	}
	if len(svc.Spec.IPFamilies) != 1 || svc.Spec.IPFamilies[0] != corev1.IPv6Protocol {
		t.Errorf("Service ipFamilies = %v, want [IPv6]", svc.Spec.IPFamilies)
	}
	gw := assignAndReconcile(t, c, "team-a", "door", "IPv6", "2001:db8::5")
	if gw.Status.NATAddress != "" || gw.Status.NATAddress6 != "2001:db8::5" {
		t.Errorf("NAT identity = (%q, %q), want (\"\", 2001:db8::5)", gw.Status.NATAddress, gw.Status.NATAddress6)
	}
}

// A dual-stack VPC draws one Service of EACH family, each an independent identity.
func TestGatewayDualStackDrawsBothServices(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")

	if got := len(allNATServices(t, c, "team-a", "door")); got != 2 {
		t.Fatalf("dual-stack gateway owns %d NAT Services, want 2", got)
	}
	assignAndReconcile(t, c, "team-a", "door", "IPv4", "203.0.113.5")
	gw := assignAndReconcile(t, c, "team-a", "door", "IPv6", "2001:db8::5")
	if gw.Status.NATAddress != "203.0.113.5" || gw.Status.NATAddress6 != "2001:db8::5" {
		t.Errorf("dual-stack identity = (%q, %q), want (203.0.113.5, 2001:db8::5)", gw.Status.NATAddress, gw.Status.NATAddress6)
	}
}

// A family whose Service gets no address yields no identity — the #15 pod fallback:
// NATAddress6 stays empty, so gateway_controller.go keeps the gateway pod for v6.
func TestGatewayV6ServiceUnassignedKeepsPodFallback(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")

	// Only the v4 Service gets an address; the v6 Service stays unassigned.
	gw := assignAndReconcile(t, c, "team-a", "door", "IPv4", "203.0.113.5")
	if gw.Status.NATAddress != "203.0.113.5" {
		t.Errorf("v4 identity = %q, want 203.0.113.5", gw.Status.NATAddress)
	}
	if gw.Status.NATAddress6 != "" {
		t.Errorf("v6 identity = %q, want empty (no address assigned ⇒ gateway pod keeps v6)", gw.Status.NATAddress6)
	}
}

// The synthesized EndpointSlice is a self-addressed, always-Ready advertisement
// trigger (there is no target pod), so MetalLB advertises the NAT address.
func TestGatewayNATServiceEndpointSliceReady(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")
	assignAndReconcile(t, c, "team-a", "door", "IPv4", "203.0.113.5")

	svc := natServiceForFamily(t, c, "team-a", "door", "IPv4")
	eps := &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: svc.Name}, eps); err != nil {
		t.Fatalf("no EndpointSlice for the NAT Service: %v", err)
	}
	if len(eps.Endpoints) != 1 {
		t.Fatalf("want one endpoint, got %d", len(eps.Endpoints))
	}
	ep := eps.Endpoints[0]
	if ep.Conditions.Ready == nil || !*ep.Conditions.Ready {
		t.Error("the NAT endpoint must be Ready (so MetalLB advertises even under etp: Cluster)")
	}
	if len(ep.Addresses) != 1 || ep.Addresses[0] != "203.0.113.5" {
		t.Errorf("endpoint addresses = %v, want [203.0.113.5] (self-addressed, the NAT address)", ep.Addresses)
	}
}

// A non-exclusive (loser) gateway owns no Service — it realizes nothing.
func TestGatewayNonExclusiveLoserOwnsNoService(t *testing.T) {
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		natGateway("team-a", "door", "vpc-a"),
		natGateway("team-a", "door2", "vpc-a"))
	reconcileGateway(t, c, "team-a", "door")
	loser := reconcileGateway(t, c, "team-a", "door2")

	if len(allNATServices(t, c, "team-a", "door2")) != 0 {
		t.Error("the losing gateway must own no NAT Service")
	}
	if len(allNATServices(t, c, "team-a", "door")) == 0 {
		t.Error("the winning gateway must own its NAT Service")
	}
	_ = loser
}

// Reservation is per family (docs/external-addresses.md §7): each per-family
// claim name lands as the association annotation on exactly that family's Service.
func TestGatewayPerFamilyClaimAnnotations(t *testing.T) {
	gw := natGateway("team-a", "door", "vpc-a")
	gw.Spec.NAT.AddressClaimName = "egress-v4"
	gw.Spec.NAT.AddressClaimName6 = "egress-v6"
	c := gwClient(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"), gw)
	reconcileGateway(t, c, "team-a", "door")

	v4 := natServiceForFamily(t, c, "team-a", "door", "IPv4")
	v6 := natServiceForFamily(t, c, "team-a", "door", "IPv6")
	if v4 == nil || v6 == nil {
		t.Fatal("expected one NAT Service per family")
	}
	if got := v4.Annotations[addressClaimAnnotation]; got != "egress-v4" {
		t.Errorf("v4 Service annotation = %q, want egress-v4", got)
	}
	if got := v6.Annotations[addressClaimAnnotation]; got != "egress-v6" {
		t.Errorf("v6 Service annotation = %q, want egress-v6", got)
	}

	// Clearing one family's claim removes only that family's annotation.
	got := &sdnv1alpha1.VPCGateway{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "door"}, got); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	got.Spec.NAT.AddressClaimName6 = ""
	if err := c.Update(context.Background(), got); err != nil {
		t.Fatalf("update gateway: %v", err)
	}
	reconcileGateway(t, c, "team-a", "door")
	if _, ok := natServiceForFamily(t, c, "team-a", "door", "IPv6").Annotations[addressClaimAnnotation]; ok {
		t.Error("v6 annotation must be removed when its claim name is cleared")
	}
	if got := natServiceForFamily(t, c, "team-a", "door", "IPv4").Annotations[addressClaimAnnotation]; got != "egress-v4" {
		t.Errorf("v4 annotation must survive the v6 clear, got %q", got)
	}
}

// NAT disabled: no identity Service at all.
func TestGatewayNATDisabledOwnsNoService(t *testing.T) {
	gw := natGateway("team-a", "door", "vpc-a")
	gw.Spec.NAT.Enabled = false
	c := gwClient(t, vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"), gw)
	reconcileGateway(t, c, "team-a", "door")
	if len(allNATServices(t, c, "team-a", "door")) != 0 {
		t.Error("a NAT-disabled gateway must own no NAT Service")
	}
}
