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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	localsdnv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// claimScheme is egressScheme with the address-controller's claim registered
// as unstructured, as on a cluster that runs it.
func claimScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := egressScheme(t)
	s.AddKnownTypeWithName(ipAddressClaimGVK, &unstructured.Unstructured{})
	s.AddKnownTypeWithName(ipAddressClaimGVK.GroupVersion().WithKind("IPAddressClaimList"), &unstructured.UnstructuredList{})
	return s
}

func ipClaim(ns, name, phase string, addrs ...string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ipAddressClaimGVK)
	u.SetNamespace(ns)
	u.SetName(name)
	var list []any
	for _, a := range addrs {
		list = append(list, map[string]any{"name": "addr-" + a, "address": a})
	}
	_ = unstructured.SetNestedField(u.Object, map[string]any{"phase": phase, "addresses": list}, "status")
	return u
}

func natgw(ns, name, vpc, c4, c6 string) *sdnv1alpha1.NATGateway {
	return &sdnv1alpha1.NATGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, UID: types.UID("uid-" + name)},
		Spec: sdnv1alpha1.NATGatewaySpec{
			VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc}, AddressClaimName: c4, AddressClaimName6: c6,
		},
	}
}

func reconcileNATGateway(t *testing.T, s *runtime.Scheme, c client.Client, ns, name string) *sdnv1alpha1.NATGateway {
	t.Helper()
	r := &NATGatewayReconciler{Client: c, Scheme: s}
	key := types.NamespacedName{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	g := &sdnv1alpha1.NATGateway{}
	if err := c.Get(context.Background(), key, g); err != nil {
		t.Fatalf("get NATGateway: %v", err)
	}
	return g
}

func ngwServices(t *testing.T, c client.Client, ns, name string) map[string]*corev1.Service {
	t.Helper()
	var list corev1.ServiceList
	if err := c.List(context.Background(), &list, client.InNamespace(ns), client.MatchingLabels{natGatewayLabel: name}); err != nil {
		t.Fatal(err)
	}
	out := map[string]*corev1.Service{}
	for i := range list.Items {
		out[list.Items[i].Labels[natSlotLabel]] = &list.Items[i]
	}
	return out
}

func setIngress(t *testing.T, c client.Client, svc *corev1.Service, ips ...string) {
	t.Helper()
	svc.Status.LoadBalancer.Ingress = nil
	for _, ip := range ips {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: ip})
	}
	if err := c.Status().Update(context.Background(), svc); err != nil {
		t.Fatal(err)
	}
}

func addrCond(g *sdnv1alpha1.NATGateway) *metav1.Condition {
	return meta.FindStatusCondition(g.Status.Conditions, sdnv1alpha1.NATGatewayConditionAddressAssigned)
}

// No claim field: one dynamic single-family Service per VPC family, each with a
// self-addressed EndpointSlice once its address arrives.
func TestNATGatewayDynamicPerFamily(t *testing.T) {
	s := egressScheme(t)
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24", "fd00::/64"), natgw("t", "egress", "v", "", ""))
	g := reconcileNATGateway(t, s, c, "t", "egress")
	if g.Status.ID != 1 || g.Status.BlockSize != DefaultNATBlockSize {
		t.Errorf("id/blockSize = %d/%d, want 1/%d", g.Status.ID, g.Status.BlockSize, DefaultNATBlockSize)
	}
	svcs := ngwServices(t, c, "t", "egress")
	v4, v6 := svcs["dynamic-IPv4"], svcs["dynamic-IPv6"]
	if len(svcs) != 2 || v4 == nil || v6 == nil {
		t.Fatalf("services = %v, want dynamic-IPv4 and dynamic-IPv6", svcs)
	}
	if len(v4.Spec.IPFamilies) != 1 || v4.Spec.IPFamilies[0] != corev1.IPv4Protocol || v4.Annotations[addressClaimAnnotation] != "" {
		t.Errorf("v4 service = %v %v, want single-stack IPv4 without a claim", v4.Spec.IPFamilies, v4.Annotations)
	}
	setIngress(t, c, v4, "203.0.113.7")
	setIngress(t, c, v6, "2001:db8::7")
	g = reconcileNATGateway(t, s, c, "t", "egress")
	if g.Status.Address != "203.0.113.7" || g.Status.Address6 != "2001:db8::7" {
		t.Errorf("addresses = %q/%q", g.Status.Address, g.Status.Address6)
	}
	if cond := addrCond(g); cond == nil || cond.Status != metav1.ConditionTrue {
		t.Errorf("AddressAssigned = %+v, want True", cond)
	}
	eps := &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: v4.Name + "-v4"}, eps); err != nil {
		t.Fatalf("no v4 EndpointSlice: %v", err)
	}
	if len(eps.Endpoints) != 0 {
		t.Errorf("EndpointSlice = %+v, want no endpoint: the cluster has no Ready node", eps.Endpoints)
	}
	if v4.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
		t.Errorf("externalTrafficPolicy = %s, want Local", v4.Spec.ExternalTrafficPolicy)
	}
}

func natNode(name, ip, boot string, ready bool) *corev1.Node {
	st := corev1.ConditionFalse
	if ready {
		st = corev1.ConditionTrue
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: st}},
			Addresses:  []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}},
			NodeInfo:   corev1.NodeSystemInfo{BootID: boot},
		},
	}
}

func natLease(uid string, block int32, active bool, acks ...localsdnv1alpha1.NATPortBlockAck) *localsdnv1alpha1.NATPortBlock {
	return &localsdnv1alpha1.NATPortBlock{
		ObjectMeta: metav1.ObjectMeta{Name: localsdnv1alpha1.NATPortBlockName(types.UID(uid), int(block)),
			Labels: map[string]string{localsdnv1alpha1.LabelNATGatewayUID: uid}},
		Spec:   localsdnv1alpha1.NATPortBlockSpec{Block: block, Node: "a"},
		Status: localsdnv1alpha1.NATPortBlockStatus{Acks: acks, Active: active},
	}
}

// The NAT Service's endpoints are the Ready nodes that acked every active lease
// in their current boot, each with its nodeName, so the LB implementation
// announces the address only from a node that can forward every leased port
// (docs/vpc-egress.md §4.3). An inactive lease does not count.
func TestNATGatewayEndpointsAreNATReadyNodes(t *testing.T) {
	s := egressScheme(t)
	gw := natgw("t", "egress", "v", "", "")
	gw.UID = "gw-uid"
	ack := func(node, boot string) localsdnv1alpha1.NATPortBlockAck {
		return localsdnv1alpha1.NATPortBlockAck{Node: node, BootID: boot}
	}
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), gw,
		natNode("a", "10.1.0.1", "a1", true),
		natNode("b", "10.1.0.2", "b2", true), // rebooted: its ack is from boot b1
		natNode("c", "10.1.0.3", "c1", false),
		natLease("gw-uid", 0, true, ack("a", "a1"), ack("b", "b1"), ack("c", "c1")),
		natLease("gw-uid", 1, false, ack("a", "a1")),
	)
	reconcileNATGateway(t, s, c, "t", "egress")
	v4 := ngwServices(t, c, "t", "egress")["dynamic-IPv4"]
	setIngress(t, c, v4, "203.0.113.7")
	reconcileNATGateway(t, s, c, "t", "egress")
	eps := &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: v4.Name + "-v4"}, eps); err != nil {
		t.Fatalf("no v4 EndpointSlice: %v", err)
	}
	if len(eps.Endpoints) != 1 || *eps.Endpoints[0].NodeName != "a" || eps.Endpoints[0].Addresses[0] != "10.1.0.1" {
		t.Fatalf("endpoints = %+v, want only node a", eps.Endpoints)
	}

	// b re-acks in its current boot and joins.
	l := &localsdnv1alpha1.NATPortBlock{}
	if err := c.Get(context.Background(), types.NamespacedName{Name: localsdnv1alpha1.NATPortBlockName("gw-uid", 0)}, l); err != nil {
		t.Fatal(err)
	}
	l.Status.Acks[1].BootID = "b2"
	if err := c.Status().Update(context.Background(), l); err != nil {
		t.Fatal(err)
	}
	reconcileNATGateway(t, s, c, "t", "egress")
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: v4.Name + "-v4"}, eps); err != nil {
		t.Fatal(err)
	}
	if len(eps.Endpoints) != 2 || *eps.Endpoints[1].NodeName != "b" {
		t.Errorf("endpoints = %+v, want nodes a and b", eps.Endpoints)
	}
}

// With no node NAT-ready, every Ready node is an endpoint.
func TestNATReadyNodesFallsBackToReady(t *testing.T) {
	nodes := []corev1.Node{*natNode("b", "10.1.0.2", "b2", true), *natNode("a", "10.1.0.1", "a2", true), *natNode("c", "10.1.0.3", "", false)}
	leases := []localsdnv1alpha1.NATPortBlock{*natLease("u", 0, true, localsdnv1alpha1.NATPortBlockAck{Node: "a", BootID: "a1"})}
	got := natReadyNodes(nodes, leases)
	if len(got) != 2 || got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("nodes = %v, want the Ready nodes a and b", got)
	}
}

// Both fields naming one Dual claim: one dual-stack Service serves both families.
func TestNATGatewaySameDualClaimOneService(t *testing.T) {
	s := claimScheme(t)
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24", "fd00::/64"),
		natgw("t", "egress", "v", "dual", "dual"), ipClaim("t", "dual", "Bound", "203.0.113.9", "2001:db8::9"))
	reconcileNATGateway(t, s, c, "t", "egress")
	svcs := ngwServices(t, c, "t", "egress")
	svc := svcs["dual"]
	if len(svcs) != 1 || svc == nil {
		t.Fatalf("services = %v, want one for the claim", svcs)
	}
	if len(svc.Spec.IPFamilies) != 2 || *svc.Spec.IPFamilyPolicy != corev1.IPFamilyPolicyRequireDualStack {
		t.Errorf("service families = %v %v, want dual-stack", svc.Spec.IPFamilies, *svc.Spec.IPFamilyPolicy)
	}
	if svc.Annotations[addressClaimAnnotation] != "dual" {
		t.Errorf("claim annotation = %q, want dual", svc.Annotations[addressClaimAnnotation])
	}
	setIngress(t, c, svc, "203.0.113.9", "2001:db8::9")
	g := reconcileNATGateway(t, s, c, "t", "egress")
	if g.Status.Address != "203.0.113.9" || g.Status.Address6 != "2001:db8::9" {
		t.Errorf("addresses = %q/%q", g.Status.Address, g.Status.Address6)
	}
}

// A Dual claim named only in addressClaimName still gets a dual-stack Service,
// and only its IPv4 address is served.
func TestNATGatewayDualClaimInV4FieldServesV4Only(t *testing.T) {
	s := claimScheme(t)
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24", "fd00::/64"),
		natgw("t", "egress", "v", "dual", ""), ipClaim("t", "dual", "Bound", "203.0.113.9", "2001:db8::9"))
	reconcileNATGateway(t, s, c, "t", "egress")
	svc := ngwServices(t, c, "t", "egress")["dual"]
	if svc == nil || len(svc.Spec.IPFamilies) != 2 {
		t.Fatalf("service = %+v, want a dual-stack Service for the Dual claim", svc)
	}
	setIngress(t, c, svc, "203.0.113.9", "2001:db8::9")
	g := reconcileNATGateway(t, s, c, "t", "egress")
	if g.Status.Address != "203.0.113.9" || g.Status.Address6 != "" {
		t.Errorf("addresses = %q/%q, want v4 only", g.Status.Address, g.Status.Address6)
	}
}

// Each failure mode of docs/vpc-egress.md §2.1 is reported by its reason.
func TestNATGatewayClaimFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		c4, c6 string
		cidrs  []string
		claims []client.Object
		want   string
	}{
		{"v6-only claim in the v4 field", "only6", "", []string{"10.0.0.0/24"},
			[]client.Object{ipClaim("t", "only6", "Bound", "2001:db8::1")}, sdnv1alpha1.NATGatewayReasonClaimFamilyMissing},
		{"missing claim", "nope", "", []string{"10.0.0.0/24"}, nil, sdnv1alpha1.NATGatewayReasonClaimNotFound},
		{"pending claim", "wait", "", []string{"10.0.0.0/24"},
			[]client.Object{ipClaim("t", "wait", "Pending")}, sdnv1alpha1.NATGatewayReasonClaimNotBound},
		{"v6 field on a v4-only VPC", "", "c6", []string{"10.0.0.0/24"},
			[]client.Object{ipClaim("t", "c6", "Bound", "2001:db8::1")}, sdnv1alpha1.NATGatewayReasonFamilyNotInVPC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := claimScheme(t)
			objs := append([]client.Object{vpcWithCIDRs("t", "v", 100, tc.cidrs...), natgw("t", "egress", "v", tc.c4, tc.c6)}, tc.claims...)
			c := egressClient(t, s, objs...)
			g := reconcileNATGateway(t, s, c, "t", "egress")
			cond := addrCond(g)
			if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != tc.want {
				t.Errorf("AddressAssigned = %+v, want False/%s", cond, tc.want)
			}
			if n := len(ngwServices(t, c, "t", "egress")); n != 0 {
				t.Errorf("services = %d, want none", n)
			}
		})
	}
}

// Without the claim API, a set field gets a single-family Service carrying the
// (inert) annotation, and the LB implementation assigns.
// A claimed Service whose assigned address is not the claim's (the driver did
// not pin it, e.g. the claim is attached to another Service) yields no address:
// it is neither published nor announced.
func TestNATGatewayClaimNotAttached(t *testing.T) {
	s := claimScheme(t)
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"),
		natgw("t", "egress", "v", "c4", ""), ipClaim("t", "c4", "Bound", "203.0.113.9"),
		natNode("a", "10.1.0.1", "a1", true))
	reconcileNATGateway(t, s, c, "t", "egress")
	svc := ngwServices(t, c, "t", "egress")["c4"]
	setIngress(t, c, svc, "203.0.113.50")
	g := reconcileNATGateway(t, s, c, "t", "egress")
	if cond := addrCond(g); g.Status.Address != "" || cond == nil || cond.Reason != sdnv1alpha1.NATGatewayReasonClaimNotAttached {
		t.Errorf("address %q, AddressAssigned %+v, want none and ClaimNotAttached", g.Status.Address, cond)
	}
	eps := &discoveryv1.EndpointSlice{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: svc.Name + "-v4"}, eps); err == nil {
		t.Errorf("EndpointSlice %+v exists, want none for a foreign address", eps.Endpoints)
	}

	setIngress(t, c, svc, "203.0.113.9")
	if g = reconcileNATGateway(t, s, c, "t", "egress"); g.Status.Address != "203.0.113.9" {
		t.Errorf("address = %q, want the claim's once the Service holds it", g.Status.Address)
	}
}

func TestNATGatewayClaimAPIMissing(t *testing.T) {
	s := egressScheme(t)
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24", "fd00::/64"), natgw("t", "egress", "v", "c4", ""))
	// A real API server answers an uninstalled kind with NoKindMatch; the fake
	// client says NotFound, so say it for it.
	noClaimAPI := interceptor.NewClient(c.(client.WithWatch), interceptor.Funcs{
		Get: func(ctx context.Context, cl client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if u, ok := obj.(*unstructured.Unstructured); ok && u.GroupVersionKind() == ipAddressClaimGVK {
				return &meta.NoKindMatchError{GroupKind: ipAddressClaimGVK.GroupKind()}
			}
			return cl.Get(ctx, key, obj, opts...)
		},
	})
	r := &NATGatewayReconciler{Client: c, Scheme: s, Reader: noClaimAPI}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "t", Name: "egress"}}); err != nil {
		t.Fatal(err)
	}
	svcs := ngwServices(t, c, "t", "egress")
	if len(svcs) != 1 {
		t.Fatalf("services = %v, want one", svcs)
	}
	for _, svc := range svcs {
		if len(svc.Spec.IPFamilies) != 1 || svc.Spec.IPFamilies[0] != corev1.IPv4Protocol || svc.Annotations[addressClaimAnnotation] != "c4" {
			t.Errorf("service = %v %v, want single-stack IPv4 annotated c4", svc.Spec.IPFamilies, svc.Annotations)
		}
	}
}

// A NAT gateway owned by a VPCGateway adopts the gateway's NAT Service, so the
// egress address survives the transition (docs/vpc-egress.md §7).
func TestNATGatewayAdoptsVPCGatewayService(t *testing.T) {
	s := egressScheme(t)
	gw := natGateway("t", "door", "v")
	gw.UID = "gw-uid"
	ngw := natgw("t", "door", "v", "", "")
	if err := controllerutil.SetControllerReference(gw, ngw, s); err != nil {
		t.Fatal(err)
	}
	old := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "door-v4-abc", Namespace: "t",
			Labels: map[string]string{vpcGatewayLabel: "door", addressFamilyLabel: "IPv4"}},
		Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, IPFamilies: []corev1.IPFamily{corev1.IPv4Protocol}},
		Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{
			Ingress: []corev1.LoadBalancerIngress{{IP: "203.0.113.5"}}}},
	}
	if err := controllerutil.SetControllerReference(gw, old, s); err != nil {
		t.Fatal(err)
	}
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), gw, ngw, old)
	g := reconcileNATGateway(t, s, c, "t", "door")
	if g.Status.Address != "203.0.113.5" {
		t.Errorf("address = %q, want the adopted Service's 203.0.113.5", g.Status.Address)
	}
	svc := ngwServices(t, c, "t", "door")["dynamic-IPv4"]
	if svc == nil || svc.Name != "door-v4-abc" || !metav1.IsControlledBy(svc, g) {
		t.Errorf("adopted service = %+v, want door-v4-abc owned by the NATGateway", svc)
	}
}

// Ids are cluster-unique; leases count into the capacity condition.
func TestNATGatewayIDsAndCapacity(t *testing.T) {
	s := egressScheme(t)
	a := natgw("t", "a", "v", "", "")
	a.Status.ID = 1
	b := natgw("t", "b", "v", "", "")
	lease := &localsdnv1alpha1.NATPortBlock{
		ObjectMeta: metav1.ObjectMeta{Name: "uid-b.0", Labels: map[string]string{localsdnv1alpha1.LabelNATGatewayUID: "uid-b"}},
		Spec:       localsdnv1alpha1.NATPortBlockSpec{Block: 0, Node: "n1"},
	}
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), a, b, lease)
	r := &NATGatewayReconciler{Client: c, Scheme: s, BlockSize: 32256} // two blocks
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "t", Name: "b"}}); err != nil {
		t.Fatal(err)
	}
	got := &sdnv1alpha1.NATGateway{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: "b"}, got); err != nil {
		t.Fatal(err)
	}
	if got.Status.ID != 2 {
		t.Errorf("id = %d, want 2 (1 is taken)", got.Status.ID)
	}
	if got.Status.Blocks != (sdnv1alpha1.NATGatewayBlocks{Leased: 1, Free: 1}) {
		t.Errorf("blocks = %+v, want 1 leased, 1 free", got.Status.Blocks)
	}
	cap := meta.FindStatusCondition(got.Status.Conditions, sdnv1alpha1.NATGatewayConditionCapacityAvailable)
	if cap == nil || cap.Status != metav1.ConditionTrue {
		t.Errorf("CapacityAvailable = %+v, want True", cap)
	}
}
