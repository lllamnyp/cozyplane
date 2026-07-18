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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func gatewayScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := testScheme(t)
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	return s
}

func egressVPC(ns, name string, vni int32, egress bool) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.10.0.0/24"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// natGateway is the VPC's door: a separate object now, because opening one is the
// operator's grant and not a bool a tenant flips on its own VPC
// (docs/north-south.md).
func natGateway(ns, name, vpcName string) *sdnv1alpha1.VPCGateway {
	return &sdnv1alpha1.VPCGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.VPCGatewaySpec{
			VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpcName},
			NAT:    sdnv1alpha1.VPCGatewayNAT{Enabled: true},
		},
	}
}

// dualStackVPC has both a v4 and a v6 CIDR. Its v4 egress is realized in eBPF
// (vpc_nat_snat), but its v6 egress still needs the gateway pod until v6 VPC NAT
// lands (docs/north-south.md §6a, #15).
func dualStackVPC(ns, name string, vni int32) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.10.0.0/24", "fd00:10::/64"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// natGatewayWithAddrs is a gateway already given its eBPF egress identities (v4
// and/or v6) by the VPCGateway controller. The pod is retired only once every
// family the VPC has is covered (docs/north-south.md §6a).
func natGatewayWithAddrs(ns, name, vpcName, v4, v6 string) *sdnv1alpha1.VPCGateway {
	gw := natGateway(ns, name, vpcName)
	gw.Status.NATAddress = v4
	gw.Status.NATAddress6 = v6
	return gw
}

func natGatewayWithAddr(ns, name, vpcName, addr string) *sdnv1alpha1.VPCGateway {
	return natGatewayWithAddrs(ns, name, vpcName, addr, "")
}

func gatewayReconciler(c client.Client) *GatewayReconciler {
	return &GatewayReconciler{
		Client: c,
		Config: GatewayConfig{
			Image:         "img:test",
			Namespace:     "cozy-cozyplane",
			InternalCIDRs: "10.244.0.0/16,10.96.0.0/16",
			ClusterDNS:    "10.96.0.10",
		},
	}
}

func TestGatewayDeploymentCreated(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(egressVPC("team-a", "vpc-a", 100, true), natGateway("team-a", "door", "vpc-a")).Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	dep := &appsv1.Deployment{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, dep); err != nil {
		t.Fatalf("gateway deployment not created: %v", err)
	}
	if got := dep.Spec.Template.Annotations[sdnv1alpha1.AnnotationGatewayFor]; got != "team-a/vpc-a" {
		t.Errorf("gateway-for annotation = %q, want team-a/vpc-a", got)
	}
	if dep.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		t.Errorf("strategy = %q, want Recreate (the .1 Port claim cannot roll)", dep.Spec.Strategy.Type)
	}
	sc := dep.Spec.Template.Spec.Containers[0].SecurityContext
	if sc == nil || sc.Privileged == nil || !*sc.Privileged {
		t.Error("gateway container must be privileged (iptables/sysctls in its own netns)")
	}
}

func TestGatewayNotCreatedWithoutOptIn(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(egressVPC("team-a", "vpc-a", 100, false)).Build() // no VPCGateway: no door
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var list appsv1.DeploymentList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("no deployment expected without spec.egress.natGateway, got %d", len(list.Items))
	}
}

// Disabling egress (or deleting the VPC) removes the Deployment — found by
// labels, since the VNI-derived name is unknowable after VPC deletion.
func TestGatewayDeletedOnDisableAndVPCDeletion(t *testing.T) {
	scheme := gatewayScheme(t)
	vpc := egressVPC("team-a", "vpc-a", 100, true)
	gw := natGateway("team-a", "door", "vpc-a")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpc, gw).Build()
	r := gatewayReconciler(c)
	ctx := context.Background()
	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Close the door.
	gw.Spec.NAT.Enabled = false
	if err := c.Update(ctx, gw); err != nil {
		t.Fatalf("update vpcgateway: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	err := c.Get(ctx, types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("deployment should be deleted when egress is disabled, got %v", err)
	}

	// Re-open, then delete the VPC entirely.
	gw.Spec.NAT.Enabled = true
	if err := c.Update(ctx, gw); err != nil {
		t.Fatalf("update vpcgateway: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Delete(ctx, vpc); err != nil {
		t.Fatalf("delete vpc: %v", err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile after delete: %v", err)
	}
	err = c.Get(ctx, types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("deployment should be deleted with its VPC, got %v", err)
	}
}

// A pure-v4 VPC that has been given its eBPF NAT identity keeps NO pod: vpc_nat_snat
// handles its egress.
func TestGatewayDeletedForV4VPCWithNATIdentity(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(egressVPC("team-a", "vpc-a", 100, true), natGatewayWithAddr("team-a", "door", "vpc-a", "203.0.113.5")).
		Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("a v4 VPC with an eBPF identity must have no gateway pod, got %v", err)
	}
}

// #15 regression: a VPC with a v6 CIDR keeps its gateway pod even after being given
// a (v4) eBPF NAT identity — the pod is the only v6 egress path until v6 VPC NAT
// lands. Deleting it here black-holes v6 (dual-stack hides it: v4 keeps working).
func TestGatewayKeptForV6VPCWithNATIdentity(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(dualStackVPC("team-a", "vpc-a", 100), natGatewayWithAddr("team-a", "door", "vpc-a", "203.0.113.5")).
		Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{}); err != nil {
		t.Fatalf("a dual-stack VPC must keep its gateway pod for v6 egress (#15), but it was gone: %v", err)
	}
}

// v6 VPC NAT (docs/north-south.md §6a): a dual-stack VPC with BOTH a v4 and a v6
// eBPF identity retires the pod — every family is served in eBPF now.
func TestGatewayDeletedForDualStackWithBothIdentities(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(dualStackVPC("team-a", "vpc-a", 100),
			natGatewayWithAddrs("team-a", "door", "vpc-a", "203.0.113.5", "2001:db8::5")).
		Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("a dual-stack VPC with both eBPF identities must have no pod, got %v", err)
	}
}

// A pure-v6 VPC with its own v6 identity also retires the pod.
func TestGatewayDeletedForV6VPCWithV6Identity(t *testing.T) {
	scheme := gatewayScheme(t)
	v6vpc := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "vpc-a", Namespace: "team-a"},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"fd00:10::/64"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: 100},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(v6vpc, natGatewayWithAddrs("team-a", "door", "vpc-a", "", "2001:db8::5")).
		Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "cozyplane-gateway-100"}, &appsv1.Deployment{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("a v6 VPC with its v6 eBPF identity must have no pod, got %v", err)
	}
}

// A Ready gateway pod whose .1 Port vanished (a raced CNI DEL) is severed and
// cannot recover on its own — the heal deletes it so the Deployment recreates
// it and the fresh CNI ADD re-claims the Port.
func TestSeveredGatewayPodIsRecreated(t *testing.T) {
	scheme := gatewayScheme(t)
	vpc := egressVPC("team-a", "vpc-a", 100, true)
	labels := map[string]string{
		sdnv1alpha1.LabelVPC:          "vpc-a",
		sdnv1alpha1.LabelVPCNamespace: "team-a",
	}
	readyPod := func(name string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "cozy-cozyplane", Labels: labels},
			Status: corev1.PodStatus{Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			}},
		}
	}
	gwPort := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v100.10-10-0-1", Labels: labels},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef:  sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"},
			IP:      "10.10.0.1",
			PodName: "gw-healthy",
			Gateway: true,
		},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(vpc, natGateway("team-a", "door", "vpc-a"), readyPod("gw-healthy"), readyPod("gw-severed"), gwPort).Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The pod holding the Port survives; the severed one is deleted.
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "gw-healthy"}, &corev1.Pod{}); err != nil {
		t.Errorf("healthy gateway pod should survive, got %v", err)
	}
	err := c.Get(context.Background(), types.NamespacedName{Namespace: "cozy-cozyplane", Name: "gw-severed"}, &corev1.Pod{})
	if !apierrors.IsNotFound(err) {
		t.Errorf("severed gateway pod should be deleted, got %v", err)
	}
}

func TestGatewayWaitsForVNI(t *testing.T) {
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(egressVPC("team-a", "vpc-a", 0, true), natGateway("team-a", "door", "vpc-a")).Build()
	r := gatewayReconciler(c)

	key := types.NamespacedName{Namespace: "team-a", Name: "vpc-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	var list appsv1.DeploymentList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Items) != 0 {
		t.Errorf("no deployment expected before the VNI is assigned, got %d", len(list.Items))
	}
}
