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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// livePort is a Port realizing a tenant IP in a VPC on a node — a running pod
// holds that IP, the FloatingIP liveness gate.
func livePort(vpcNS, vpc, ip, node string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "port-" + ip},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpc},
			IP:     ip,
			Node:   node,
		},
	}
}

func floatingIP(ns, name, vpc, target string) *sdnv1alpha1.FloatingIP {
	return &sdnv1alpha1.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.FloatingIPSpec{
			VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc},
			Target: target,
		},
	}
}

func fipClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(gatewayScheme(t)). // registers client-go (Services) + sdn
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.FloatingIP{}, &corev1.Service{}).
		Build()
}

func reconcileFIP(t *testing.T, c client.Client, ns, name string) *sdnv1alpha1.FloatingIP {
	t.Helper()
	r := &FloatingIPReconciler{Client: c, Scheme: gatewayScheme(t)}
	key := types.NamespacedName{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.FloatingIP{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	return got
}

// ownedFloatingService returns the Service the reconciler created for a FloatingIP.
func ownedFloatingService(t *testing.T, c client.Client, ns, fip string) *corev1.Service {
	t.Helper()
	var list corev1.ServiceList
	if err := c.List(context.Background(), &list, client.InNamespace(ns),
		client.MatchingLabels{floatingIPLabel: fip}); err != nil {
		t.Fatalf("list services: %v", err)
	}
	if len(list.Items) == 0 {
		return nil
	}
	return &list.Items[0]
}

// assignServiceAddress simulates the LB implementation writing an ingress IP.
func assignServiceAddress(t *testing.T, c client.Client, svc *corev1.Service, ip string) {
	t.Helper()
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: ip}}
	if err := c.Status().Update(context.Background(), svc); err != nil {
		t.Fatalf("set service ingress: %v", err)
	}
}

// A FloatingIP creates a delegated Service (its allocation+attraction vehicle) and
// stays Pending until the LB implementation assigns an address. cozyplane allocates
// nothing itself (docs/external-addresses.md).
func TestFloatingIPCreatesDelegatedService(t *testing.T) {
	c := fipClient(t,
		livePort("team-a", "vpc-a", "10.0.0.5", "node-1"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)
	got := reconcileFIP(t, c, "team-a", "web")

	svc := ownedFloatingService(t, c, "team-a", "web")
	if svc == nil {
		t.Fatal("no Service was created for the FloatingIP")
	}
	if svc.Spec.Type != corev1.ServiceTypeLoadBalancer {
		t.Errorf("Service type = %q, want LoadBalancer", svc.Spec.Type)
	}
	if svc.Labels[serviceProxyNameLabel] != serviceProxyNameValue {
		t.Errorf("Service missing service-proxy-name=%s (every proxy must skip its datapath)", serviceProxyNameValue)
	}
	if !metav1.IsControlledBy(svc, got) {
		t.Error("Service must be owner-ref'd to the FloatingIP (so it is GC'd with it)")
	}
	if got.Status.Address != "" {
		t.Errorf("address = %q, want empty before the LB implementation assigns one", got.Status.Address)
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending before an address is assigned", got.Status.Phase)
	}
}

// Once the LB implementation writes the address, the FloatingIP consumes it and
// (with a live target) goes Ready.
func TestFloatingIPReadyWhenServiceGetsAddress(t *testing.T) {
	c := fipClient(t,
		livePort("team-a", "vpc-a", "10.0.0.5", "node-1"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)
	reconcileFIP(t, c, "team-a", "web") // creates the Service
	assignServiceAddress(t, c, ownedFloatingService(t, c, "team-a", "web"), "203.0.113.7")

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Address != "203.0.113.7" {
		t.Errorf("address = %q, want the LB-assigned 203.0.113.7", got.Status.Address)
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhaseReady {
		t.Errorf("phase = %q, want Ready (conditions: %+v)", got.Status.Phase, got.Status.Conditions)
	}
}

// Without a live target the address is held (the Service still gets one) but the
// binding stays Pending — there is no node to deliver to.
func TestFloatingIPPendingWithoutLiveTarget(t *testing.T) {
	c := fipClient(t, floatingIP("team-a", "web", "vpc-a", "10.0.0.5")) // no Port
	reconcileFIP(t, c, "team-a", "web")
	assignServiceAddress(t, c, ownedFloatingService(t, c, "team-a", "web"), "203.0.113.7")

	got := reconcileFIP(t, c, "team-a", "web")
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionTargetLive) {
		t.Error("TargetLive should be False when no pod holds the target IP")
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending without a live target", got.Status.Phase)
	}
	if got.Status.Address == "" {
		t.Error("the address should still be held (assigned to the Service) while Pending on the target")
	}
}

// A Port in a different VPC sharing the target IP does not satisfy liveness —
// delivery is net-scoped, so the match must be VPC + IP.
func TestFloatingIPPendingWhenPortIsInAnotherVPC(t *testing.T) {
	c := fipClient(t,
		livePort("team-a", "vpc-other", "10.0.0.5", "node-1"), // same IP, wrong VPC
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)
	got := reconcileFIP(t, c, "team-a", "web")
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionTargetLive) {
		t.Error("TargetLive should be False: the Port is in a different VPC")
	}
}

// Two FloatingIPs on one target: the loser gets NO Service, so it can never hold an
// address that would break the winner's egress (the 1:1 bijection constraint).
func TestFloatingIPConflictLoserGetsNoService(t *testing.T) {
	// Same creation time in the fake client, so the name tiebreak decides:
	// "web" < "web2", so web wins and web2 loses.
	c := fipClient(t,
		livePort("team-a", "vpc-a", "10.0.0.5", "node-1"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
		floatingIP("team-a", "web2", "vpc-a", "10.0.0.5"),
	)

	reconcileFIP(t, c, "team-a", "web")
	loser := reconcileFIP(t, c, "team-a", "web2")

	if meta.IsStatusConditionTrue(loser.Status.Conditions, sdnv1alpha1.FloatingIPConditionTargetExclusive) {
		t.Error("the newer FloatingIP must not be TargetExclusive on a shared target")
	}
	if svc := ownedFloatingService(t, c, "team-a", "web2"); svc != nil {
		t.Error("a losing FloatingIP must own no Service (no address it could break the winner with)")
	}
	if svc := ownedFloatingService(t, c, "team-a", "web"); svc == nil {
		t.Error("the winner must own its Service")
	}
}
