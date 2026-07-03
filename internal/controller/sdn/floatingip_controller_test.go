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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func pool(name string, cidrs ...string) *sdnv1alpha1.ExternalPool {
	return &sdnv1alpha1.ExternalPool{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       sdnv1alpha1.ExternalPoolSpec{CIDRs: cidrs},
	}
}

// livePort is a Port realizing a tenant IP in a VPC on a node — i.e. a running
// pod holds that IP, which is the FloatingIP liveness gate.
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
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.FloatingIP{}, &sdnv1alpha1.ExternalPool{}).
		Build()
}

func reconcileFIP(t *testing.T, c client.Client, ns, name string) *sdnv1alpha1.FloatingIP {
	t.Helper()
	r := &FloatingIPReconciler{Client: c}
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

// A FloatingIP whose target IP has no running pod reserves its address but stays
// Pending with TargetLive=False — there is no node to advertise from, so the
// address is held, not black-holed.
func TestFloatingIPPendingWithoutLiveTarget(t *testing.T) {
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	) // no Port realizes 10.0.0.5

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending without a live target", got.Status.Phase)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionTargetLive) {
		t.Error("TargetLive should be False when no pod holds the target IP")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionAddressAssigned) {
		t.Error("AddressAssigned should be True: allocation is independent of the target")
	}
	if got.Status.Address == "" {
		t.Error("an address should be reserved even while Pending on the target")
	}
}

// With a live target Port, an address assigned, and the pool resolved, the
// FloatingIP is Ready.
func TestFloatingIPReadyWithLiveTarget(t *testing.T) {
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		livePort("team-a", "vpc-a", "10.0.0.5", "node-1"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhaseReady {
		t.Errorf("phase = %q, want Ready (conditions: %+v)", got.Status.Phase, got.Status.Conditions)
	}
	if got.Status.Address == "" {
		t.Error("a Ready FloatingIP must have an address")
	}
}

// A Port in a different VPC that happens to share the target IP does not satisfy
// liveness — delivery is net-scoped, so the match must be VPC + IP.
func TestFloatingIPPendingWhenPortIsInAnotherVPC(t *testing.T) {
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		livePort("team-a", "vpc-other", "10.0.0.5", "node-1"), // same IP, wrong VPC
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)

	got := reconcileFIP(t, c, "team-a", "web")
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionTargetLive) {
		t.Error("TargetLive should be False: the Port is in a different VPC")
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
}

// No pool → Pending, PoolResolved=False, no address.
func TestFloatingIPPendingWithoutPool(t *testing.T) {
	c := fipClient(t,
		livePort("team-a", "vpc-a", "10.0.0.5", "node-1"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending without a pool", got.Status.Phase)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.FloatingIPConditionPoolResolved) {
		t.Error("PoolResolved should be False with no ExternalPool")
	}
	if got.Status.Address != "" {
		t.Errorf("address = %q, want empty without a pool", got.Status.Address)
	}
}

// Two FloatingIPs from the same pool must get distinct addresses.
func TestFloatingIPAllocatesDistinctAddresses(t *testing.T) {
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
		floatingIP("team-a", "api", "vpc-a", "10.0.0.6"),
	)

	web := reconcileFIP(t, c, "team-a", "web")
	api := reconcileFIP(t, c, "team-a", "api")
	if web.Status.Address == "" || api.Status.Address == "" {
		t.Fatalf("both should be assigned: web=%q api=%q", web.Status.Address, api.Status.Address)
	}
	if web.Status.Address == api.Status.Address {
		t.Errorf("addresses collided: both got %q", web.Status.Address)
	}
}

// A specific requested address is honoured when in-range and free.
func TestFloatingIPHonorsRequestedAddress(t *testing.T) {
	fip := floatingIP("team-a", "web", "vpc-a", "10.0.0.5")
	fip.Spec.Address = "203.0.113.4"
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		fip,
	)

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Address != "203.0.113.4" {
		t.Errorf("address = %q, want the requested 203.0.113.4", got.Status.Address)
	}
}

// A requested address outside the pool leaves the binding Pending, unassigned.
func TestFloatingIPPendingWhenRequestedAddressOutOfRange(t *testing.T) {
	fip := floatingIP("team-a", "web", "vpc-a", "10.0.0.5")
	fip.Spec.Address = "198.51.100.9" // not in the pool
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		fip,
	)

	got := reconcileFIP(t, c, "team-a", "web")
	if got.Status.Address != "" {
		t.Errorf("address = %q, want empty for an out-of-range request", got.Status.Address)
	}
	if got.Status.Phase != sdnv1alpha1.FloatingIPPhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
}

// Allocation is sticky: a second reconcile keeps the same address.
func TestFloatingIPAddressIsSticky(t *testing.T) {
	c := fipClient(t,
		pool("public", "203.0.113.0/29"),
		floatingIP("team-a", "web", "vpc-a", "10.0.0.5"),
	)

	first := reconcileFIP(t, c, "team-a", "web").Status.Address
	second := reconcileFIP(t, c, "team-a", "web").Status.Address
	if first == "" || first != second {
		t.Errorf("address not sticky: first=%q second=%q", first, second)
	}
}
