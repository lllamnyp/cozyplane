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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	ctrl "sigs.k8s.io/controller-runtime/pkg/reconcile"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func pooledGateway(ns, name, vpcName, poolName string) *sdnv1alpha1.VPCGateway {
	gw := natGateway(ns, name, vpcName)
	gw.Spec.PoolRef = sdnv1alpha1.ExternalPoolRef{Name: poolName}
	return gw
}

func vpcWithCIDRs(ns, name string, vni int32, cidrs ...string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: cidrs},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// reconcileGatewayAddr runs the VPCGateway controller once and returns the
// allocated egress identity (status.NATAddress).
func reconcileGatewayAddr(t *testing.T, objs ...client.Object) string {
	t.Helper()
	scheme := gatewayScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&sdnv1alpha1.VPCGateway{}).
		WithObjects(objs...).Build()
	r := &VPCGatewayReconciler{Client: c}

	key := types.NamespacedName{Namespace: "team-a", Name: "door"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	gw := &sdnv1alpha1.VPCGateway{}
	if err := c.Get(context.Background(), key, gw); err != nil {
		t.Fatalf("get gateway: %v", err)
	}
	return gw.Status.NATAddress
}

// The eBPF NAT identity is v4, so a v4 VPC draws a v4 address from the pool.
func TestNATAddressV4VPC(t *testing.T) {
	got := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "203.0.113.0/24"))
	if got != "203.0.113.0" {
		t.Errorf("v4 VPC NAT address = %q, want 203.0.113.0", got)
	}
}

// #15: a pure-v6 VPC gets NO eBPF identity — vpc_nat_snat cannot serve it — so the
// gateway pod is kept for its v6 egress. Handing it a v4 address here would delete
// the pod and black-hole v6.
func TestNATAddressV6VPCGetsNone(t *testing.T) {
	got := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "fd00:10::/64"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "203.0.113.0/24"))
	if got != "" {
		t.Errorf("v6 VPC must get no eBPF NAT identity, got %q", got)
	}
}

// A dual-stack VPC draws a v4 identity (for its v4 egress), even when the pool's
// lowest range is v6 — the identity must be a family vpc_nat_snat can wear.
func TestNATAddressDualStackDrawsV4(t *testing.T) {
	got := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "2001:db8::/64", "203.0.113.0/24"))
	if got != "203.0.113.0" {
		t.Errorf("dual-stack VPC NAT address = %q, want the v4 203.0.113.0", got)
	}
}
