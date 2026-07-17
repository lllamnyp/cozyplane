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
// allocated egress identities (status.NATAddress, status.NATAddress6).
func reconcileGatewayAddr(t *testing.T, objs ...client.Object) (v4, v6 string) {
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
	return gw.Status.NATAddress, gw.Status.NATAddress6
}

// A v4 VPC draws a v4 identity and no v6 one.
func TestNATAddressV4VPC(t *testing.T) {
	v4, v6 := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "203.0.113.0/24"))
	if v4 != "203.0.113.0" || v6 != "" {
		t.Errorf("v4 VPC identity = (%q, %q), want (203.0.113.0, \"\")", v4, v6)
	}
}

// A pure-v6 VPC with a v6 pool now gets its OWN v6 identity — v6 VPC NAT
// (docs/north-south.md §6a). It no longer launders through the gateway pod.
func TestNATAddressV6VPCGetsV6(t *testing.T) {
	v4, v6 := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "fd00:10::/64"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "2001:db8::/64"))
	if v4 != "" || v6 != "2001:db8::" {
		t.Errorf("v6 VPC identity = (%q, %q), want (\"\", 2001:db8::)", v4, v6)
	}
}

// A v6 VPC with only a v4 pool gets no identity — the pool cannot serve its family,
// so it keeps the gateway pod (the #15 safety, preserved).
func TestNATAddressV6VPCV4PoolGetsNone(t *testing.T) {
	v4, v6 := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "fd00:10::/64"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "203.0.113.0/24"))
	if v4 != "" || v6 != "" {
		t.Errorf("v6 VPC with a v4-only pool must get no identity, got (%q, %q)", v4, v6)
	}
}

// A dual-stack VPC with a dual-family pool draws one identity of EACH family.
func TestNATAddressDualStackDrawsBoth(t *testing.T) {
	v4, v6 := reconcileGatewayAddr(t,
		vpcWithCIDRs("team-a", "vpc-a", 100, "10.10.0.0/24", "fd00:10::/64"),
		pooledGateway("team-a", "door", "vpc-a", "pool"),
		pool("pool", "2001:db8::/64", "203.0.113.0/24"))
	if v4 != "203.0.113.0" || v6 != "2001:db8::" {
		t.Errorf("dual-stack identity = (%q, %q), want (203.0.113.0, 2001:db8::)", v4, v6)
	}
}
