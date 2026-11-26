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
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// A new generation whose computed status is unchanged must still be restamped
// on every condition, or a reader cannot tell the status is current.
func TestControllersRestampObservedGeneration(t *testing.T) {
	cases := []struct {
		name  string
		ns    string
		setup func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object)
	}{
		{"NATGateway", "t", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			s := egressScheme(t)
			c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), natgw("t", "egress", "v", "", ""))
			return c, &NATGatewayReconciler{Client: c, Scheme: s}, &sdnv1alpha1.NATGateway{}
		}},
		{"VPCPeering", "t", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			c := peeringClient(t,
				nsVPCWithVNI("t", "vpc-a", 100),
				nsVPCWithVNI("team-b", "vpc-b", 101),
				peeringHalf("t", "egress", "vpc-a", "team-b", "vpc-b"),
				peeringHalf("team-b", "to-a", "vpc-b", "t", "vpc-a"))
			return c, &VPCPeeringReconciler{Client: c}, &sdnv1alpha1.VPCPeering{}
		}},
		{"VPCGateway", "t", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			c := gwClient(t, vpcWithCIDRs("t", "vpc-a", 100, "10.10.0.0/24"), natGateway("t", "egress", "vpc-a"))
			return c, &VPCGatewayReconciler{Client: c, Scheme: gatewayScheme(t)}, &sdnv1alpha1.VPCGateway{}
		}},
		{"RouteTable", "t", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			s := egressScheme(t)
			c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), &sdnv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: "egress", Namespace: "t", UID: "egress"},
				Spec:       sdnv1alpha1.RouteTableSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "v"}, Default: true},
			})
			return c, &RouteTableReconciler{Client: c}, &sdnv1alpha1.RouteTable{}
		}},
		{"Route", "t", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			s := egressScheme(t)
			rt := route("egress", "main", "0.0.0.0/0", toBlackhole, 0)
			c := egressClient(t, s, &rt)
			return c, &RouteReconciler{Client: c}, &sdnv1alpha1.Route{}
		}},
		{"PortClaim", "tenant", func(t *testing.T) (client.Client, reconcile.Reconciler, client.Object) {
			r := newPCReconciler(t, newPortClaim("egress", "u1"), claimedPortOn("egress", "u1", "node-a", "pod-a"))
			return r.Client, r, &sdnv1alpha1.PortClaim{}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, r, obj := tc.setup(t)
			ctx := context.Background()
			key := types.NamespacedName{Namespace: tc.ns, Name: "egress"}
			run := func() {
				t.Helper()
				if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
					t.Fatalf("reconcile: %v", err)
				}
				if err := c.Get(ctx, key, obj); err != nil {
					t.Fatalf("get: %v", err)
				}
			}
			run()
			run() // settled: the next reconcile computes the same status

			// The apiserver bumps the generation on a spec change; the fake client
			// does not, and no spec change is needed to leave the status unchanged.
			obj.SetGeneration(obj.GetGeneration() + 1)
			if err := c.Update(ctx, obj); err != nil {
				t.Fatalf("bump generation: %v", err)
			}
			want := obj.GetGeneration()
			run()

			conds := statusConditions(obj)
			if len(conds) == 0 {
				t.Fatal("test is broken: the status carries no condition")
			}
			for _, cond := range conds {
				if cond.ObservedGeneration != want {
					t.Errorf("condition %s observedGeneration = %d, want %d", cond.Type, cond.ObservedGeneration, want)
				}
			}
		})
	}
}

func statusConditions(obj client.Object) []metav1.Condition {
	switch o := obj.(type) {
	case *sdnv1alpha1.NATGateway:
		return o.Status.Conditions
	case *sdnv1alpha1.VPCPeering:
		return o.Status.Conditions
	case *sdnv1alpha1.VPCGateway:
		return o.Status.Conditions
	case *sdnv1alpha1.RouteTable:
		return o.Status.Conditions
	case *sdnv1alpha1.Route:
		return o.Status.Conditions
	case *sdnv1alpha1.PortClaim:
		return o.Status.Conditions
	}
	return nil
}
