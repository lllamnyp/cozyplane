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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func route(name, table, dst string, target sdnv1alpha1.RouteTarget, age time.Duration) sdnv1alpha1.Route {
	return sdnv1alpha1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "t", UID: types.UID(name),
			CreationTimestamp: metav1.NewTime(time.Unix(1_000_000, 0).Add(-age))},
		Spec: sdnv1alpha1.RouteSpec{RouteTableRef: sdnv1alpha1.LocalRouteTableRef{Name: table}, Destination: dst, Target: target},
	}
}

var (
	toNAT       = sdnv1alpha1.RouteTarget{NATGateway: &sdnv1alpha1.LocalNATGatewayRef{Name: "egress"}}
	toBlackhole = sdnv1alpha1.RouteTarget{Blackhole: &sdnv1alpha1.RouteBlackholeTarget{}}
)

// resolveRoute's verdicts follow docs/vpc-egress.md §3.3.
func TestResolveRoute(t *testing.T) {
	table := &sdnv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: "main", Namespace: "t"},
		Spec:       sdnv1alpha1.RouteTableSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "v"}},
	}
	vpc := vpcWithCIDRs("t", "v", 100, "10.0.0.0/16")
	gw := *natgw("t", "egress", "v", "", "")
	gw.Status.ID = 3
	gw.Status.Address = "203.0.113.7"
	other := *natgw("t", "egress", "other", "", "")
	other.Status.ID = 4
	other.Status.Address = "203.0.113.8"

	for _, tc := range []struct {
		name   string
		r      sdnv1alpha1.Route
		table  *sdnv1alpha1.RouteTable
		vpc    *sdnv1alpha1.VPC
		natgws []sdnv1alpha1.NATGateway
		others []sdnv1alpha1.Route
		want   sdnv1alpha1.RouteState
		reason string
	}{
		{"active NAT route", route("r", "main", "0.0.0.0/0", toNAT, 0), table, vpc, []sdnv1alpha1.NATGateway{gw}, nil,
			sdnv1alpha1.RouteStateActive, "Resolved"},
		{"missing table", route("r", "main", "0.0.0.0/0", toBlackhole, 0), nil, nil, nil, nil,
			sdnv1alpha1.RouteStateUnresolved, "RouteTableNotFound"},
		{"inside the VPC", route("r", "main", "10.0.5.0/24", toBlackhole, 0), table, vpc, nil, nil,
			sdnv1alpha1.RouteStateUnresolved, "InsideVPC"},
		{"the VPC's own CIDR", route("r", "main", "10.0.0.0/16", toBlackhole, 0), table, vpc, nil, nil,
			sdnv1alpha1.RouteStateUnresolved, "InsideVPC"},
		{"missing NAT gateway", route("r", "main", "0.0.0.0/0", toNAT, 0), table, vpc, nil, nil,
			sdnv1alpha1.RouteStateUnresolved, "NATGatewayNotFound"},
		{"NAT gateway of another VPC", route("r", "main", "0.0.0.0/0", toNAT, 0), table, vpc, []sdnv1alpha1.NATGateway{other}, nil,
			sdnv1alpha1.RouteStateUnresolved, "NATGatewayInAnotherVPC"},
		{"no address of the family", route("r", "main", "::/0", toNAT, 0), table, vpc, []sdnv1alpha1.NATGateway{gw}, nil,
			sdnv1alpha1.RouteStateUnresolved, "NoAddressOfFamily"},
		{"older route wins", route("r", "main", "192.0.2.0/24", toBlackhole, 0), table, vpc, nil,
			[]sdnv1alpha1.Route{route("older", "main", "192.0.2.0/24", toBlackhole, time.Hour)},
			sdnv1alpha1.RouteStateConflict, "OlderRouteExists"},
		{"same destination in another table", route("r", "main", "192.0.2.0/24", toBlackhole, 0), table, vpc, nil,
			[]sdnv1alpha1.Route{route("older", "other", "192.0.2.0/24", toBlackhole, time.Hour)},
			sdnv1alpha1.RouteStateActive, "Resolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.r
			got := resolveRoute(&r, tc.table, tc.vpc, tc.natgws, append(tc.others, r))
			if got.state != tc.want || got.reason != tc.reason {
				t.Errorf("verdict = %s/%s (%s), want %s/%s", got.state, got.reason, got.message, tc.want, tc.reason)
			}
		})
	}
}

// Of two tables with spec.default, the older is the VPC's default.
func TestRouteTableDefaultOldestWins(t *testing.T) {
	s := egressScheme(t)
	mk := func(name string, age time.Duration) *sdnv1alpha1.RouteTable {
		return &sdnv1alpha1.RouteTable{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "t", UID: types.UID(name),
				CreationTimestamp: metav1.NewTime(time.Now().Add(-age))},
			Spec: sdnv1alpha1.RouteTableSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "v"}, Default: true},
		}
	}
	c := egressClient(t, s, vpcWithCIDRs("t", "v", 100, "10.0.0.0/24"), mk("first", time.Hour), mk("second", 0))
	r := &RouteTableReconciler{Client: c}
	for _, n := range []string{"first", "second"} {
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "t", Name: n}}); err != nil {
			t.Fatal(err)
		}
	}
	ids := map[int32]bool{}
	for n, want := range map[string]metav1.ConditionStatus{"first": metav1.ConditionTrue, "second": metav1.ConditionFalse} {
		rt := &sdnv1alpha1.RouteTable{}
		if err := c.Get(context.Background(), types.NamespacedName{Namespace: "t", Name: n}, rt); err != nil {
			t.Fatal(err)
		}
		cond := meta.FindStatusCondition(rt.Status.Conditions, sdnv1alpha1.RouteTableConditionDefault)
		if cond == nil || cond.Status != want {
			t.Errorf("%s: Default = %+v, want %s", n, cond, want)
		}
		if rt.Status.ID == 0 || ids[rt.Status.ID] {
			t.Errorf("%s: id %d is zero or shared", n, rt.Status.ID)
		}
		ids[rt.Status.ID] = true
	}
}
