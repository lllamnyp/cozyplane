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
	"fmt"
	"net/netip"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// maxRouteTableID bounds RouteTable ids (docs/vpc-egress.md §2.2).
const maxRouteTableID = 1<<24 - 1

// older reports whether a was created before b, ties broken by name, so every
// replica picks the same winner.
func older(a, b metav1.Object) bool {
	ta, tb := a.GetCreationTimestamp(), b.GetCreationTimestamp()
	if !ta.Equal(&tb) {
		return ta.Before(&tb)
	}
	return a.GetName() < b.GetName()
}

// effectiveDefaultTable adapts sdnv1alpha1.EffectiveDefaultTable to a list.
func effectiveDefaultTable(tables []sdnv1alpha1.RouteTable, vpcName string) *sdnv1alpha1.RouteTable {
	ptrs := make([]*sdnv1alpha1.RouteTable, len(tables))
	for i := range tables {
		ptrs[i] = &tables[i]
	}
	return sdnv1alpha1.EffectiveDefaultTable(ptrs, vpcName)
}

// RouteTableReconciler allocates each RouteTable's id and reports whether it is
// its VPC's default table.
type RouteTableReconciler struct {
	client.Client
	// Reader reads live, for id allocation.
	Reader client.Reader
}

// Reconcile sets the table's id and conditions.
func (r *RouteTableReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rt := &sdnv1alpha1.RouteTable{}
	if err := r.Get(ctx, req.NamespacedName, rt); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	status := sdnv1alpha1.RouteTableStatus{
		ID:         rt.Status.ID,
		Conditions: append([]metav1.Condition(nil), rt.Status.Conditions...),
	}
	if status.ID == 0 {
		id, err := r.allocateID(ctx, rt)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.ID = id
	}

	vpcOK := true
	if err := r.Get(ctx, types.NamespacedName{Namespace: rt.Namespace, Name: rt.Spec.VPCRef.Name}, &sdnv1alpha1.VPC{}); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
		}
		vpcOK = false
	}
	setCond(&status.Conditions, sdnv1alpha1.RouteTableConditionVPCResolved, vpcOK,
		"VPCResolved", "spec.vpcRef names a VPC in this namespace")

	switch {
	case !rt.Spec.Default:
		setCond(&status.Conditions, sdnv1alpha1.RouteTableConditionDefault, false,
			"NotDefault", "spec.default is false")
	default:
		var list sdnv1alpha1.RouteTableList
		if err := r.List(ctx, &list, client.InNamespace(rt.Namespace)); err != nil {
			return ctrl.Result{}, fmt.Errorf("list RouteTables: %w", err)
		}
		if eff := effectiveDefaultTable(list.Items, rt.Spec.VPCRef.Name); eff != nil && eff.UID != rt.UID {
			setCond(&status.Conditions, sdnv1alpha1.RouteTableConditionDefault, false, "NotOldest",
				fmt.Sprintf("RouteTable %q is the VPC's default table; this one acts as an ordinary table", eff.Name))
		} else {
			setCond(&status.Conditions, sdnv1alpha1.RouteTableConditionDefault, true,
				"Default", "this is the VPC's default table")
		}
	}

	if status.ID == rt.Status.ID && conditionsEqual(status.Conditions, rt.Status.Conditions) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = rt.Generation
	}
	rt.Status = status
	if err := r.Status().Update(ctx, rt); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update RouteTable status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *RouteTableReconciler) allocateID(ctx context.Context, self *sdnv1alpha1.RouteTable) (int32, error) {
	reader := r.Reader
	if reader == nil {
		reader = r.Client
	}
	var list sdnv1alpha1.RouteTableList
	if err := reader.List(ctx, &list); err != nil {
		return 0, fmt.Errorf("list RouteTables: %w", err)
	}
	used := map[int32]bool{}
	for i := range list.Items {
		if list.Items[i].UID != self.UID {
			used[list.Items[i].Status.ID] = true
		}
	}
	for id := int32(1); id <= maxRouteTableID; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free route table id")
}

// SetupWithManager wires the controller. A table's default verdict depends on
// its siblings, so any table change re-reconciles the namespace's tables.
func (r *RouteTableReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.RouteTable{}).
		Watches(&sdnv1alpha1.RouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapSiblings)).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapSiblings)).
		Named("routetable").
		Complete(r)
}

func (r *RouteTableReconciler) mapSiblings(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.RouteTableList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}

// RouteReconciler sets each Route's state (docs/vpc-egress.md §3.3).
type RouteReconciler struct {
	client.Client
}

// routeVerdict is a Route's state and why.
type routeVerdict struct {
	state   sdnv1alpha1.RouteState
	reason  string
	message string
}

// ResolveRoute decides a Route's state from the objects it depends on. tables,
// natgws and routes are the namespace's; vpc is the table's VPC (nil when the
// table or the VPC is missing).
func resolveRoute(rt *sdnv1alpha1.Route, table *sdnv1alpha1.RouteTable, vpc *sdnv1alpha1.VPC,
	natgws []sdnv1alpha1.NATGateway, routes []sdnv1alpha1.Route) routeVerdict {
	dst, err := netip.ParsePrefix(rt.Spec.Destination)
	if err != nil {
		return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "InvalidDestination", err.Error()}
	}
	for i := range routes {
		o := &routes[i]
		if o.UID == rt.UID || o.Spec.RouteTableRef != rt.Spec.RouteTableRef || !o.DeletionTimestamp.IsZero() {
			continue
		}
		if op, err := netip.ParsePrefix(o.Spec.Destination); err == nil && op == dst && older(o, rt) {
			return routeVerdict{sdnv1alpha1.RouteStateConflict, "OlderRouteExists",
				fmt.Sprintf("Route %q in the same table has the same destination and is older", o.Name)}
		}
	}
	if table == nil {
		return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "RouteTableNotFound",
			fmt.Sprintf("RouteTable %q does not exist", rt.Spec.RouteTableRef.Name)}
	}
	if vpc == nil {
		return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "VPCNotFound",
			fmt.Sprintf("the table's VPC %q does not exist", table.Spec.VPCRef.Name)}
	}
	// A route inside the VPC's own CIDR would capture traffic within the VPC.
	// A shorter prefix that contains it (0.0.0.0/0) is fine: the local route is
	// longer, so in-VPC destinations still match it.
	for _, c := range vpc.Spec.CIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && dst.Bits() >= p.Bits() && p.Contains(dst.Addr()) {
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "InsideVPC",
				fmt.Sprintf("the destination lies inside the VPC's own CIDR %s", c)}
		}
	}
	if ng := rt.Spec.Target.NATGateway; ng != nil {
		var gw *sdnv1alpha1.NATGateway
		for i := range natgws {
			if natgws[i].Name == ng.Name {
				gw = &natgws[i]
			}
		}
		switch {
		case gw == nil:
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "NATGatewayNotFound",
				fmt.Sprintf("NATGateway %q does not exist", ng.Name)}
		case gw.Spec.VPCRef.Name != table.Spec.VPCRef.Name:
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "NATGatewayInAnotherVPC",
				fmt.Sprintf("NATGateway %q serves VPC %q, not the table's VPC %q", ng.Name, gw.Spec.VPCRef.Name, table.Spec.VPCRef.Name)}
		case gw.Status.ID == 0:
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "NATGatewayPending",
				fmt.Sprintf("NATGateway %q has no id yet", ng.Name)}
		case dst.Addr().Is4() && gw.Status.Address == "":
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "NoAddressOfFamily",
				fmt.Sprintf("NATGateway %q has no IPv4 address", ng.Name)}
		case !dst.Addr().Is4() && gw.Status.Address6 == "":
			return routeVerdict{sdnv1alpha1.RouteStateUnresolved, "NoAddressOfFamily",
				fmt.Sprintf("NATGateway %q has no IPv6 address", ng.Name)}
		}
	}
	return routeVerdict{sdnv1alpha1.RouteStateActive, "Resolved", "the route is programmed as declared"}
}

// Reconcile sets the Route's state and Resolved condition.
func (r *RouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	rt := &sdnv1alpha1.Route{}
	if err := r.Get(ctx, req.NamespacedName, rt); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ns := client.InNamespace(rt.Namespace)
	var routes sdnv1alpha1.RouteList
	if err := r.List(ctx, &routes, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("list Routes: %w", err)
	}
	var natgws sdnv1alpha1.NATGatewayList
	if err := r.List(ctx, &natgws, ns); err != nil {
		return ctrl.Result{}, fmt.Errorf("list NATGateways: %w", err)
	}
	var table *sdnv1alpha1.RouteTable
	t := &sdnv1alpha1.RouteTable{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: rt.Namespace, Name: rt.Spec.RouteTableRef.Name}, t); err == nil {
		table = t
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("fetch RouteTable: %w", err)
	}
	var vpc *sdnv1alpha1.VPC
	if table != nil {
		v := &sdnv1alpha1.VPC{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: rt.Namespace, Name: table.Spec.VPCRef.Name}, v); err == nil {
			vpc = v
		} else if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
		}
	}

	v := resolveRoute(rt, table, vpc, natgws.Items, routes.Items)
	status := sdnv1alpha1.RouteStatus{
		State:      v.state,
		Conditions: append([]metav1.Condition(nil), rt.Status.Conditions...),
	}
	setCond(&status.Conditions, sdnv1alpha1.RouteConditionResolved, v.state == sdnv1alpha1.RouteStateActive, v.reason, v.message)
	if status.State == rt.Status.State && conditionsEqual(status.Conditions, rt.Status.Conditions) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = rt.Generation
	}
	rt.Status = status
	if err := r.Status().Update(ctx, rt); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update Route status: %w", err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager wires the controller. A Route depends on its siblings (for
// conflicts), its table, the table's VPC and the namespace's NAT gateways, so a
// change to any of them re-reconciles the namespace's Routes.
func (r *RouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	m := handler.EnqueueRequestsFromMapFunc(r.mapNamespace)
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Route{}).
		Watches(&sdnv1alpha1.Route{}, m).
		Watches(&sdnv1alpha1.RouteTable{}, m).
		Watches(&sdnv1alpha1.NATGateway{}, m).
		Watches(&sdnv1alpha1.VPC{}, m).
		Named("route").
		Complete(r)
}

func (r *RouteReconciler) mapNamespace(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.RouteList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}
