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
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// VPCGatewayReconciler owns a VPCGateway's status: does its VPC exist, is it the
// VPC's *only* gateway, and what NAT identity did its owned Services draw
// (docs/north-south.md; docs/external-addresses.md §5).
//
// It realizes nothing itself. The gateway pod is GatewayReconciler's job, the
// LoadBalancer-ingress gate is the agent's, and the counters are the datapath's —
// what this controller establishes is whether the boundary is legitimate, which
// all three of them then read.
type VPCGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch;create;update;patch;delete

// Reconcile computes the gateway's phase and conditions.
func (r *VPCGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &sdnv1alpha1.VPCGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	vpcOK := false
	vpc := &sdnv1alpha1.VPC{}
	if name := gw.Spec.VPCRef.Name; name != "" {
		err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, vpc)
		vpcOK = err == nil
		if err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
		}
	}

	conflict, err := r.conflictingGateway(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	exclusive := conflict == ""

	// The VPC's egress identity: an address of its OWN, drawn from a delegated
	// Service (one per family), not a pool. Without one, its traffic is SNATed to the
	// node's address and the tenant is indistinguishable from the platform on the
	// wire (docs/north-south.md, tenet 8; docs/external-addresses.md §5). A losing
	// (non-exclusive) gateway owns no Service — it realizes nothing.
	// nat.enabled is realized as a NATGateway, a default RouteTable and default
	// Routes the gateway owns (docs/vpc-egress.md §7); the NAT addresses are the
	// NAT gateway's, mirrored here. A losing (non-exclusive) gateway realizes
	// nothing.
	natAddr, natAddr6, problem := "", "", ""
	if exclusive && gw.Spec.NAT.Enabled && vpcOK {
		v4, v6, p, err := r.ensureEgress(ctx, gw)
		if err != nil {
			return ctrl.Result{}, err
		}
		natAddr, natAddr6, problem = v4, v6, p
	} else if err := r.deleteEgress(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}

	status := sdnv1alpha1.VPCGatewayStatus{
		Phase:       sdnv1alpha1.VPCGatewayPhasePending,
		NATAddress:  natAddr,
		NATAddress6: natAddr6,
		Conditions:  append([]metav1.Condition(nil), gw.Status.Conditions...),
	}
	setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionVPCResolved, vpcOK,
		"VPCResolved", "spec.vpcRef names a VPC in this namespace")
	natReady := !gw.Spec.NAT.Enabled || natAddr != "" || natAddr6 != ""
	if problem != "" {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionNATReady, false, "NameTaken", problem)
	} else if natReady {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionNATReady, true,
			"NATReady", "NAT egress has an eBPF identity (or is disabled)")
	} else {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionNATReady, false,
			"NATAddressPending",
			"the VPC's NAT address is not yet assigned; egress falls back to the gateway pod")
	}
	if exclusive {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionExclusive, true,
			"Exclusive", "this is the VPC's only gateway")
	} else {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionExclusive, false,
			"GatewayConflict",
			fmt.Sprintf("VPCGateway %q is already this VPC's boundary; a VPC has exactly one", conflict))
	}
	if vpcOK && exclusive {
		status.Phase = sdnv1alpha1.VPCGatewayPhaseReady
	}

	if gwStatusEqual(gw.Status, status) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	gw.Status = status
	if err := r.Status().Update(ctx, gw); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPCGateway status: %w", err)
	}
	logger.Info("VPCGateway status updated", "vpcgateway", req.NamespacedName.String(), "phase", status.Phase)
	return ctrl.Result{}, nil
}

// conflictingGateway returns the name of an older VPCGateway that already binds
// this one's VPC, or "" when this gateway owns it. A VPC has exactly one boundary
// — that is what makes "everything crosses it" checkable and the per-VPC counters
// unambiguous. First writer wins, ties broken by name so replicas agree.
func (r *VPCGatewayReconciler) conflictingGateway(ctx context.Context, gw *sdnv1alpha1.VPCGateway) (string, error) {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
		return "", fmt.Errorf("list VPCGateways: %w", err)
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == gw.Name ||
			other.Spec.VPCRef.Name != gw.Spec.VPCRef.Name ||
			!other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.CreationTimestamp.Time.Before(gw.CreationTimestamp.Time) ||
			(other.CreationTimestamp.Equal(&gw.CreationTimestamp) && other.Name < gw.Name) {
			return other.Name, nil
		}
	}
	return "", nil
}

// Labels on a VPCGateway's owned NAT-identity Services (docs/external-addresses.md §5).
const (
	// vpcGatewayLabel links an owned Service back to its VPCGateway (the Service uses
	// generateName, so cozyplane finds its own Services by this label).
	vpcGatewayLabel = "sdn.cozystack.io/vpc-gateway"
	// addressFamilyLabel disambiguates a gateway's per-family Services ("IPv4"/"IPv6").
	addressFamilyLabel = "sdn.cozystack.io/address-family"
)

func familyLabelValue(f corev1.IPFamily) string {
	if f == corev1.IPv6Protocol {
		return "IPv6"
	}
	return "IPv4"
}

func familyShort(f corev1.IPFamily) string {
	if f == corev1.IPv6Protocol {
		return "v6"
	}
	return "v4"
}

// egressRouteName is the name of the default route the transition creates for
// a family (docs/vpc-egress.md §7).
func egressRouteName(gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily) string {
	return gw.Name + "-default-" + strings.ToLower(familyLabelValue(f))
}

// ensureEgress realizes nat.enabled as the objects of docs/vpc-egress.md §7: a
// NATGateway named after the VPCGateway, a default RouteTable if the VPC has
// none, and a default route per family the NAT gateway holds an address for.
// It returns the NAT gateway's addresses, which VPCGateway status mirrors, and
// a non-empty problem when an object it needs is taken by someone else.
func (r *VPCGatewayReconciler) ensureEgress(ctx context.Context, gw *sdnv1alpha1.VPCGateway) (v4, v6, problem string, err error) {
	ngw := &sdnv1alpha1.NATGateway{}
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	switch err := r.Get(ctx, key, ngw); {
	case apierrors.IsNotFound(err):
		ngw = &sdnv1alpha1.NATGateway{
			ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace},
			Spec: sdnv1alpha1.NATGatewaySpec{
				VPCRef:            gw.Spec.VPCRef,
				LoadBalancerClass: gw.Spec.LoadBalancerClass,
				AddressClaimName:  gw.Spec.NAT.AddressClaimName,
				AddressClaimName6: gw.Spec.NAT.AddressClaimName6,
			},
		}
		if err := controllerutil.SetControllerReference(gw, ngw, r.Scheme); err != nil {
			return "", "", "", err
		}
		if err := r.Create(ctx, ngw); err != nil {
			return "", "", "", fmt.Errorf("create NATGateway: %w", err)
		}
	case err != nil:
		return "", "", "", fmt.Errorf("fetch NATGateway: %w", err)
	case !metav1.IsControlledBy(ngw, gw):
		return "", "", fmt.Sprintf("NATGateway %q exists and is not this VPCGateway's", gw.Name), nil
	case ngw.Spec.VPCRef != gw.Spec.VPCRef:
		// vpcRef is immutable: a VPCGateway re-pointed at another VPC gets a
		// new NAT gateway.
		if err := r.Delete(ctx, ngw); err != nil && !apierrors.IsNotFound(err) {
			return "", "", "", fmt.Errorf("delete NATGateway of the previous VPC: %w", err)
		}
		return "", "", "", nil
	default:
		want := sdnv1alpha1.NATGatewaySpec{
			VPCRef:            gw.Spec.VPCRef,
			LoadBalancerClass: gw.Spec.LoadBalancerClass,
			AddressClaimName:  gw.Spec.NAT.AddressClaimName,
			AddressClaimName6: gw.Spec.NAT.AddressClaimName6,
		}
		if ngw.Spec != want {
			ngw.Spec = want
			if err := r.Update(ctx, ngw); err != nil {
				return "", "", "", fmt.Errorf("update NATGateway: %w", err)
			}
		}
	}

	var tables sdnv1alpha1.RouteTableList
	if err := r.List(ctx, &tables, client.InNamespace(gw.Namespace)); err != nil {
		return "", "", "", fmt.Errorf("list RouteTables: %w", err)
	}
	tableName := ""
	if eff := effectiveDefaultTable(tables.Items, gw.Spec.VPCRef.Name); eff != nil {
		tableName = eff.Name
	} else {
		rt := &sdnv1alpha1.RouteTable{}
		switch err := r.Get(ctx, key, rt); {
		case apierrors.IsNotFound(err):
			rt = &sdnv1alpha1.RouteTable{
				ObjectMeta: metav1.ObjectMeta{Name: gw.Name, Namespace: gw.Namespace},
				Spec:       sdnv1alpha1.RouteTableSpec{VPCRef: gw.Spec.VPCRef, Default: true},
			}
			if err := controllerutil.SetControllerReference(gw, rt, r.Scheme); err != nil {
				return "", "", "", err
			}
			if err := r.Create(ctx, rt); err != nil {
				return "", "", "", fmt.Errorf("create default RouteTable: %w", err)
			}
		case err != nil:
			return "", "", "", fmt.Errorf("fetch RouteTable: %w", err)
		case !metav1.IsControlledBy(rt, gw):
			return "", "", fmt.Sprintf("the VPC has no default RouteTable and RouteTable %q is not this VPCGateway's", gw.Name), nil
		}
		tableName = gw.Name
	}

	addrs := map[corev1.IPFamily]string{corev1.IPv4Protocol: ngw.Status.Address, corev1.IPv6Protocol: ngw.Status.Address6}
	dests := map[corev1.IPFamily]string{corev1.IPv4Protocol: "0.0.0.0/0", corev1.IPv6Protocol: "::/0"}
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		if err := r.ensureDefaultRoute(ctx, gw, f, tableName, dests[f], addrs[f] != ""); err != nil {
			return "", "", "", err
		}
	}
	return ngw.Status.Address, ngw.Status.Address6, "", nil
}

// ensureDefaultRoute makes the transition's default route of one family exist
// (in the VPC's default table) when the NAT gateway has an address of that
// family, and not exist otherwise — so a family without an address still
// reaches the gateway pod (docs/vpc-egress.md §3.1 step 4).
func (r *VPCGatewayReconciler) ensureDefaultRoute(ctx context.Context, gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily, table, dest string, want bool) error {
	route := &sdnv1alpha1.Route{}
	key := types.NamespacedName{Namespace: gw.Namespace, Name: egressRouteName(gw, f)}
	err := r.Get(ctx, key, route)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("fetch default Route: %w", err)
	}
	exists := err == nil
	if exists && !metav1.IsControlledBy(route, gw) {
		return nil // someone else's route of that name: leave it
	}
	if exists && (!want || route.Spec.RouteTableRef.Name != table) {
		// routeTableRef is immutable: a moved default table means a new route.
		if err := r.Delete(ctx, route); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete default Route: %w", err)
		}
		exists = false
	}
	if !want || exists {
		return nil
	}
	route = &sdnv1alpha1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: gw.Namespace},
		Spec: sdnv1alpha1.RouteSpec{
			RouteTableRef: sdnv1alpha1.LocalRouteTableRef{Name: table},
			Destination:   dest,
			Target:        sdnv1alpha1.RouteTarget{NATGateway: &sdnv1alpha1.LocalNATGatewayRef{Name: gw.Name}},
		},
	}
	if err := controllerutil.SetControllerReference(gw, route, r.Scheme); err != nil {
		return err
	}
	if err := r.Create(ctx, route); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create default Route: %w", err)
	}
	return nil
}

// deleteEgress removes what ensureEgress created, and any NAT Service a
// VPCGateway owned before NAT gateways existed.
func (r *VPCGatewayReconciler) deleteEgress(ctx context.Context, gw *sdnv1alpha1.VPCGateway) error {
	key := types.NamespacedName{Namespace: gw.Namespace, Name: gw.Name}
	objs := []client.Object{&sdnv1alpha1.NATGateway{}, &sdnv1alpha1.RouteTable{}}
	keys := []types.NamespacedName{key, key}
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		objs = append(objs, &sdnv1alpha1.Route{})
		keys = append(keys, types.NamespacedName{Namespace: gw.Namespace, Name: egressRouteName(gw, f)})
	}
	for i, o := range objs {
		if err := r.Get(ctx, keys[i], o); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return fmt.Errorf("fetch %T: %w", o, err)
		}
		if !metav1.IsControlledBy(o, gw) {
			continue
		}
		if err := r.Delete(ctx, o); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %T: %w", o, err)
		}
	}
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace), client.MatchingLabels{vpcGatewayLabel: gw.Name}); err != nil {
		return fmt.Errorf("list NAT services: %w", err)
	}
	for i := range list.Items {
		if metav1.IsControlledBy(&list.Items[i], gw) {
			if err := r.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete NAT service: %w", err)
			}
		}
	}
	return nil
}

// setGWCondition goes through meta.SetStatusCondition rather than appending, as
// its FloatingIP twin already did. A bare append left LastTransitionTime unset —
// a field metav1.Condition marks required, so kubectl shows a blank transition
// time, anything computing a condition's age is wrong, and the object would fail
// schema validation outright if this kind ever went back to being CRD-served. It
// also meant two calls with the same Type silently produced two entries.
func setGWCondition(status *sdnv1alpha1.VPCGatewayStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(&status.Conditions, metav1.Condition{
		Type:    condType,
		Status:  st,
		Reason:  reason,
		Message: msg,
	})
}

func gwStatusEqual(a, b sdnv1alpha1.VPCGatewayStatus) bool {
	if a.Phase != b.Phase || a.NATAddress != b.NATAddress || a.NATAddress6 != b.NATAddress6 ||
		len(a.Conditions) != len(b.Conditions) {
		return false
	}
	// By type, not by index: meta.SetStatusCondition owns the ordering now, and
	// a comparison that depends on it would report a spurious difference (and so
	// write status forever) the day a condition is added or reordered. The
	// timestamps are deliberately not compared — they change on every rebuild.
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

// SetupWithManager wires the controller.
func (r *VPCGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCGateway{}).
		Owns(&sdnv1alpha1.NATGateway{}). // re-reconcile when its NAT gateway's addresses fill
		Owns(&sdnv1alpha1.RouteTable{}).
		Owns(&sdnv1alpha1.Route{}).
		Watches(&sdnv1alpha1.RouteTable{}, handler.EnqueueRequestsFromMapFunc(r.mapNamespaceGateways)).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCToGateways)).
		Named("vpcgateway").
		Complete(r)
}

func (r *VPCGatewayReconciler) mapVPCToGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []ctrl.Request
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef.Name == obj.GetName() {
			out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

// mapNamespaceGateways re-reconciles a namespace's gateways when its route
// tables change: the default table decides where the default routes go.
func (r *VPCGatewayReconciler) mapNamespaceGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}
