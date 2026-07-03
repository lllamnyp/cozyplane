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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// FloatingIPReconciler allocates an externally-routable address from an
// ExternalPool to a FloatingIP and surfaces readiness in its status. It
// deliberately does not touch the target VPC: a FloatingIP does not own the
// VPC, so it never enables the gateway on the owner's behalf. If the target
// VPC has no egress gateway, the binding stays Pending with GatewayEnabled=False
// until the VPC owner turns it on.
//
// Allocation reads committed allocations from other FloatingIPs' status; leader
// election serializes the writer, so a plain list-and-pick is race-free. A
// dedicated per-address claim object (à la Port) is a later hardening step.
type FloatingIPReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=externalpools,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch

// Reconcile allocates an address and computes the FloatingIP's phase/conditions.
func (r *FloatingIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	fip := &sdnv1alpha1.FloatingIP{}
	if err := r.Get(ctx, req.NamespacedName, fip); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	pool := r.resolvePool(ctx, fip)

	// The gateway is the anchor a floating IP is realized on. We only observe
	// whether the VPC owner has enabled it — we never enable it ourselves.
	vpc := r.getVPC(ctx, fip.Namespace, fip.Spec.VPCRef.Name)
	gatewayEnabled := vpc != nil && vpc.Spec.Egress != nil && vpc.Spec.Egress.NATGateway

	status := sdnv1alpha1.FloatingIPStatus{
		Phase:   sdnv1alpha1.FloatingIPPhasePending,
		Address: fip.Status.Address,
	}

	addressAssigned := false
	if pool != nil {
		addr, err := r.ensureAddress(ctx, fip, pool)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.Address = addr
		addressAssigned = addr != ""
	} else {
		// Without a resolvable pool the previously-held address is meaningless.
		status.Address = ""
	}

	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionPoolResolved, pool != nil,
		"PoolResolved", "the referenced (or single default) ExternalPool exists")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionAddressAssigned, addressAssigned,
		"AddressAssigned", "an address was allocated from the pool")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionGatewayEnabled, gatewayEnabled,
		"GatewayEnabled", "the target VPC has spec.egress.natGateway enabled")

	if pool != nil && addressAssigned && gatewayEnabled {
		status.Phase = sdnv1alpha1.FloatingIPPhaseReady
	}

	if fipStatusEqual(fip.Status, status) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = fip.Generation
	}
	fip.Status = status
	if err := r.Status().Update(ctx, fip); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update FloatingIP status: %w", err)
	}

	logger.Info("FloatingIP status updated", "floatingip", req.NamespacedName.String(),
		"phase", status.Phase, "address", status.Address)
	return ctrl.Result{}, nil
}

// resolvePool returns the ExternalPool this FloatingIP allocates from: the one
// named in spec.poolRef, or — when unset — the single pool if exactly one
// exists. Returns nil when the reference is missing or the default is ambiguous.
func (r *FloatingIPReconciler) resolvePool(ctx context.Context, fip *sdnv1alpha1.FloatingIP) *sdnv1alpha1.ExternalPool {
	if name := fip.Spec.PoolRef.Name; name != "" {
		pool := &sdnv1alpha1.ExternalPool{}
		if err := r.Get(ctx, types.NamespacedName{Name: name}, pool); err != nil {
			return nil
		}
		return pool
	}
	var list sdnv1alpha1.ExternalPoolList
	if err := r.List(ctx, &list); err != nil || len(list.Items) != 1 {
		return nil
	}
	return &list.Items[0]
}

// ensureAddress returns the address bound to this FloatingIP, allocating one if
// needed. A valid existing assignment is sticky. A specific spec.address is
// honoured when in-range and free; otherwise the lowest free address is picked.
// Returns "" (stay Pending) when nothing is available.
func (r *FloatingIPReconciler) ensureAddress(ctx context.Context, fip *sdnv1alpha1.FloatingIP, pool *sdnv1alpha1.ExternalPool) (string, error) {
	used, err := r.usedAddresses(ctx, fip)
	if err != nil {
		return "", err
	}

	// Keep the current assignment if it is still in-range and unclaimed.
	if cur := fip.Status.Address; cur != "" && addrInCIDRs(pool.Spec.CIDRs, cur) && !used[cur] {
		return cur, nil
	}
	// A specifically requested address, if available.
	if want := fip.Spec.Address; want != "" {
		if addrInCIDRs(pool.Spec.CIDRs, want) && !used[want] {
			return want, nil
		}
		return "", nil
	}
	return firstFreeAddress(pool.Spec.CIDRs, used), nil
}

// usedAddresses is the set of addresses currently assigned to other
// FloatingIPs (cluster-wide — pools are cluster-scoped).
func (r *FloatingIPReconciler) usedAddresses(ctx context.Context, self *sdnv1alpha1.FloatingIP) (map[string]bool, error) {
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list floatingips: %w", err)
	}
	used := make(map[string]bool, len(list.Items))
	for i := range list.Items {
		f := &list.Items[i]
		if f.Namespace == self.Namespace && f.Name == self.Name {
			continue
		}
		if f.Status.Address != "" {
			used[f.Status.Address] = true
		}
	}
	return used, nil
}

func (r *FloatingIPReconciler) getVPC(ctx context.Context, namespace, name string) *sdnv1alpha1.VPC {
	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, vpc); err != nil {
		return nil
	}
	return vpc
}

// addrInCIDRs reports whether ip parses and falls within any of the CIDRs.
func addrInCIDRs(cidrs []string, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(a) {
			return true
		}
	}
	return false
}

// firstFreeAddress returns the lowest address across the CIDRs that is not in
// used, or "" when all are taken.
func firstFreeAddress(cidrs []string, used map[string]bool) string {
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		for addr := p.Masked().Addr(); p.Contains(addr); addr = addr.Next() {
			if s := addr.String(); !used[s] {
				return s
			}
		}
	}
	return ""
}

func setFIPCondition(status *sdnv1alpha1.FloatingIPStatus, condType string, ok bool, reason, message string) {
	cond := metav1.Condition{Type: condType, Status: metav1.ConditionFalse, Reason: reason + "Missing", Message: "not " + message}
	if ok {
		cond.Status = metav1.ConditionTrue
		cond.Reason = reason
		cond.Message = message
	}
	meta.SetStatusCondition(&status.Conditions, cond)
}

// fipStatusEqual compares status ignoring condition timestamps/generation so
// reconciles converge instead of updating forever.
func fipStatusEqual(a, b sdnv1alpha1.FloatingIPStatus) bool {
	if a.Phase != b.Phase || a.Address != b.Address || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

// SetupWithManager registers the reconciler. A FloatingIP must re-reconcile when
// its target VPC changes (gateway toggled), when any ExternalPool changes (pool
// CIDRs), and when another FloatingIP changes (an address may have freed up).
func (r *FloatingIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.FloatingIP{}).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCToFloatingIPs)).
		Watches(&sdnv1alpha1.ExternalPool{}, handler.EnqueueRequestsFromMapFunc(r.mapPoolToFloatingIPs)).
		Watches(&sdnv1alpha1.FloatingIP{}, handler.EnqueueRequestsFromMapFunc(r.mapToPendingFloatingIPs)).
		Named("floatingip").
		Complete(r)
}

// mapVPCToFloatingIPs enqueues FloatingIPs in the changed VPC's namespace that
// target it (their gateway gate depends on the VPC's egress config).
func (r *FloatingIPReconciler) mapVPCToFloatingIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	vpc, ok := obj.(*sdnv1alpha1.VPC)
	if !ok {
		return nil
	}
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list, client.InNamespace(vpc.Namespace)); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range list.Items {
		f := &list.Items[i]
		if f.Spec.VPCRef.Name == vpc.Name {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: f.Namespace, Name: f.Name}})
		}
	}
	return reqs
}

// mapPoolToFloatingIPs enqueues FloatingIPs that resolve to the changed pool —
// those naming it explicitly, plus those relying on the single default pool.
func (r *FloatingIPReconciler) mapPoolToFloatingIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	pool, ok := obj.(*sdnv1alpha1.ExternalPool)
	if !ok {
		return nil
	}
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range list.Items {
		f := &list.Items[i]
		if f.Spec.PoolRef.Name == "" || f.Spec.PoolRef.Name == pool.Name {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: f.Namespace, Name: f.Name}})
		}
	}
	return reqs
}

// mapToPendingFloatingIPs enqueues every not-yet-Ready FloatingIP when any
// FloatingIP changes: a delete (or an address change) may have freed an address
// a Pending binding is waiting for.
func (r *FloatingIPReconciler) mapToPendingFloatingIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range list.Items {
		f := &list.Items[i]
		if f.Status.Phase != sdnv1alpha1.FloatingIPPhaseReady {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: f.Namespace, Name: f.Name}})
		}
	}
	return reqs
}
