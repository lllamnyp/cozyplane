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
// ExternalPool to a FloatingIP and surfaces readiness in its status. The address
// is reserved permanently, but the binding is Ready — and, downstream, the
// address advertised and programmed — only while the target tenant IP belongs to
// a live Port (a running pod). Without a live target there is no node to
// advertise from, so the address stays reserved but silent (TargetLive=False)
// rather than black-holing traffic. A FloatingIP needs no egress gateway: the
// datapath maps the address straight to the tenant IP in the eBPF bridge.
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
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch

// Reconcile allocates an address and computes the FloatingIP's phase/conditions.
func (r *FloatingIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	fip := &sdnv1alpha1.FloatingIP{}
	if err := r.Get(ctx, req.NamespacedName, fip); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	pool := r.resolvePool(ctx, fip)

	// The address is advertised from, and delivered to, the node hosting the
	// target's Port. A live Port means a running pod holds the target IP — so it
	// is the readiness gate. We never touch the VPC or a gateway.
	targetLive := r.targetHasLivePort(ctx, fip)

	// A floating IP is a BIJECTION, and only the forward half of it is keyed by
	// the public address; the reverse half (floating_egress) is keyed by the
	// target's {net, VPC IP} alone. So two FloatingIPs on one target do not
	// coexist — the second overwrites the first's egress entry, and the first
	// address silently stops working: its client gets a SYN-ACK sourced from the
	// second address and drops it. Nothing in the datapath can detect this, so the
	// conflict is refused here. First writer wins (oldest, then by name for a
	// same-timestamp tie); the loser stays Pending and is never programmed.
	conflict := r.conflictingFIP(ctx, fip)
	exclusive := conflict == ""

	status := sdnv1alpha1.FloatingIPStatus{
		Phase:   sdnv1alpha1.FloatingIPPhasePending,
		Address: fip.Status.Address,
	}

	addressAssigned := false
	switch {
	case !exclusive:
		// Do not even allocate: an address held by a binding that can never be
		// programmed is just a leak.
		status.Address = ""
	case pool != nil:
		addr, err := r.ensureAddress(ctx, fip, pool)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.Address = addr
		addressAssigned = addr != ""
	default:
		// Without a resolvable pool the previously-held address is meaningless.
		status.Address = ""
	}

	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionPoolResolved, pool != nil,
		"PoolResolved", "the referenced (or single default) ExternalPool exists")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionAddressAssigned, addressAssigned,
		"AddressAssigned", "an address was allocated from the pool")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetLive, targetLive,
		"TargetLive", "the target tenant IP belongs to a running pod's Port")
	if exclusive {
		setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetExclusive, true,
			"TargetExclusive", "no other FloatingIP binds this target")
	} else {
		setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetExclusive, false,
			"TargetConflict", fmt.Sprintf("FloatingIP %q already binds target %s; a target takes exactly one floating address", conflict, fip.Spec.Target))
	}

	if pool != nil && addressAssigned && targetLive && exclusive {
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
// resolvePool returns the ExternalPool this FloatingIP draws from — the pool of
// its VPC's GATEWAY (docs/north-south.md § increment 3).
//
// A floating IP is an EIP: an address on the VPC's boundary, associated with a
// Port. So it comes out of the boundary's pool, and a VPC with no gateway gets no
// external address at all — which is tenet 7 ("nothing crosses by default") read
// from the other side, and it makes the `attach` verb on the pool govern EVERY
// address a tenant can wear, not just its NAT identity.
//
// spec.poolRef still wins when set, for the case of a pool an operator granted
// directly; but the gateway is the answer when it is not.
func (r *FloatingIPReconciler) resolvePool(ctx context.Context, fip *sdnv1alpha1.FloatingIP) *sdnv1alpha1.ExternalPool {
	name := fip.Spec.PoolRef.Name
	if name == "" {
		var gws sdnv1alpha1.VPCGatewayList
		if err := r.List(ctx, &gws, client.InNamespace(fip.Namespace)); err != nil {
			return nil
		}
		gw := sdnv1alpha1.EffectiveGateway(gws.Items, fip.Spec.VPCRef.Name)
		if gw == nil {
			return nil // no boundary: no address
		}
		name = gw.Spec.PoolRef.Name
	}
	if name == "" {
		return nil
	}
	pool := &sdnv1alpha1.ExternalPool{}
	if err := r.Get(ctx, types.NamespacedName{Name: name}, pool); err != nil {
		return nil
	}
	return pool
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
	// A VPC's NAT identity comes out of the SAME pools (docs/north-south.md), so a
	// floating address must not be handed an address a gateway already egresses as.
	var gws sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &gws); err != nil {
		return nil, fmt.Errorf("list vpcgateways: %w", err)
	}
	for i := range gws.Items {
		if a := gws.Items[i].Status.NATAddress; a != "" {
			used[a] = true
		}
	}
	return used, nil
}

// targetHasLivePort reports whether a Port realizes the FloatingIP's target IP
// in its VPC — i.e. a running pod holds that tenant IP on some node. Ports are
// cluster-scoped; their VPCRef namespace is the VPC owner's, which for a
// FloatingIP's local vpcRef is the FloatingIP's own namespace.
func (r *FloatingIPReconciler) targetHasLivePort(ctx context.Context, fip *sdnv1alpha1.FloatingIP) bool {
	var list sdnv1alpha1.PortList
	if err := r.List(ctx, &list); err != nil {
		return false
	}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Spec.VPCRef.Namespace == fip.Namespace &&
			p.Spec.VPCRef.Name == fip.Spec.VPCRef.Name &&
			p.Spec.IP == fip.Spec.Target &&
			p.Spec.Node != "" {
			return true
		}
	}
	return false
}

// conflictingFIP returns the name of another FloatingIP that already binds this
// one's target, or "" when this FloatingIP owns the target. First writer wins:
// the older object holds the target, ties broken by name so every replica of the
// controller reaches the same verdict.
//
// The datapath cannot arbitrate this itself — floating_egress is keyed by the
// target's {net, VPC IP}, so the last writer simply wins and the loser's clients
// break silently (see FloatingIPConditionTargetExclusive).
func (r *FloatingIPReconciler) conflictingFIP(ctx context.Context, fip *sdnv1alpha1.FloatingIP) string {
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list, client.InNamespace(fip.Namespace)); err != nil {
		// Fail closed: an unverifiable target is not provably ours, and programming
		// it could break a binding that already works.
		return "unknown (FloatingIP list failed)"
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == fip.Name ||
			other.Spec.VPCRef.Name != fip.Spec.VPCRef.Name ||
			other.Spec.Target != fip.Spec.Target ||
			!other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.CreationTimestamp.Time.Before(fip.CreationTimestamp.Time) ||
			(other.CreationTimestamp.Equal(&fip.CreationTimestamp) && other.Name < fip.Name) {
			return other.Name
		}
	}
	return ""
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

// cidrsHaveV4 / cidrsHaveV6 report whether any CIDR is of that family. The eBPF
// VPC NAT is v4-only (bpf/overlay.c: vpc_nat_snat guards !p.is_v6), so these
// decide whether a VPC gets an eBPF egress identity (v4) or must keep the gateway
// pod for its v6 egress until v6 VPC NAT lands (docs/north-south.md §6a, #15).
func cidrsHaveV4(cidrs []string) bool {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			return true
		}
	}
	return false
}

func cidrsHaveV6(cidrs []string) bool {
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is6() && !p.Addr().Is4In6() {
			return true
		}
	}
	return false
}

// cidrsV4 / cidrsV6 keep only one family's CIDRs, so a NAT identity is drawn from
// an address family the matching eBPF SNAT (vpc_nat_snat / vpc_nat_snat6) can use.
func cidrsV4(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			out = append(out, c)
		}
	}
	return out
}

func cidrsV6(cidrs []string) []string {
	out := make([]string, 0, len(cidrs))
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is6() && !p.Addr().Is4In6() {
			out = append(out, c)
		}
	}
	return out
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
// a Port appears or disappears for its target IP (the liveness gate), when any
// ExternalPool changes (pool CIDRs), and when another FloatingIP changes (an
// address may have freed up).
func (r *FloatingIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.FloatingIP{}).
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(r.mapPortToFloatingIPs)).
		Watches(&sdnv1alpha1.ExternalPool{}, handler.EnqueueRequestsFromMapFunc(r.mapPoolToFloatingIPs)).
		Watches(&sdnv1alpha1.FloatingIP{}, handler.EnqueueRequestsFromMapFunc(r.mapToPendingFloatingIPs)).
		Watches(&sdnv1alpha1.VPCGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayToFloatingIPs)).
		Named("floatingip").
		Complete(r)
}

// mapPortToFloatingIPs enqueues FloatingIPs whose target IP matches the changed
// Port's VPC and IP — their liveness gate turns on/off with the Port.
func (r *FloatingIPReconciler) mapPortToFloatingIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	port, ok := obj.(*sdnv1alpha1.Port)
	if !ok {
		return nil
	}
	// A local vpcRef resolves in the VPC owner's namespace, which is the Port's
	// VPCRef namespace.
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list, client.InNamespace(port.Spec.VPCRef.Namespace)); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range list.Items {
		f := &list.Items[i]
		if f.Spec.VPCRef.Name == port.Spec.VPCRef.Name && f.Spec.Target == port.Spec.IP {
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

// mapGatewayToFloatingIPs re-drives a VPC's floating addresses when its boundary
// changes: the gateway is where their pool comes from.
func (r *FloatingIPReconciler) mapGatewayToFloatingIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	gw, ok := obj.(*sdnv1alpha1.VPCGateway)
	if !ok {
		return nil
	}
	var list sdnv1alpha1.FloatingIPList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
		return nil
	}
	var out []ctrl.Request
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef.Name == gw.Spec.VPCRef.Name {
			out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}
