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

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
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

// FloatingIPReconciler gives a FloatingIP an externally-routable address by owning
// a delegated `Service type: LoadBalancer` — the cluster's LB implementation
// allocates and attracts the address, every proxy skips its datapath
// (`service-proxy-name`), and cozyplane consumes `status.loadBalancer.ingress` and
// programs the floating datapath. cozyplane allocates and attracts nothing
// (docs/external-addresses.md).
//
// The binding is Ready — and the agent programs the datapath — only while the
// target tenant IP belongs to a live Port (a running pod); without one the address
// is held (on the Service) but the binding stays Pending rather than black-holing.
// The address (via a claim) surviving deletion/reservation is the additive claim
// layer, not built here.
type FloatingIPReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=floatingips/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch;create;update;patch;delete

// Reconcile owns the FloatingIP's Service (its allocation+attraction vehicle),
// reads the address the LB implementation assigned, and computes phase/conditions.
// cozyplane allocates and attracts nothing (docs/external-addresses.md).
func (r *FloatingIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	fip := &sdnv1alpha1.FloatingIP{}
	if err := r.Get(ctx, req.NamespacedName, fip); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// The address is delivered to the node hosting the target's Port. A live Port
	// means a running pod holds the target IP — the readiness gate. The node also
	// backs the owned Service's synthesized endpoint (below).
	targetNode := r.targetLiveNode(ctx, fip)
	targetLive := targetNode != ""

	// A floating IP is a BIJECTION, and only the forward half is keyed by the public
	// address; the reverse half (floating_egress) is keyed by the target's {net, VPC
	// IP} alone. So two FloatingIPs on one target do not coexist — the second
	// overwrites the first's egress entry and the first address silently stops
	// working. The datapath cannot detect this, so the conflict is refused here.
	// First writer wins (oldest, then by name); the loser gets no Service and stays
	// Pending.
	conflict := r.conflictingFIP(ctx, fip)
	exclusive := conflict == ""

	// The address comes from a Service this FloatingIP owns: a type: LoadBalancer
	// carrying service-proxy-name, so every proxy skips its datapath while the
	// cluster's LB implementation allocates and attracts the address. A losing
	// binding gets no Service — an address it could never program is a leak.
	var svc *corev1.Service
	var err error
	if exclusive {
		svc, err = r.ensureService(ctx, fip)
		// The LB implementation announces the address only while the owned Service
		// has a ready endpoint (MetalLB gates L2/BGP advertisement on endpoints —
		// verified on dev4). The Service is selectorless, so cozyplane synthesizes
		// one endpoint, ready iff the target Port is live: this makes announcement
		// track liveness (address held but dark when the target is gone), matching
		// the datapath, which only delivers to a live target.
		if err == nil && svc != nil {
			err = r.ensureEndpointSlice(ctx, svc, fip, targetNode)
		}
	} else {
		err = r.deleteOwnedService(ctx, fip) // its owned EndpointSlice cascades with it
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	address := ingressAddress(svc)
	addressAssigned := address != ""

	status := sdnv1alpha1.FloatingIPStatus{
		Phase:   sdnv1alpha1.FloatingIPPhasePending,
		Address: address,
	}

	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionServiceReady, svc != nil,
		"ServiceReady", "the owned LoadBalancer Service exists")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionAddressAssigned, addressAssigned,
		"AddressAssigned", "the load-balancer implementation assigned an address")
	setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetLive, targetLive,
		"TargetLive", "the target tenant IP belongs to a running pod's Port")
	if exclusive {
		setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetExclusive, true,
			"TargetExclusive", "no other FloatingIP binds this target")
	} else {
		setFIPCondition(&status, sdnv1alpha1.FloatingIPConditionTargetExclusive, false,
			"TargetConflict", fmt.Sprintf("FloatingIP %q already binds target %s; a target takes exactly one floating address", conflict, fip.Spec.Target))
	}

	if svc != nil && addressAssigned && targetLive && exclusive {
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

// The labels on a FloatingIP's owned Service (docs/external-addresses.md).
const (
	// serviceProxyNameLabel delegates a Service away from the default proxy —
	// every proxy (kube-proxy, Cilium, cozyplane-kpr) skips a Service that has it.
	serviceProxyNameLabel = "service.kubernetes.io/service-proxy-name"
	// serviceProxyNameValue marks a Service whose datapath cozyplane owns. It must
	// NOT be a name cozyplane-kpr is configured to claim (kpr stays the default
	// proxy, --k8s-service-proxy-name empty, so it skips this Service).
	serviceProxyNameValue = "cozyplane"
	// floatingIPLabel links an owned Service back to its FloatingIP. The Service
	// uses generateName, so cozyplane finds its own Service by this label.
	floatingIPLabel = "sdn.cozystack.io/floating-ip"

	// addressClaimAnnotation is the address-controller's association contract
	// (docs/external-addresses.md §7): set on a Service, it names an
	// IPAddressClaim in the Service's own namespace whose reserved address the
	// claim's driver should pin onto the Service. cozyplane writes only this
	// backend-agnostic key — never a provider's raw pin — and takes no dependency
	// on the claim CRDs (the mechanism is optional; absent, the LB implementation
	// auto-assigns). Mirrors ServiceClaimAnnotation in
	// github.com/lllamnyp/address-controller api/v1alpha1/well_known.go, the
	// authority for this value.
	addressClaimAnnotation = "local.sdn.cozystack.io/ip-address-claim"
)

// reconcileClaimAnnotation makes the Service's association annotation match the
// desired claim name ("" = no association). Returns true if the Service object
// was modified and needs an Update.
func reconcileClaimAnnotation(svc *corev1.Service, claim string) bool {
	current := svc.Annotations[addressClaimAnnotation]
	if current == claim {
		return false
	}
	if claim == "" {
		delete(svc.Annotations, addressClaimAnnotation)
		return true
	}
	if svc.Annotations == nil {
		svc.Annotations = map[string]string{}
	}
	svc.Annotations[addressClaimAnnotation] = claim
	return true
}

// ownedService returns the Service this FloatingIP owns (by label + controller
// owner-ref), or nil if it has none.
func (r *FloatingIPReconciler) ownedService(ctx context.Context, fip *sdnv1alpha1.FloatingIP) (*corev1.Service, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(fip.Namespace),
		client.MatchingLabels{floatingIPLabel: fip.Name}); err != nil {
		return nil, fmt.Errorf("list floating services: %w", err)
	}
	for i := range list.Items {
		if metav1.IsControlledBy(&list.Items[i], fip) {
			return &list.Items[i], nil
		}
	}
	return nil, nil
}

// ensureService returns the FloatingIP's owned Service, creating it if absent. The
// Service is the allocation+attraction vehicle only: cozyplane owns the datapath,
// so it is selectorless and its port is a placeholder. `etp: Cluster` announces the
// address unconditionally (delivery is node-agnostic — from_uplink is at tc ingress).
func (r *FloatingIPReconciler) ensureService(ctx context.Context, fip *sdnv1alpha1.FloatingIP) (*corev1.Service, error) {
	svc, err := r.ownedService(ctx, fip)
	if err != nil {
		return nil, err
	}
	if svc != nil {
		// Reservation (docs/external-addresses.md §7): keep the association
		// annotation in step with spec.addressClaimName; the claim's driver
		// does the pinning.
		if reconcileClaimAnnotation(svc, fip.Spec.AddressClaimName) {
			if err := r.Update(ctx, svc); err != nil {
				return nil, fmt.Errorf("update floating service annotations: %w", err)
			}
		}
		return svc, nil
	}
	svc = &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fip.Name + "-",
			Namespace:    fip.Namespace,
			Labels: map[string]string{
				serviceProxyNameLabel: serviceProxyNameValue,
				floatingIPLabel:       fip.Name,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyCluster,
			AllocateLoadBalancerNodePorts: new(false),
			Ports:                         []corev1.ServicePort{{Name: "placeholder", Port: 1, Protocol: corev1.ProtocolTCP}},
		},
	}
	if fip.Spec.LoadBalancerClass != "" {
		svc.Spec.LoadBalancerClass = new(fip.Spec.LoadBalancerClass)
	}
	reconcileClaimAnnotation(svc, fip.Spec.AddressClaimName)
	if err := controllerutil.SetControllerReference(fip, svc, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, svc); err != nil {
		return nil, fmt.Errorf("create floating service: %w", err)
	}
	return svc, nil
}

// deleteOwnedService removes the FloatingIP's Service — a losing (non-exclusive)
// binding must hold no address.
func (r *FloatingIPReconciler) deleteOwnedService(ctx context.Context, fip *sdnv1alpha1.FloatingIP) error {
	svc, err := r.ownedService(ctx, fip)
	if err != nil || svc == nil {
		return err
	}
	if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete floating service: %w", err)
	}
	return nil
}

// ensureEndpointSlice reconciles the single EndpointSlice that backs the owned
// (selectorless) Service. The endpoint exists only to trigger the LB
// implementation's advertisement — MetalLB (and BGP peers generally) advertise a
// LoadBalancer address only while the Service has a ready endpoint; delivery
// itself is cozyplane's eBPF datapath, not this endpoint (every proxy skips the
// Service via service-proxy-name). The endpoint's address is the target tenant IP
// and its Ready condition tracks the live Port: no live target ⇒ not Ready ⇒ the
// address is allocated but not advertised (held but dark). nodeName carries the
// target's node so a future externalTrafficPolicy: Local can pin advertisement to
// it (source-IP preservation). The slice is owner-ref'd to the Service, so it is
// garbage-collected when the Service is (loser path, or FloatingIP deletion).
func (r *FloatingIPReconciler) ensureEndpointSlice(ctx context.Context, svc *corev1.Service, fip *sdnv1alpha1.FloatingIP, node string) error {
	addr, err := netip.ParseAddr(fip.Spec.Target)
	if err != nil {
		// An unparseable target cannot back an endpoint; leave none (the address
		// stays dark) rather than write an invalid slice.
		return nil
	}
	addrType := discoveryv1.AddressTypeIPv4
	if addr.Is6() && !addr.Is4In6() {
		addrType = discoveryv1.AddressTypeIPv6
	}

	ep := discoveryv1.Endpoint{
		Addresses:  []string{fip.Spec.Target},
		Conditions: discoveryv1.EndpointConditions{Ready: new(node != "")},
	}
	if node != "" {
		ep.NodeName = new(node)
	}
	desiredPorts := []discoveryv1.EndpointPort{{
		Name:     new("placeholder"),
		Port:     new(int32(1)),
		Protocol: new(corev1.ProtocolTCP),
	}}

	key := client.ObjectKey{Namespace: svc.Namespace, Name: svc.Name}
	existing := &discoveryv1.EndpointSlice{}
	switch err := r.Get(ctx, key, existing); {
	case apierrors.IsNotFound(err):
		slice := &discoveryv1.EndpointSlice{
			ObjectMeta: metav1.ObjectMeta{
				Name:      svc.Name,
				Namespace: svc.Namespace,
				Labels: map[string]string{
					discoveryv1.LabelServiceName: svc.Name,
					discoveryv1.LabelManagedBy:   serviceProxyNameValue,
					floatingIPLabel:              fip.Name,
				},
			},
			AddressType: addrType,
			Endpoints:   []discoveryv1.Endpoint{ep},
			Ports:       desiredPorts,
		}
		if err := controllerutil.SetControllerReference(svc, slice, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, slice); err != nil {
			return fmt.Errorf("create endpointslice: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get endpointslice: %w", err)
	}

	// AddressType is immutable; a family change (target edited) needs a recreate.
	if existing.AddressType != addrType {
		if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete endpointslice for family change: %w", err)
		}
		return r.ensureEndpointSlice(ctx, svc, fip, node)
	}
	existing.Endpoints = []discoveryv1.Endpoint{ep}
	existing.Ports = desiredPorts
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("update endpointslice: %w", err)
	}
	return nil
}

// ingressAddress returns the address the LB implementation assigned to the Service,
// or "" if none yet.
func ingressAddress(svc *corev1.Service) string {
	if svc == nil {
		return ""
	}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ing.IP != "" {
			return ing.IP
		}
	}
	return ""
}

// targetLiveNode returns the node whose Port realizes the FloatingIP's target IP
// in its VPC — i.e. a running pod holds that tenant IP there — or "" when no live
// Port exists (the liveness gate is closed). Ports are cluster-scoped; their
// VPCRef namespace is the VPC owner's, which for a FloatingIP's local vpcRef is
// the FloatingIP's own namespace.
func (r *FloatingIPReconciler) targetLiveNode(ctx context.Context, fip *sdnv1alpha1.FloatingIP) string {
	var list sdnv1alpha1.PortList
	if err := r.List(ctx, &list); err != nil {
		return ""
	}
	for i := range list.Items {
		p := &list.Items[i]
		if p.Spec.VPCRef.Namespace == fip.Namespace &&
			p.Spec.VPCRef.Name == fip.Spec.VPCRef.Name &&
			p.Spec.IP == fip.Spec.Target &&
			p.Spec.Node != "" {
			return p.Spec.Node
		}
	}
	return ""
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
// its owned Service changes (the LB implementation fills in the ingress address),
// when a Port appears or disappears for its target IP (the liveness gate, which
// drives the endpoint's Ready condition), and when another FloatingIP changes (a
// target may have freed up).
func (r *FloatingIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.FloatingIP{}).
		Owns(&corev1.Service{}). // re-reconcile when the owned Service's LB ingress is filled
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(r.mapPortToFloatingIPs)).
		Watches(&sdnv1alpha1.FloatingIP{}, handler.EnqueueRequestsFromMapFunc(r.mapToPendingFloatingIPs)).
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
