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

// VPCGatewayReconciler owns a VPCGateway's status: does its VPC exist, does its
// pool exist, and is it the VPC's *only* gateway (docs/north-south.md).
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
	natAddr, natAddr6 := "", ""
	if exclusive && gw.Spec.NAT.Enabled && vpcOK {
		v4, v6, err := r.ensureNATServices(ctx, gw, vpc)
		if err != nil {
			return ctrl.Result{}, err
		}
		natAddr, natAddr6 = v4, v6
	} else if err := r.deleteNATServices(ctx, gw); err != nil {
		return ctrl.Result{}, err
	}

	status := sdnv1alpha1.VPCGatewayStatus{
		Phase:       sdnv1alpha1.VPCGatewayPhasePending,
		NATAddress:  natAddr,
		NATAddress6: natAddr6,
	}
	setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionVPCResolved, vpcOK,
		"VPCResolved", "spec.vpcRef names a VPC in this namespace")
	natReady := !gw.Spec.NAT.Enabled || natAddr != "" || natAddr6 != ""
	if natReady {
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

// ensureNATServices reconciles the VPC's eBPF egress identities: one delegated
// LoadBalancer Service per address family the VPC has, whose assigned address the
// datapath SNATs the VPC's egress to. A family the VPC lacks (or the cluster cannot
// serve a LoadBalancer for) gets no address here, and — per the unchanged pod
// reconciler (gateway_controller.go) — keeps the gateway pod (docs/north-south.md
// §6a, #15). cozyplane allocates nothing; the LB implementation does.
func (r *VPCGatewayReconciler) ensureNATServices(ctx context.Context, gw *sdnv1alpha1.VPCGateway, vpc *sdnv1alpha1.VPC) (v4, v6 string, err error) {
	haveV4, haveV6 := cidrsHaveV4(vpc.Spec.CIDRs), cidrsHaveV6(vpc.Spec.CIDRs)

	if haveV4 {
		if v4, err = r.ensureNATFamilyService(ctx, gw, corev1.IPv4Protocol); err != nil {
			return "", "", err
		}
	} else if err = r.deleteNATFamilyService(ctx, gw, corev1.IPv4Protocol); err != nil {
		return "", "", err
	}

	if haveV6 {
		if v6, err = r.ensureNATFamilyService(ctx, gw, corev1.IPv6Protocol); err != nil {
			return "", "", err
		}
	} else if err = r.deleteNATFamilyService(ctx, gw, corev1.IPv6Protocol); err != nil {
		return "", "", err
	}
	return v4, v6, nil
}

// deleteNATServices removes every NAT-identity Service this gateway owns (both
// families) — used when the gateway is non-exclusive or NAT is disabled.
func (r *VPCGatewayReconciler) deleteNATServices(ctx context.Context, gw *sdnv1alpha1.VPCGateway) error {
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		if err := r.deleteNATFamilyService(ctx, gw, f); err != nil {
			return err
		}
	}
	return nil
}

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

// ownedNATService returns the Service this gateway owns for the given family, or nil.
func (r *VPCGatewayReconciler) ownedNATService(ctx context.Context, gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily) (*corev1.Service, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace), client.MatchingLabels{
		vpcGatewayLabel:    gw.Name,
		addressFamilyLabel: familyLabelValue(f),
	}); err != nil {
		return nil, fmt.Errorf("list NAT services: %w", err)
	}
	for i := range list.Items {
		if metav1.IsControlledBy(&list.Items[i], gw) {
			return &list.Items[i], nil
		}
	}
	return nil, nil
}

// ensureNATFamilyService returns the assigned NAT address for a family, creating the
// gateway's owned single-family LoadBalancer Service if absent and synthesizing its
// advertisement-trigger EndpointSlice once an address is assigned. A cluster that
// cannot serve a LoadBalancer of this family (an IPv6 VPC on a v4-only cluster) yields
// "" — that family keeps the gateway pod (#15).
func (r *VPCGatewayReconciler) ensureNATFamilyService(ctx context.Context, gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily) (string, error) {
	svc, err := r.ownedNATService(ctx, gw, f)
	if err != nil {
		return "", err
	}
	if svc == nil {
		svc = &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName: gw.Name + "-" + familyShort(f) + "-",
				Namespace:    gw.Namespace,
				Labels: map[string]string{
					serviceProxyNameLabel: serviceProxyNameValue,
					vpcGatewayLabel:       gw.Name,
					addressFamilyLabel:    familyLabelValue(f),
				},
			},
			Spec: corev1.ServiceSpec{
				Type:                          corev1.ServiceTypeLoadBalancer,
				ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyCluster,
				AllocateLoadBalancerNodePorts: new(false),
				IPFamilyPolicy:                new(corev1.IPFamilyPolicySingleStack),
				IPFamilies:                    []corev1.IPFamily{f},
				Ports:                         []corev1.ServicePort{{Name: "placeholder", Port: 1, Protocol: corev1.ProtocolTCP}},
			},
		}
		if gw.Spec.LoadBalancerClass != "" {
			svc.Spec.LoadBalancerClass = new(gw.Spec.LoadBalancerClass)
		}
		if err := controllerutil.SetControllerReference(gw, svc, r.Scheme); err != nil {
			return "", err
		}
		if err := r.Create(ctx, svc); err != nil {
			// A cluster that cannot serve a LoadBalancer of this family rejects the
			// Service as Invalid; treat that as "no identity" so the family keeps the
			// gateway pod (#15), rather than failing the whole reconcile.
			if apierrors.IsInvalid(err) {
				log.FromContext(ctx).Info("cluster cannot serve a LoadBalancer of this family; NAT identity falls back to the gateway pod",
					"vpcgateway", client.ObjectKeyFromObject(gw).String(), "family", familyLabelValue(f))
				return "", nil
			}
			return "", fmt.Errorf("create NAT service: %w", err)
		}
	}

	addr := ingressAddress(svc)
	if addr != "" {
		if err := r.ensureNATEndpointSlice(ctx, svc, gw, f, addr); err != nil {
			return "", err
		}
	}
	return addr, nil
}

// ensureNATEndpointSlice reconciles the self-addressed, always-Ready EndpointSlice
// that makes the LB implementation advertise the NAT address. There is no target
// pod — the endpoint is a pure advertisement trigger (MetalLB advertises only a
// Service with a ready endpoint, even under etp: Cluster; docs/external-addresses.md
// §5). Nothing dials it (every proxy skips the Service via service-proxy-name); the
// real reverse path is vpc_nat_reverse on whichever node attracts the address.
func (r *VPCGatewayReconciler) ensureNATEndpointSlice(ctx context.Context, svc *corev1.Service, gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily, addr string) error {
	addrType := discoveryv1.AddressTypeIPv4
	if f == corev1.IPv6Protocol {
		addrType = discoveryv1.AddressTypeIPv6
	}
	if a, err := netip.ParseAddr(addr); err != nil ||
		(a.Is6() && !a.Is4In6()) != (f == corev1.IPv6Protocol) {
		// The assigned address must parse and match the Service's family.
		return nil
	}
	ep := discoveryv1.Endpoint{
		Addresses:  []string{addr},
		Conditions: discoveryv1.EndpointConditions{Ready: new(true)},
	}
	ports := []discoveryv1.EndpointPort{{
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
					vpcGatewayLabel:              gw.Name,
				},
			},
			AddressType: addrType,
			Endpoints:   []discoveryv1.Endpoint{ep},
			Ports:       ports,
		}
		if err := controllerutil.SetControllerReference(svc, slice, r.Scheme); err != nil {
			return err
		}
		if err := r.Create(ctx, slice); err != nil {
			return fmt.Errorf("create NAT endpointslice: %w", err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("get NAT endpointslice: %w", err)
	}
	if existing.AddressType != addrType {
		if err := r.Delete(ctx, existing); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete NAT endpointslice for family change: %w", err)
		}
		return r.ensureNATEndpointSlice(ctx, svc, gw, f, addr)
	}
	existing.Endpoints = []discoveryv1.Endpoint{ep}
	existing.Ports = ports
	if err := r.Update(ctx, existing); err != nil {
		return fmt.Errorf("update NAT endpointslice: %w", err)
	}
	return nil
}

// deleteNATFamilyService removes the gateway's owned Service for a family (its
// EndpointSlice cascades with it) — used when the VPC drops that family.
func (r *VPCGatewayReconciler) deleteNATFamilyService(ctx context.Context, gw *sdnv1alpha1.VPCGateway, f corev1.IPFamily) error {
	svc, err := r.ownedNATService(ctx, gw, f)
	if err != nil || svc == nil {
		return err
	}
	if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NAT service: %w", err)
	}
	return nil
}

func setGWCondition(status *sdnv1alpha1.VPCGatewayStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	status.Conditions = append(status.Conditions, metav1.Condition{
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
	for i := range a.Conditions {
		if a.Conditions[i].Type != b.Conditions[i].Type ||
			a.Conditions[i].Status != b.Conditions[i].Status ||
			a.Conditions[i].Reason != b.Conditions[i].Reason ||
			a.Conditions[i].Message != b.Conditions[i].Message {
			return false
		}
	}
	return true
}

// SetupWithManager wires the controller.
func (r *VPCGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCGateway{}).
		Owns(&corev1.Service{}). // re-reconcile when an owned NAT Service's LB ingress fills
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
