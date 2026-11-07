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
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	localsdnv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// DefaultNATBlockSize is the ports per NATPortBlock when the controller is not
// told otherwise (docs/vpc-egress.md §4.3).
const DefaultNATBlockSize = 1008

// Labels on a NAT gateway's owned Services.
const (
	// natGatewayLabel links an owned Service back to its NATGateway.
	natGatewayLabel = "sdn.cozystack.io/nat-gateway"
	// natSlotLabel names which of the NAT gateway's Services this is: the claim
	// it attaches, or "dynamic-IPv4" / "dynamic-IPv6".
	natSlotLabel = "sdn.cozystack.io/nat-slot"
)

// ipAddressClaimGVK is the address-controller's claim. Cozyplane imports nothing
// from it: the NAT gateway reads a claim's status.addresses with a plain GET
// (docs/vpc-egress.md §2.1).
var ipAddressClaimGVK = schema.GroupVersionKind{Group: "local.sdn.cozystack.io", Version: "v1alpha1", Kind: "IPAddressClaim"}

// NATGatewayReconciler owns a NATGateway's status and the LoadBalancer Services
// that obtain its addresses (docs/vpc-egress.md §2.1, §6).
type NATGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	// Reader reads live, for id allocation and for claims.
	Reader client.Reader
	// BlockSize is published in every NAT gateway's status (§4.3).
	BlockSize int
}

// natSlot is one Service the NAT gateway needs.
type natSlot struct {
	key      string            // natSlotLabel value
	claim    string            // "" = dynamic
	families []corev1.IPFamily // the Service's families, v4 first
	serves   []corev1.IPFamily // families whose address the NAT gateway takes from it
}

// natFamilyFailure is why a served family has no address.
type natFamilyFailure struct {
	reason, message string
}

// natClaimInfo is what the controller learned about a named claim.
type natClaimInfo struct {
	apiMissing bool // the claim API is not installed
	found      bool
	bound      bool
	families   []corev1.IPFamily
}

// Reconcile computes the NAT gateway's id, Services, addresses and conditions.
func (r *NATGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ngw := &sdnv1alpha1.NATGateway{}
	if err := r.Get(ctx, req.NamespacedName, ngw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ngw.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	status := sdnv1alpha1.NATGatewayStatus{
		ID:         ngw.Status.ID,
		BlockSize:  int32(r.blockSize()),
		Conditions: append([]metav1.Condition(nil), ngw.Status.Conditions...),
	}

	if status.ID == 0 {
		id, err := r.allocateID(ctx, ngw)
		if err != nil {
			return ctrl.Result{}, err
		}
		status.ID = id
	}

	vpc := &sdnv1alpha1.VPC{}
	vpcOK := false
	if err := r.Get(ctx, types.NamespacedName{Namespace: ngw.Namespace, Name: ngw.Spec.VPCRef.Name}, vpc); err == nil {
		vpcOK = vpc.Status.VNI != 0
	} else if !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}
	setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionVPCResolved, vpcOK,
		"VPCResolved", "spec.vpcRef names a realized VPC in this namespace")

	var leases localsdnv1alpha1.NATPortBlockList
	if err := r.List(ctx, &leases, client.MatchingLabels{localsdnv1alpha1.LabelNATGatewayUID: string(ngw.UID)}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list NATPortBlocks: %w", err)
	}

	var failures map[corev1.IPFamily]natFamilyFailure
	if vpcOK {
		slots, f, err := r.desiredSlots(ctx, ngw, vpc)
		if err != nil {
			return ctrl.Result{}, err
		}
		failures = f
		var nodes corev1.NodeList
		if err := r.List(ctx, &nodes); err != nil {
			return ctrl.Result{}, fmt.Errorf("list nodes: %w", err)
		}
		addrs, err := r.reconcileServices(ctx, ngw, slots, natReadyNodes(nodes.Items, leases.Items))
		if err != nil {
			return ctrl.Result{}, err
		}
		for _, s := range slots {
			for _, fam := range s.serves {
				a := addrs[s.key][fam]
				if a == "" {
					failures[fam] = natFamilyFailure{sdnv1alpha1.NATGatewayReasonAddressPending,
						"the LoadBalancer Service has no " + familyLabelValue(fam) + " address yet"}
					continue
				}
				if fam == corev1.IPv6Protocol {
					status.Address6 = a
				} else {
					status.Address = a
				}
			}
		}
	} else if err := r.deleteServices(ctx, ngw, nil); err != nil {
		return ctrl.Result{}, err
	}
	setAddressCondition(&status, vpcOK, failures)

	leased := len(leases.Items)
	total := localsdnv1alpha1.NATBlocks(r.blockSize())
	free := total - leased
	if free < 0 {
		free = 0
	}
	status.Blocks = sdnv1alpha1.NATGatewayBlocks{Leased: int32(leased), Free: int32(free)}
	if free > 0 {
		setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionCapacityAvailable, true,
			"BlocksFree", fmt.Sprintf("%d of %d port blocks are free", free, total))
	} else {
		setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionCapacityAvailable, false,
			"NoFreeBlock", fmt.Sprintf("all %d port blocks are leased; a node without one cannot NAT through this NAT gateway", total))
	}

	if natStatusEqual(ngw.Status, status) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = ngw.Generation
	}
	ngw.Status = status
	if err := r.Status().Update(ctx, ngw); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update NATGateway status: %w", err)
	}
	log.FromContext(ctx).Info("NATGateway status updated", "natgateway", req.NamespacedName.String(),
		"id", status.ID, "address", status.Address, "address6", status.Address6)
	return ctrl.Result{}, nil
}

func (r *NATGatewayReconciler) blockSize() int {
	if r.BlockSize > 0 {
		return r.BlockSize
	}
	return DefaultNATBlockSize
}

// allocateID returns the lowest id in 1..65535 no other NAT gateway holds,
// listing live so two NAT gateways reconciled back to back never share one.
func (r *NATGatewayReconciler) allocateID(ctx context.Context, self *sdnv1alpha1.NATGateway) (int32, error) {
	var list sdnv1alpha1.NATGatewayList
	if err := r.reader().List(ctx, &list); err != nil {
		return 0, fmt.Errorf("list NATGateways: %w", err)
	}
	used := map[int32]bool{}
	for i := range list.Items {
		if list.Items[i].UID != self.UID {
			used[list.Items[i].Status.ID] = true
		}
	}
	for id := int32(1); id <= 65535; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free NAT gateway id")
}

func (r *NATGatewayReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// desiredSlots decides the NAT gateway's Services (docs/vpc-egress.md §2.1):
// with no claim field, one dynamic single-family Service per VPC family; with
// claims, one Service per distinct claim, with the claim's families. It
// returns the failure of every served family it can already tell will get no
// address.
func (r *NATGatewayReconciler) desiredSlots(ctx context.Context, ngw *sdnv1alpha1.NATGateway, vpc *sdnv1alpha1.VPC) ([]natSlot, map[corev1.IPFamily]natFamilyFailure, error) {
	inVPC := map[corev1.IPFamily]bool{
		corev1.IPv4Protocol: cidrsHaveV4(vpc.Spec.CIDRs),
		corev1.IPv6Protocol: cidrsHaveV6(vpc.Spec.CIDRs),
	}
	claims := map[corev1.IPFamily]string{
		corev1.IPv4Protocol: ngw.Spec.AddressClaimName,
		corev1.IPv6Protocol: ngw.Spec.AddressClaimName6,
	}
	infos := map[string]natClaimInfo{}
	for _, c := range claims {
		if c == "" {
			continue
		}
		if _, ok := infos[c]; ok {
			continue
		}
		info, err := r.claimInfo(ctx, ngw.Namespace, c)
		if err != nil {
			return nil, nil, err
		}
		infos[c] = info
	}
	slots, failures := planNATSlots(inVPC, claims, infos)
	return slots, failures, nil
}

// planNATSlots is desiredSlots' decision, without I/O.
func planNATSlots(inVPC map[corev1.IPFamily]bool, claims map[corev1.IPFamily]string, infos map[string]natClaimInfo) ([]natSlot, map[corev1.IPFamily]natFamilyFailure) {
	families := []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol}
	failures := map[corev1.IPFamily]natFamilyFailure{}
	var slots []natSlot

	if claims[corev1.IPv4Protocol] == "" && claims[corev1.IPv6Protocol] == "" {
		for _, f := range families {
			if inVPC[f] {
				slots = append(slots, natSlot{
					key: "dynamic-" + familyLabelValue(f), families: []corev1.IPFamily{f}, serves: []corev1.IPFamily{f},
				})
			}
		}
		return slots, failures
	}

	byClaim := map[string][]corev1.IPFamily{}
	var order []string
	for _, f := range families {
		c := claims[f]
		if c == "" {
			continue
		}
		if !inVPC[f] {
			failures[f] = natFamilyFailure{sdnv1alpha1.NATGatewayReasonFamilyNotInVPC,
				familyLabelValue(f) + " is not one of the VPC's families"}
			continue
		}
		if _, ok := byClaim[c]; !ok {
			order = append(order, c)
		}
		byClaim[c] = append(byClaim[c], f)
	}
	for _, c := range order {
		serves := byClaim[c]
		info := infos[c]
		switch {
		case info.apiMissing:
			// The claim cannot be read: one single-family Service per field. The
			// annotation has no effect and the LB implementation assigns.
			for _, f := range serves {
				slots = append(slots, natSlot{
					key: c + "-" + familyLabelValue(f), claim: c,
					families: []corev1.IPFamily{f}, serves: []corev1.IPFamily{f},
				})
			}
		case !info.found:
			for _, f := range serves {
				failures[f] = natFamilyFailure{sdnv1alpha1.NATGatewayReasonClaimNotFound,
					fmt.Sprintf("IPAddressClaim %q does not exist", c)}
			}
		case !info.bound:
			for _, f := range serves {
				failures[f] = natFamilyFailure{sdnv1alpha1.NATGatewayReasonClaimNotBound,
					fmt.Sprintf("IPAddressClaim %q is not Bound", c)}
			}
		default:
			has := map[corev1.IPFamily]bool{}
			for _, f := range info.families {
				has[f] = true
			}
			var served []corev1.IPFamily
			for _, f := range serves {
				if has[f] {
					served = append(served, f)
					continue
				}
				failures[f] = natFamilyFailure{sdnv1alpha1.NATGatewayReasonClaimFamilyMissing,
					fmt.Sprintf("IPAddressClaim %q has no %s address", c, familyLabelValue(f))}
			}
			if len(served) > 0 {
				slots = append(slots, natSlot{key: c, claim: c, families: info.families, serves: served})
			}
		}
	}
	return slots, failures
}

// claimInfo reads a claim's phase and the families of its bound addresses.
func (r *NATGatewayReconciler) claimInfo(ctx context.Context, namespace, name string) (natClaimInfo, error) {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(ipAddressClaimGVK)
	err := r.reader().Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, u)
	switch {
	case meta.IsNoMatchError(err):
		return natClaimInfo{apiMissing: true}, nil
	case apierrors.IsNotFound(err):
		return natClaimInfo{}, nil
	case err != nil:
		return natClaimInfo{}, fmt.Errorf("get IPAddressClaim %s/%s: %w", namespace, name, err)
	}
	info := natClaimInfo{found: true}
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	info.bound = phase == "Bound"
	addrs, _, _ := unstructured.NestedSlice(u.Object, "status", "addresses")
	has := map[corev1.IPFamily]bool{}
	for _, a := range addrs {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		s, _ := m["address"].(string)
		if ip, err := netip.ParseAddr(s); err == nil {
			if ip.Is4() || ip.Is4In6() {
				has[corev1.IPv4Protocol] = true
			} else {
				has[corev1.IPv6Protocol] = true
			}
		}
	}
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		if has[f] {
			info.families = append(info.families, f)
		}
	}
	return info, nil
}

// ownedServices lists the Services this NAT gateway controls, by slot.
func (r *NATGatewayReconciler) ownedServices(ctx context.Context, ngw *sdnv1alpha1.NATGateway) (map[string]*corev1.Service, error) {
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(ngw.Namespace), client.MatchingLabels{natGatewayLabel: ngw.Name}); err != nil {
		return nil, fmt.Errorf("list NAT gateway services: %w", err)
	}
	out := map[string]*corev1.Service{}
	for i := range list.Items {
		s := &list.Items[i]
		if metav1.IsControlledBy(s, ngw) {
			out[s.Labels[natSlotLabel]] = s
		}
	}
	return out, nil
}

// reconcileServices makes the owned Services exactly `slots` and returns each
// slot's assigned address per family.
func (r *NATGatewayReconciler) reconcileServices(ctx context.Context, ngw *sdnv1alpha1.NATGateway, slots []natSlot, nodes []*corev1.Node) (map[string]map[corev1.IPFamily]string, error) {
	owned, err := r.ownedServices(ctx, ngw)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	out := map[string]map[corev1.IPFamily]string{}
	for _, s := range slots {
		keep[s.key] = true
		svc := owned[s.key]
		if svc != nil && !sameFamilies(svc.Spec.IPFamilies, s.families) {
			if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("delete NAT gateway service for a family change: %w", err)
			}
			svc = nil
		}
		if svc == nil {
			if svc, err = r.adoptGatewayService(ctx, ngw, s); err != nil {
				return nil, err
			}
		}
		if svc == nil {
			if svc, err = r.createService(ctx, ngw, s); err != nil {
				return nil, err
			}
			if svc == nil {
				continue // the cluster cannot serve these families
			}
		} else if changed := reconcileClaimAnnotation(svc, s.claim); changed || svc.Spec.ExternalTrafficPolicy != corev1.ServiceExternalTrafficPolicyLocal {
			svc.Spec.ExternalTrafficPolicy = corev1.ServiceExternalTrafficPolicyLocal
			if err := r.Update(ctx, svc); err != nil {
				return nil, fmt.Errorf("update NAT gateway service: %w", err)
			}
		}
		addrs := ingressByFamily(svc)
		out[s.key] = addrs
		if err := r.reconcileEndpointSlices(ctx, ngw, svc, addrs, nodes); err != nil {
			return nil, err
		}
	}
	return out, r.deleteServices(ctx, ngw, keep)
}

// deleteServices deletes the owned Services whose slot is not in keep.
func (r *NATGatewayReconciler) deleteServices(ctx context.Context, ngw *sdnv1alpha1.NATGateway, keep map[string]bool) error {
	owned, err := r.ownedServices(ctx, ngw)
	if err != nil {
		return err
	}
	for slot, svc := range owned {
		if keep[slot] {
			continue
		}
		if err := r.Delete(ctx, svc); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete NAT gateway service: %w", err)
		}
	}
	return nil
}

// adoptGatewayService takes over the NAT Service of the VPCGateway that owns
// this NAT gateway, so the address survives the transition (docs/vpc-egress.md
// §7). Only a single-family slot can adopt: that is the only shape a
// VPCGateway's Services have.
func (r *NATGatewayReconciler) adoptGatewayService(ctx context.Context, ngw *sdnv1alpha1.NATGateway, s natSlot) (*corev1.Service, error) {
	owner := metav1.GetControllerOf(ngw)
	if owner == nil || owner.Kind != "VPCGateway" || len(s.families) != 1 {
		return nil, nil
	}
	var list corev1.ServiceList
	if err := r.List(ctx, &list, client.InNamespace(ngw.Namespace), client.MatchingLabels{
		vpcGatewayLabel:    owner.Name,
		addressFamilyLabel: familyLabelValue(s.families[0]),
	}); err != nil {
		return nil, fmt.Errorf("list VPCGateway NAT services: %w", err)
	}
	for i := range list.Items {
		svc := &list.Items[i]
		c := metav1.GetControllerOf(svc)
		if c == nil || c.UID != owner.UID {
			continue
		}
		delete(svc.Labels, vpcGatewayLabel)
		delete(svc.Labels, addressFamilyLabel)
		svc.Labels[natGatewayLabel] = ngw.Name
		svc.Labels[natSlotLabel] = s.key
		svc.OwnerReferences = nil
		if err := controllerutil.SetControllerReference(ngw, svc, r.Scheme); err != nil {
			return nil, err
		}
		reconcileClaimAnnotation(svc, s.claim)
		if err := r.Update(ctx, svc); err != nil {
			return nil, fmt.Errorf("adopt VPCGateway NAT service: %w", err)
		}
		log.FromContext(ctx).Info("NATGateway adopted its VPCGateway's NAT service",
			"natgateway", client.ObjectKeyFromObject(ngw).String(), "service", svc.Name)
		return svc, nil
	}
	return nil, nil
}

// createService creates a slot's backend-less LoadBalancer Service. A cluster
// that cannot serve its families rejects it as Invalid; that yields nil and the
// families report AddressPending.
func (r *NATGatewayReconciler) createService(ctx context.Context, ngw *sdnv1alpha1.NATGateway, s natSlot) (*corev1.Service, error) {
	policy := corev1.IPFamilyPolicySingleStack
	if len(s.families) > 1 {
		policy = corev1.IPFamilyPolicyRequireDualStack
	}
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: ngw.Name + "-",
			Namespace:    ngw.Namespace,
			Labels: map[string]string{
				serviceProxyNameLabel: serviceProxyNameValue,
				natGatewayLabel:       ngw.Name,
				natSlotLabel:          s.key,
			},
		},
		Spec: corev1.ServiceSpec{
			Type:                          corev1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy:         corev1.ServiceExternalTrafficPolicyLocal,
			AllocateLoadBalancerNodePorts: new(false),
			IPFamilyPolicy:                &policy,
			IPFamilies:                    append([]corev1.IPFamily(nil), s.families...),
			Ports:                         []corev1.ServicePort{{Name: "placeholder", Port: 1, Protocol: corev1.ProtocolTCP}},
		},
	}
	if ngw.Spec.LoadBalancerClass != "" {
		svc.Spec.LoadBalancerClass = new(ngw.Spec.LoadBalancerClass)
	}
	reconcileClaimAnnotation(svc, s.claim)
	if err := controllerutil.SetControllerReference(ngw, svc, r.Scheme); err != nil {
		return nil, err
	}
	if err := r.Create(ctx, svc); err != nil {
		if apierrors.IsInvalid(err) {
			log.FromContext(ctx).Info("cluster cannot serve a LoadBalancer of these families",
				"natgateway", client.ObjectKeyFromObject(ngw).String(), "families", s.families)
			return nil, nil
		}
		return nil, fmt.Errorf("create NAT gateway service: %w", err)
	}
	return svc, nil
}

// reconcileEndpointSlices keeps one EndpointSlice per assigned family, with a
// Ready endpoint per NAT-ready node (natReadyNodes) carrying its nodeName. With
// externalTrafficPolicy Local, the LB implementation advertises the address
// only from those nodes (docs/external-addresses.md §5). Nothing dials the
// endpoints.
func (r *NATGatewayReconciler) reconcileEndpointSlices(ctx context.Context, ngw *sdnv1alpha1.NATGateway, svc *corev1.Service, addrs map[corev1.IPFamily]string, nodes []*corev1.Node) error {
	want := map[string]bool{}
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		addr := addrs[f]
		if addr == "" {
			continue
		}
		name := svc.Name + "-" + familyShort(f)
		want[name] = true
		addrType := discoveryv1.AddressTypeIPv4
		if f == corev1.IPv6Protocol {
			addrType = discoveryv1.AddressTypeIPv6
		}
		eps := make([]discoveryv1.Endpoint, 0, len(nodes))
		for _, n := range nodes {
			a := nodeAddress(n, f)
			if a == "" {
				a = addr
			}
			eps = append(eps, discoveryv1.Endpoint{Addresses: []string{a}, NodeName: new(n.Name),
				Conditions: discoveryv1.EndpointConditions{Ready: new(true)}})
		}
		ports := []discoveryv1.EndpointPort{{Name: new("placeholder"), Port: new(int32(1)), Protocol: new(corev1.ProtocolTCP)}}
		existing := &discoveryv1.EndpointSlice{}
		switch err := r.Get(ctx, client.ObjectKey{Namespace: svc.Namespace, Name: name}, existing); {
		case apierrors.IsNotFound(err):
			slice := &discoveryv1.EndpointSlice{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: svc.Namespace,
					Labels: map[string]string{
						discoveryv1.LabelServiceName: svc.Name,
						discoveryv1.LabelManagedBy:   serviceProxyNameValue,
						natGatewayLabel:              ngw.Name,
					},
				},
				AddressType: addrType,
				Endpoints:   eps,
				Ports:       ports,
			}
			if err := controllerutil.SetControllerReference(svc, slice, r.Scheme); err != nil {
				return err
			}
			if err := r.Create(ctx, slice); err != nil {
				return fmt.Errorf("create NAT gateway endpointslice: %w", err)
			}
		case err != nil:
			return fmt.Errorf("get NAT gateway endpointslice: %w", err)
		default:
			if sameNodeEndpoints(existing.Endpoints, eps) {
				continue
			}
			existing.Endpoints = eps
			existing.Ports = ports
			if err := r.Update(ctx, existing); err != nil {
				return fmt.Errorf("update NAT gateway endpointslice: %w", err)
			}
		}
	}
	// Slices of this Service under any other name (an adopted VPCGateway
	// Service's, or a family it no longer has) go.
	var list discoveryv1.EndpointSliceList
	if err := r.List(ctx, &list, client.InNamespace(svc.Namespace), client.MatchingLabels{
		discoveryv1.LabelServiceName: svc.Name,
		discoveryv1.LabelManagedBy:   serviceProxyNameValue,
	}); err != nil {
		return fmt.Errorf("list NAT gateway endpointslices: %w", err)
	}
	for i := range list.Items {
		if !want[list.Items[i].Name] {
			if err := r.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
				return fmt.Errorf("delete NAT gateway endpointslice: %w", err)
			}
		}
	}
	return nil
}

// sameNodeEndpoints compares endpoint lists by address and nodeName, in order.
func sameNodeEndpoints(a, b []discoveryv1.Endpoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i].Addresses) != 1 || a[i].Addresses[0] != b[i].Addresses[0] ||
			a[i].NodeName == nil || *a[i].NodeName != *b[i].NodeName ||
			a[i].Conditions.Ready == nil || !*a[i].Conditions.Ready {
			return false
		}
	}
	return true
}

// natReadyNodes returns, sorted by name, the Ready nodes that may attract the
// NAT gateway's return traffic: those that have acked every active lease in
// their current boot, so their nat_blk_owner forwards every leased port
// (docs/vpc-egress.md §4.3). If no node qualifies, every Ready node does: an
// address announced from an unready node beats one announced from none.
func natReadyNodes(nodes []corev1.Node, leases []localsdnv1alpha1.NATPortBlock) []*corev1.Node {
	var ready, qualified []*corev1.Node
	for i := range nodes {
		n := &nodes[i]
		if !nodeReady(n) || !n.DeletionTimestamp.IsZero() {
			continue
		}
		ready = append(ready, n)
		ok := true
		for j := range leases {
			if leases[j].Status.Active && !ackedInBoot(&leases[j], n) {
				ok = false
				break
			}
		}
		if ok {
			qualified = append(qualified, n)
		}
	}
	if len(qualified) == 0 {
		qualified = ready
	}
	sort.Slice(qualified, func(i, j int) bool { return qualified[i].Name < qualified[j].Name })
	return qualified
}

// ackedInBoot reports whether a node has acked a lease in its current boot. A
// node that reports no boot ID counts with an ack of any boot.
func ackedInBoot(l *localsdnv1alpha1.NATPortBlock, n *corev1.Node) bool {
	for _, a := range l.Status.Acks {
		if a.Node == n.Name && (n.Status.NodeInfo.BootID == "" || a.BootID == n.Status.NodeInfo.BootID) {
			return true
		}
	}
	return false
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// nodeAddress returns a node's InternalIP of a family, or "".
func nodeAddress(n *corev1.Node, f corev1.IPFamily) string {
	for _, a := range n.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		ip, err := netip.ParseAddr(a.Address)
		if err == nil && (ip.Is4() == (f == corev1.IPv4Protocol)) {
			return ip.String()
		}
	}
	return ""
}

// ingressByFamily returns a Service's assigned LoadBalancer addresses by family.
func ingressByFamily(svc *corev1.Service) map[corev1.IPFamily]string {
	out := map[corev1.IPFamily]string{}
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		ip, err := netip.ParseAddr(ing.IP)
		if err != nil {
			continue
		}
		f := corev1.IPv6Protocol
		if ip.Is4() || ip.Is4In6() {
			f = corev1.IPv4Protocol
		}
		if out[f] == "" {
			out[f] = ip.Unmap().String()
		}
	}
	return out
}

func sameFamilies(a, b []corev1.IPFamily) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]corev1.IPFamily(nil), a...)
	y := append([]corev1.IPFamily(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// setAddressCondition sets AddressAssigned from the per-family failures.
func setAddressCondition(status *sdnv1alpha1.NATGatewayStatus, vpcOK bool, failures map[corev1.IPFamily]natFamilyFailure) {
	if !vpcOK {
		setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionAddressAssigned, false,
			"VPCNotResolved", "the VPC does not exist or has no VNI yet")
		return
	}
	if len(failures) == 0 {
		if status.Address == "" && status.Address6 == "" {
			setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionAddressAssigned, false,
				sdnv1alpha1.NATGatewayReasonAddressPending, "no family has an address yet")
			return
		}
		setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionAddressAssigned, true,
			"Assigned", "every family the NAT gateway serves has an address")
		return
	}
	var reason string
	var parts []string
	for _, f := range []corev1.IPFamily{corev1.IPv4Protocol, corev1.IPv6Protocol} {
		ff, ok := failures[f]
		if !ok {
			continue
		}
		if reason == "" {
			reason = ff.reason
		}
		parts = append(parts, familyLabelValue(f)+": "+ff.reason+": "+ff.message)
	}
	setCond(&status.Conditions, sdnv1alpha1.NATGatewayConditionAddressAssigned, false, reason, strings.Join(parts, "; "))
}

// setCondition sets a condition through meta.SetStatusCondition.
func setCond(conds *[]metav1.Condition, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	meta.SetStatusCondition(conds, metav1.Condition{Type: condType, Status: st, Reason: reason, Message: msg})
}

// conditionsEqual compares conditions by type, status, reason and message.
func conditionsEqual(a, b []metav1.Condition) bool {
	if len(a) != len(b) {
		return false
	}
	for _, ca := range a {
		cb := meta.FindStatusCondition(b, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

func natStatusEqual(a, b sdnv1alpha1.NATGatewayStatus) bool {
	return a.ID == b.ID && a.Address == b.Address && a.Address6 == b.Address6 &&
		a.BlockSize == b.BlockSize && a.Blocks == b.Blocks && conditionsEqual(a.Conditions, b.Conditions)
}

// SetupWithManager wires the controller.
func (r *NATGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.NATGateway{}).
		Owns(&corev1.Service{}).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPC)).
		Watches(&localsdnv1alpha1.NATPortBlock{}, handler.EnqueueRequestsFromMapFunc(mapLeaseToNATGateway)).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapAll), builder.WithPredicates(natNodeChanged)).
		Named("natgateway").
		Complete(r)
}

// mapAll enqueues every NAT gateway: a node's readiness or boot changes which
// nodes attract every NAT gateway's return traffic.
func (r *NATGatewayReconciler) mapAll(ctx context.Context, _ client.Object) []ctrl.Request {
	var list sdnv1alpha1.NATGatewayList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
	}
	return out
}

// natNodeChanged passes node events that change natReadyNodes or nodeAddress.
var natNodeChanged = predicate.Funcs{
	UpdateFunc: func(e event.UpdateEvent) bool {
		o, ok1 := e.ObjectOld.(*corev1.Node)
		n, ok2 := e.ObjectNew.(*corev1.Node)
		if !ok1 || !ok2 {
			return true
		}
		return nodeReady(o) != nodeReady(n) || o.Status.NodeInfo.BootID != n.Status.NodeInfo.BootID ||
			!reflect.DeepEqual(o.Status.Addresses, n.Status.Addresses) || o.DeletionTimestamp.IsZero() != n.DeletionTimestamp.IsZero()
	},
}

func (r *NATGatewayReconciler) mapVPC(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.NATGatewayList
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

func mapLeaseToNATGateway(_ context.Context, obj client.Object) []ctrl.Request {
	l, ok := obj.(*localsdnv1alpha1.NATPortBlock)
	if !ok {
		return nil
	}
	ref := l.Spec.NATGatewayRef
	return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}}}
}
