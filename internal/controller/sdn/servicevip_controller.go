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
	"net"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// ServiceVIPReconciler materializes a ServiceVIP per attached, non-headless
// Service (docs/services-in-vpc.md increment 2): the Service carries the
// sdn.cozystack.io/vpc annotation (the pod->Port idiom), authorization is the
// VPCBinding in the Service's namespace (the same gate pods use), and the VIP
// is allocated from the VPC's own address space. Backends are the ready
// endpoints resolved through their Ports to VPC IPs — never fabric addresses.
type ServiceVIPReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// Reader reads live from the API server for ALLOCATION (never the lagging
	// informer cache — the VNI-duplicate lesson). Falls back to Client (tests).
	Reader client.Reader
}

// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups=discovery.k8s.io,resources=endpointslices,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=servicevips,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=servicevips/status,verbs=get;update;patch

func (r *ServiceVIPReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

// Reconcile is keyed on the Service (namespace/name).
func (r *ServiceVIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	svc := &corev1.Service{}
	err := r.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		return ctrl.Result{}, r.reapVIPs(ctx, req.Namespace, req.Name, "")
	}
	if err != nil {
		return ctrl.Result{}, err
	}

	vpcNS, vpcName, attached := serviceVPCRef(svc)
	if !attached || svc.Spec.ClusterIP == corev1.ClusterIPNone || svc.DeletionTimestamp != nil {
		// Not attached (or headless — served by the resolver directly, no VIP,
		// or being deleted): reap whatever VIP the service may have had.
		return ctrl.Result{}, r.reapVIPs(ctx, svc.Namespace, svc.Name, "")
	}

	// Authorization: the same gate pods pass at CNI ADD — a VPCBinding in the
	// consumer namespace referencing the VPC. No binding, no attachment.
	if !r.bindingExists(ctx, svc.Namespace, vpcNS, vpcName) {
		logger.Info("service annotated into a VPC without a VPCBinding; ignoring", "service", req.NamespacedName, "vpc", vpcNS+"/"+vpcName)
		return ctrl.Result{}, r.reapVIPs(ctx, svc.Namespace, svc.Name, "")
	}

	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: vpcNS, Name: vpcName}, vpc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if vpc.Status.VNI == 0 || len(vpc.Spec.CIDRs) == 0 {
		return ctrl.Result{Requeue: true}, nil
	}

	// A VPC re-attachment (annotation now names a different VPC) reaps the old
	// VIP; the new one is allocated below.
	if err := r.reapVIPs(ctx, svc.Namespace, svc.Name, vpcKey(vpcNS, vpcName)); err != nil {
		return ctrl.Result{}, err
	}

	svip, err := r.ensureVIP(ctx, svc, vpc)
	if err != nil {
		return ctrl.Result{}, err
	}
	if svip == nil {
		return ctrl.Result{Requeue: true}, nil
	}

	// Port always wins an IP conflict: a Port's address is pinned workload
	// identity; the VIP is the movable kind (nothing addresses it except
	// through a DNS answer we control). Live read — repair must not lag.
	if taken, err := r.ipHeldByPort(ctx, vpc, svip.Spec.IP); err != nil {
		return ctrl.Result{}, err
	} else if taken {
		logger.Info("ServiceVIP yields its address to a Port", "vip", svip.Name, "ip", svip.Spec.IP)
		if err := r.Delete(ctx, svip); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	backends, err := r.resolveBackends(ctx, svc, vpc)
	if err != nil {
		return ctrl.Result{}, err
	}

	phase := sdnv1alpha1.ServiceVIPPhasePending
	if len(backends) > 0 {
		phase = sdnv1alpha1.ServiceVIPPhaseReady
	}
	if !slices.EqualFunc(svip.Status.Backends, backends, backendEqual) || svip.Status.Phase != phase {
		svip.Status.Backends = backends
		svip.Status.Phase = phase
		if err := r.Status().Update(ctx, svip); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, fmt.Errorf("update ServiceVIP status: %w", err)
		}
		logger.Info("ServiceVIP reconciled", "vip", svip.Name, "ip", svip.Spec.IP, "backends", len(backends), "phase", phase)
	}
	return ctrl.Result{}, nil
}

func backendEqual(a, b sdnv1alpha1.VIPBackend) bool {
	return a.IP == b.IP && slices.Equal(a.Ports, b.Ports)
}

func vpcKey(ns, name string) string { return ns + "/" + name }

// serviceVPCRef resolves the Service's VPC annotation ("[<owner-ns>/]<vpc>",
// defaulting to the Service's own namespace).
func serviceVPCRef(svc *corev1.Service) (ns, name string, ok bool) {
	anno := svc.Annotations[sdnv1alpha1.AnnotationVPC]
	if anno == "" {
		return "", "", false
	}
	ns, name = svc.Namespace, anno
	if owner, rest, found := strings.Cut(anno, "/"); found {
		ns, name = owner, rest
	}
	return ns, name, true
}

func (r *ServiceVIPReconciler) bindingExists(ctx context.Context, consumerNS, vpcNS, vpcName string) bool {
	bindings := &sdnv1alpha1.VPCBindingList{}
	if err := r.List(ctx, bindings, client.InNamespace(consumerNS)); err != nil {
		return false
	}
	for _, b := range bindings.Items {
		if b.Spec.VPCRef.Namespace == vpcNS && b.Spec.VPCRef.Name == vpcName {
			return true
		}
	}
	return false
}

// reapVIPs deletes every ServiceVIP labelled for the service, except ones
// belonging to keepVPC ("" reaps all).
func (r *ServiceVIPReconciler) reapVIPs(ctx context.Context, svcNS, svcName, keepVPC string) error {
	vips := &sdnv1alpha1.ServiceVIPList{}
	if err := r.List(ctx, vips, client.MatchingLabels{
		sdnv1alpha1.LabelServiceNamespace: svcNS,
		sdnv1alpha1.LabelServiceName:      svcName,
	}); err != nil {
		return err
	}
	for i := range vips.Items {
		v := &vips.Items[i]
		if keepVPC != "" && vpcKey(v.Spec.VPCRef.Namespace, v.Spec.VPCRef.Name) == keepVPC {
			continue
		}
		if err := r.Delete(ctx, v); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

// ensureVIP returns the service's ServiceVIP, allocating one when absent. A
// nil, nil return means allocation should be retried (transient collision).
func (r *ServiceVIPReconciler) ensureVIP(ctx context.Context, svc *corev1.Service, vpc *sdnv1alpha1.VPC) (*sdnv1alpha1.ServiceVIP, error) {
	vips := &sdnv1alpha1.ServiceVIPList{}
	if err := r.reader().List(ctx, vips, client.MatchingLabels{
		sdnv1alpha1.LabelServiceNamespace: svc.Namespace,
		sdnv1alpha1.LabelServiceName:      svc.Name,
	}); err != nil {
		return nil, err
	}
	for i := range vips.Items {
		v := &vips.Items[i]
		if v.Spec.VPCRef.Namespace == vpc.Namespace && v.Spec.VPCRef.Name == vpc.Name {
			// Keep the declared ports and affinity fresh (a Service change is
			// a spec update, not a reallocation).
			ports := vipPorts(svc)
			affinity := string(svc.Spec.SessionAffinity)
			if !slices.Equal(v.Spec.Ports, ports) || v.Spec.SessionAffinity != affinity {
				v.Spec.Ports = ports
				v.Spec.SessionAffinity = affinity
				if err := r.Update(ctx, v); err != nil {
					return nil, err
				}
			}
			return v, nil
		}
	}

	ip, err := r.allocateVIP(ctx, vpc)
	if err != nil {
		return nil, err
	}
	svip := &sdnv1alpha1.ServiceVIP{
		ObjectMeta: metav1.ObjectMeta{
			Name: vipName(vpc.Status.VNI, ip),
			Labels: map[string]string{
				sdnv1alpha1.LabelVPC:              vpc.Name,
				sdnv1alpha1.LabelVPCNamespace:     vpc.Namespace,
				sdnv1alpha1.LabelServiceNamespace: svc.Namespace,
				sdnv1alpha1.LabelServiceName:      svc.Name,
			},
		},
		Spec: sdnv1alpha1.ServiceVIPSpec{
			VPCRef:          sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name},
			IP:              ip,
			ServiceRef:      sdnv1alpha1.ServiceRef{Namespace: svc.Namespace, Name: svc.Name},
			Ports:           vipPorts(svc),
			SessionAffinity: string(svc.Spec.SessionAffinity),
		},
	}
	if err := r.Create(ctx, svip); err != nil {
		if apierrors.IsAlreadyExists(err) || apierrors.IsConflict(err) {
			// The name encodes the (VNI, IP) claim: a concurrent allocator got
			// there first — AlreadyExists for a sibling VIP, Conflict (409)
			// from the aggregated registry's cross-kind check when a Port
			// holds the address. Requeue and walk again.
			return nil, nil
		}
		return nil, fmt.Errorf("create ServiceVIP: %w", err)
	}
	return svip, nil
}

func vipPorts(svc *corev1.Service) []sdnv1alpha1.VIPPort {
	var out []sdnv1alpha1.VIPPort
	for _, p := range svc.Spec.Ports {
		proto := string(p.Protocol)
		if proto == "" {
			proto = "TCP"
		}
		if proto != "TCP" && proto != "UDP" {
			continue // SCTP is out of scope for the datapath ct
		}
		out = append(out, sdnv1alpha1.VIPPort{Name: p.Name, Protocol: proto, Port: p.Port})
	}
	return out
}

// vipName mirrors the Port name convention (sv<vni>.<ip-with-dashes>): the
// name is an atomic claim on the address among ServiceVIPs, registry-validated
// to match spec.ip. Shared helper so the writers and the registry check can
// never drift.
func vipName(vni int32, ip string) string {
	return sdn.ServiceVIPName(vni, ip)
}

// allocateVIP picks a free address from the top of the VPC's first CIDR
// downward — the CNI's Port allocator walks from the bottom up, so the two
// kinds approach from opposite ends and collide only on a nearly-full pool.
// The free check is a LIVE union of both kinds (Ports and ServiceVIPs); the
// residual race is closed by the name claim (vs ServiceVIPs) and the
// Port-always-wins repair (vs Ports).
func (r *ServiceVIPReconciler) allocateVIP(ctx context.Context, vpc *sdnv1alpha1.VPC) (string, error) {
	_, ipnet, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		return "", fmt.Errorf("VPC %s/%s CIDR: %w", vpc.Namespace, vpc.Name, err)
	}

	used := map[string]bool{}
	ports := &sdnv1alpha1.PortList{}
	if err := r.reader().List(ctx, ports); err != nil {
		return "", err
	}
	for _, p := range ports.Items {
		if p.Spec.VPCRef.Namespace == vpc.Namespace && p.Spec.VPCRef.Name == vpc.Name {
			used[p.Spec.IP] = true
		}
	}
	vips := &sdnv1alpha1.ServiceVIPList{}
	if err := r.reader().List(ctx, vips); err != nil {
		return "", err
	}
	for _, v := range vips.Items {
		if v.Spec.VPCRef.Namespace == vpc.Namespace && v.Spec.VPCRef.Name == vpc.Name {
			used[v.Spec.IP] = true
		}
	}

	first, last := cidrRange(ipnet)
	// Skip the v4 broadcast address; start just below the top. The walk stops
	// above the network address and the reserved .1 (the gateway leg).
	candidate := prevIP(last)
	if candidate.To4() == nil {
		candidate = last // v6 has no broadcast; the top address is usable
	}
	floor := incIP(incIP(first)) // network address + the reserved .1
	for i := 0; i < 65536 && ipnet.Contains(candidate) && !candidate.Equal(floor); i++ {
		if !used[candidate.String()] {
			return candidate.String(), nil
		}
		candidate = prevIP(candidate)
	}
	return "", fmt.Errorf("no free address for a VIP in VPC %s/%s (%s)", vpc.Namespace, vpc.Name, vpc.Spec.CIDRs[0])
}

// ipHeldByPort live-checks whether a Port of the VPC holds ip.
func (r *ServiceVIPReconciler) ipHeldByPort(ctx context.Context, vpc *sdnv1alpha1.VPC, ip string) (bool, error) {
	ports := &sdnv1alpha1.PortList{}
	if err := r.reader().List(ctx, ports); err != nil {
		return false, err
	}
	for _, p := range ports.Items {
		if p.Spec.IP == ip && p.Spec.VPCRef.Namespace == vpc.Namespace && p.Spec.VPCRef.Name == vpc.Name {
			return true, nil
		}
	}
	return false, nil
}

// resolveBackends maps the service's ready endpoints to backend VPC IPs with
// per-port targets: EndpointSlice endpoint -> its Pod's Port (same VPC) ->
// Port.Spec.IP. Fabric addresses never appear.
func (r *ServiceVIPReconciler) resolveBackends(ctx context.Context, svc *corev1.Service, vpc *sdnv1alpha1.VPC) ([]sdnv1alpha1.VIPBackend, error) {
	slicesList := &discoveryv1.EndpointSliceList{}
	if err := r.List(ctx, slicesList, client.InNamespace(svc.Namespace), client.MatchingLabels{
		discoveryv1.LabelServiceName: svc.Name,
	}); err != nil {
		return nil, err
	}
	ports := &sdnv1alpha1.PortList{}
	if err := r.List(ctx, ports, client.MatchingLabels{
		sdnv1alpha1.LabelVPC:          vpc.Name,
		sdnv1alpha1.LabelVPCNamespace: vpc.Namespace,
	}); err != nil {
		return nil, err
	}
	portByPod := map[string]*sdnv1alpha1.Port{}
	for i := range ports.Items {
		p := &ports.Items[i]
		if p.Spec.PodName != "" {
			portByPod[p.Spec.PodNamespace+"/"+p.Spec.PodName] = p
		}
	}

	var out []sdnv1alpha1.VIPBackend
	seen := map[string]bool{}
	for _, slice := range slicesList.Items {
		// The slice's ports carry the resolved numeric target for each named
		// service port.
		target := map[string]int32{} // service port name -> target port
		for _, sp := range slice.Ports {
			if sp.Port == nil {
				continue
			}
			name := ""
			if sp.Name != nil {
				name = *sp.Name
			}
			target[name] = *sp.Port
		}
		for _, ep := range slice.Endpoints {
			ready := ep.Conditions.Ready == nil || *ep.Conditions.Ready
			if !ready && !svc.Spec.PublishNotReadyAddresses {
				continue
			}
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			port := portByPod[ep.TargetRef.Namespace+"/"+ep.TargetRef.Name]
			if port == nil || port.Spec.IP == "" || seen[port.Spec.IP] {
				continue // not a Port of this VPC: structurally not a backend
			}
			seen[port.Spec.IP] = true
			var bps []sdnv1alpha1.VIPBackendPort
			for _, vp := range vipPorts(svc) {
				t, ok := target[vp.Name]
				if !ok {
					continue
				}
				bps = append(bps, sdnv1alpha1.VIPBackendPort{Protocol: vp.Protocol, Port: vp.Port, TargetPort: t})
			}
			out = append(out, sdnv1alpha1.VIPBackend{IP: port.Spec.IP, Ports: bps})
		}
	}
	slices.SortFunc(out, func(a, b sdnv1alpha1.VIPBackend) int { return strings.Compare(a.IP, b.IP) })
	return out, nil
}

// SetupWithManager wires the reconciler: Services are the primary;
// EndpointSlices and owned ServiceVIPs requeue their Service.
func (r *ServiceVIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	toService := func(ns, name string) []ctrl.Request {
		if name == "" {
			return nil
		}
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}}
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			return toService(obj.GetNamespace(), obj.GetLabels()[discoveryv1.LabelServiceName])
		})).
		Watches(&sdnv1alpha1.ServiceVIP{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			return toService(obj.GetLabels()[sdnv1alpha1.LabelServiceNamespace], obj.GetLabels()[sdnv1alpha1.LabelServiceName])
		})).
		// A Port appearing on a VIP's address must re-trigger that VIP's
		// reconcile promptly — the Port-always-wins repair otherwise waits for
		// the Service to change. Map the Port to the Service of any same-VPC
		// ServiceVIP holding its IP.
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []ctrl.Request {
			port, ok := obj.(*sdnv1alpha1.Port)
			if !ok || port.Spec.IP == "" {
				return nil
			}
			vips := &sdnv1alpha1.ServiceVIPList{}
			if err := r.List(ctx, vips, client.MatchingLabels{
				sdnv1alpha1.LabelVPC:          port.Spec.VPCRef.Name,
				sdnv1alpha1.LabelVPCNamespace: port.Spec.VPCRef.Namespace,
			}); err != nil {
				return nil
			}
			var reqs []ctrl.Request
			for i := range vips.Items {
				v := &vips.Items[i]
				if v.Spec.IP == port.Spec.IP {
					reqs = append(reqs, toService(v.Labels[sdnv1alpha1.LabelServiceNamespace], v.Labels[sdnv1alpha1.LabelServiceName])...)
				}
			}
			return reqs
		})).
		Named("servicevip").
		Complete(r)
}

// incIP returns the IP after ip (the CNI plugin has its own twin, nextIP).
func incIP(ip net.IP) net.IP {
	base := ip.To4()
	if base == nil {
		base = ip.To16()
	}
	out := make(net.IP, len(base))
	copy(out, base)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]++
		if out[i] != 0 {
			break
		}
	}
	return out
}

// prevIP returns the IP before ip (the decrementing twin of the CNI's nextIP).
func prevIP(ip net.IP) net.IP {
	base := ip.To4()
	if base == nil {
		base = ip.To16()
	}
	out := make(net.IP, len(base))
	copy(out, base)
	for i := len(out) - 1; i >= 0; i-- {
		out[i]--
		if out[i] != 0xff {
			break
		}
	}
	return out
}

// cidrRange returns the first (network) and last (v4: broadcast) addresses.
func cidrRange(ipnet *net.IPNet) (first, last net.IP) {
	first = ipnet.IP
	last = make(net.IP, len(first))
	copy(last, first)
	for i := range last {
		last[i] |= ^ipnet.Mask[i]
	}
	return first, last
}
