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
	"github.com/lllamnyp/cozyplane/pkg/netid"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
)

const gatewayVPCUIDAnnotation = "sdn.cozystack.io/gateway-vpc-uid"

// GatewayConfig parameterizes the gateway pods the controller spawns.
type GatewayConfig struct {
	// Image is the cozyplane image (the gateway binary ships in it). Empty
	// disables gateway reconciliation.
	Image string
	// Namespace is the system namespace gateway Deployments run in — it must
	// be the namespace the agents publish as theirs, because the CNI honors
	// gateway-attach only there.
	Namespace string
	// InternalCIDRs are the cluster-internal networks (pod, service, node)
	// the gateway must not forward tenant traffic to.
	InternalCIDRs string
	// ClusterDNS is the cluster DNS ClusterIP the gateway allows on :53.
	ClusterDNS string
}

// GatewayReconciler realizes VPC.spec.egress.natGateway as a per-VPC gateway
// Deployment in the system namespace. The gateway pod is a default-network pod
// whose gateway-for annotation makes the CNI give it a second leg into the VPC
// (the reserved .1); agents then route the VPC's off-net traffic to it.
type GatewayReconciler struct {
	client.Client

	Scheme *runtime.Scheme
	Config GatewayConfig
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch
// +kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;delete

// Reconcile ensures the gateway Deployment matches the VPC's egress spec.
func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, req.NamespacedName, vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, r.deleteGateways(ctx, req.Namespace, req.Name, "")
		}
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}
	if !vpc.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name, vpc.UID)
	}

	// The door is a VPCGateway now, not a field on the VPC: the boundary is a
	// separate, grantable object, and a tenant must not be able to give itself
	// internet by flipping a bool on an object it owns (docs/north-south.md).
	// The VPC's boundary is its OLDEST gateway; a second one realizes nothing.
	var gws sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &gws, client.InNamespace(vpc.Namespace), client.MatchingFields{gatewayVPCIndex: vpc.Name}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPCGateways: %w", err)
	}
	gw := sdnv1alpha1.EffectiveGateway(gws.Items, vpc.Name)
	if gw == nil || !gw.Spec.NAT.Enabled {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name, vpc.UID)
	}
	// The tenant declared its own appliance as the VPC's door
	// (docs/multi-attach.md). There is exactly one door, and gateways[vni] holds
	// exactly one entry, so cozyplane must not also run a pod for it: two
	// claimants would race for the same map entry and the winner would be
	// whichever agent resynced last.
	if gw.Spec.Appliance != nil {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name, vpc.UID)
	}
	// A gateway realizes each family's egress in eBPF (vpc_nat_snat / vpc_nat_snat6)
	// when the pool could give that family an address — SNAT at the pod's own veth,
	// no pod, no hairpin, no per-VPC SPOF, the tenant's own identity on the wire
	// (docs/north-south.md §6a). The gateway pod survives ONLY as the fallback for a
	// family with no eBPF identity: a VPC family the pool cannot serve.
	//
	// So retire the pod once EVERY family the VPC has is covered in eBPF. This
	// composes: from_pod tries vpc_nat_snat{,6} BEFORE the isolation/gateway branch,
	// so a covered family never reaches the pod; an uncovered family falls through
	// to it. The pool-less case (no identity at all) keeps the pod for both families.
	v4Covered := !cidrsHaveV4(vpc.Spec.CIDRs) || gw.Status.NATAddress != ""
	v6Covered := !cidrsHaveV6(vpc.Spec.CIDRs) || gw.Status.NATAddress6 != ""
	haveIdentity := gw.Status.NATAddress != "" || gw.Status.NATAddress6 != ""
	if v4Covered && v6Covered && haveIdentity {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name, vpc.UID)
	}
	if !netid.ValidVNI(vpc.Status.VNI) {
		return ctrl.Result{}, nil // requeued by the VPC status update
	}
	if vpc.UID == "" {
		return ctrl.Result{}, fmt.Errorf("gateway VPC has no UID")
	}

	desired := r.deployment(vpc)
	existing := &appsv1.Deployment{}
	err := r.Get(ctx, client.ObjectKeyFromObject(desired), existing)
	switch {
	case apierrors.IsNotFound(err):
		if err := r.Create(ctx, desired); err != nil {
			return ctrl.Result{}, fmt.Errorf("create gateway deployment: %w", err)
		}
		logger.Info("gateway deployment created", "vpc", req.NamespacedName.String(), "deployment", desired.Name)
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get gateway deployment: %w", err)
	default:
		if existing.Annotations[gatewayVPCUIDAnnotation] != string(vpc.UID) {
			return ctrl.Result{}, fmt.Errorf("gateway deployment %q is not owned by current VPC", existing.Name)
		}
		if !equality.Semantic.DeepDerivative(desired.Spec.Template.Spec, existing.Spec.Template.Spec) ||
			!equality.Semantic.DeepDerivative(desired.Spec.Template.Annotations, existing.Spec.Template.Annotations) {
			existing.Spec = desired.Spec
			if err := r.Update(ctx, existing); err != nil {
				return ctrl.Result{}, fmt.Errorf("update gateway deployment: %w", err)
			}
			logger.Info("gateway deployment updated", "vpc", req.NamespacedName.String(), "deployment", desired.Name)
		}
	}
	return ctrl.Result{}, r.healSeveredGateway(ctx, vpc)
}

// healSeveredGateway recreates a gateway pod that is Ready but whose .1 Port
// no longer exists — the leg was severed out from under it (seen live: a
// replaced pod's asynchronous CNI DEL raced the successor's ADD during
// concurrent rollouts). The Port is claimed at CNI ADD, so only a pod
// recreation can restore it; deleting the pod lets the Deployment do that.
func (r *GatewayReconciler) healSeveredGateway(ctx context.Context, vpc *sdnv1alpha1.VPC) error {
	sel := client.MatchingLabels{
		sdnv1alpha1.LabelVPC:          vpc.Name,
		sdnv1alpha1.LabelVPCNamespace: vpc.Namespace,
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.Config.Namespace), sel); err != nil {
		return fmt.Errorf("list gateway pods: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !pod.DeletionTimestamp.IsZero() || !podReady(pod) {
			continue
		}
		owned, err := r.gatewayPodOwned(ctx, pod, vpc)
		if err != nil {
			return err
		}
		if !owned {
			continue
		}
		var ports sdnv1alpha1.PortList
		if err := r.List(ctx, &ports, sel, client.MatchingFields{vpnAppliancePodIndex: pod.Namespace + "/" + pod.Name}); err != nil {
			return fmt.Errorf("list gateway pod ports: %w", err)
		}
		havePort := false
		for i := range ports.Items {
			port := &ports.Items[i]
			if port.Spec.Gateway && port.DeletionTimestamp.IsZero() &&
				port.Spec.PodNamespace == pod.Namespace && port.Spec.PodName == pod.Name &&
				port.Spec.VPCRef == (sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}) &&
				port.Labels[sdnv1alpha1.LabelPodUID] == string(pod.UID) {
				havePort = true
				break
			}
		}
		if havePort {
			continue
		}
		if err := r.Delete(ctx, pod, client.Preconditions{UID: &pod.UID, ResourceVersion: &pod.ResourceVersion}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete severed gateway pod %q: %w", pod.Name, err)
		}
		log.FromContext(ctx).Info("recreating severed gateway pod (Ready but its gateway Port is gone)",
			"pod", pod.Name, "vpc", vpc.Namespace+"/"+vpc.Name)
	}
	return nil
}

// Only the actual Deployment/ReplicaSet chain authorizes destructive healing.
func (r *GatewayReconciler) gatewayPodOwned(ctx context.Context, pod *corev1.Pod, vpc *sdnv1alpha1.VPC) (bool, error) {
	ref := metav1.GetControllerOf(pod)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "ReplicaSet" || ref.UID == "" {
		return false, nil
	}
	rs := &appsv1.ReplicaSet{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: ref.Name}, rs); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if rs.UID != ref.UID || !rs.DeletionTimestamp.IsZero() {
		return false, nil
	}
	ref = metav1.GetControllerOf(rs)
	if ref == nil || ref.APIVersion != "apps/v1" || ref.Kind != "Deployment" || ref.UID == "" || ref.Name != r.deployment(vpc).Name {
		return false, nil
	}
	dep := &appsv1.Deployment{}
	if err := r.Get(ctx, client.ObjectKey{Namespace: pod.Namespace, Name: ref.Name}, dep); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return vpc.UID != "" && dep.UID == ref.UID && dep.DeletionTimestamp.IsZero() && dep.Annotations[gatewayVPCUIDAnnotation] == string(vpc.UID), nil
}

func podReady(pod *corev1.Pod) bool {
	for _, c := range pod.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// deleteGateways removes any gateway Deployment labeled for the VPC (looked up
// by labels, not name — the VNI-derived name is unknowable once the VPC is
// gone, and a cross-namespace ownerRef is not an option).
func (r *GatewayReconciler) deleteGateways(ctx context.Context, vpcNS, vpcName string, vpcUID types.UID) error {
	var list appsv1.DeploymentList
	if err := r.List(ctx, &list, client.InNamespace(r.Config.Namespace), client.MatchingLabels{
		"app":                         "cozyplane-gateway",
		sdnv1alpha1.LabelVPC:          vpcName,
		sdnv1alpha1.LabelVPCNamespace: vpcNS,
	}); err != nil {
		return fmt.Errorf("list gateway deployments: %w", err)
	}
	for i := range list.Items {
		dep := &list.Items[i]
		uid := dep.Annotations[gatewayVPCUIDAnnotation]
		if uid == "" || (vpcUID != "" && uid != string(vpcUID)) {
			continue
		}
		if err := r.Delete(ctx, dep, client.Preconditions{UID: &dep.UID, ResourceVersion: &dep.ResourceVersion}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete gateway deployment %q: %w", list.Items[i].Name, err)
		}
		log.FromContext(ctx).Info("gateway deployment deleted", "deployment", list.Items[i].Name)
	}
	return nil
}

// deployment renders the gateway Deployment for a VPC. Recreate strategy: the
// gateway leg claims the VPC's reserved .1 Port, and a rolling replacement
// would collide on it.
func (r *GatewayReconciler) deployment(vpc *sdnv1alpha1.VPC) *appsv1.Deployment {
	labels := map[string]string{
		"app":                         "cozyplane-gateway",
		sdnv1alpha1.LabelVPC:          vpc.Name,
		sdnv1alpha1.LabelVPCNamespace: vpc.Namespace,
	}
	args := []string{}
	if r.Config.ClusterDNS != "" {
		args = append(args, "--cluster-dns="+r.Config.ClusterDNS)
	}
	if r.Config.InternalCIDRs != "" {
		args = append(args, "--internal-cidrs="+r.Config.InternalCIDRs)
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:        fmt.Sprintf("cozyplane-gateway-%d", vpc.Status.VNI),
			Namespace:   r.Config.Namespace,
			Labels:      labels,
			Annotations: map[string]string{gatewayVPCUIDAnnotation: string(vpc.UID)},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: new(int32(1)),
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
					Annotations: map[string]string{
						sdnv1alpha1.AnnotationGatewayFor: vpc.Namespace + "/" + vpc.Name,
					},
				},
				Spec: corev1.PodSpec{
					AutomountServiceAccountToken: new(false),
					Containers: []corev1.Container{{
						Name:    "gateway",
						Image:   r.Config.Image,
						Command: []string{"/usr/local/bin/cozyplane-gateway"},
						Args:    args,
						SecurityContext: &corev1.SecurityContext{
							Privileged: new(false), AllowPrivilegeEscalation: new(false),
							Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_ADMIN", "NET_BIND_SERVICE"}},
							SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
						},
					}},
				},
			},
		},
	}
}

// SetupWithManager registers the reconciler: VPC events drive it, and gateway
// Deployment events map back to their VPC so a deleted or drifted Deployment
// self-heals.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// VPCGatewayReconciler registers the shared VPCGateway index first in main.
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPC{}).
		Watches(&appsv1.Deployment{}, handler.EnqueueRequestsFromMapFunc(r.mapDeploymentToVPC)).
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(r.mapGatewayPortToVPC)).
		Watches(&sdnv1alpha1.VPCGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCGatewayToVPC)).
		Named("gateway").
		Complete(r)
}

// mapGatewayPortToVPC enqueues a gateway Port's VPC — a deleted gateway Port
// is what the severed-gateway heal reacts to.
func (r *GatewayReconciler) mapGatewayPortToVPC(ctx context.Context, obj client.Object) []ctrl.Request {
	port, ok := obj.(*sdnv1alpha1.Port)
	if !ok || !port.Spec.Gateway {
		return nil
	}
	return []ctrl.Request{{NamespacedName: client.ObjectKey{
		Namespace: port.Spec.VPCRef.Namespace,
		Name:      port.Spec.VPCRef.Name,
	}}}
}

func (r *GatewayReconciler) mapDeploymentToVPC(ctx context.Context, obj client.Object) []ctrl.Request {
	if obj.GetNamespace() != r.Config.Namespace || obj.GetLabels()["app"] != "cozyplane-gateway" {
		return nil
	}
	ns := obj.GetLabels()[sdnv1alpha1.LabelVPCNamespace]
	name := obj.GetLabels()[sdnv1alpha1.LabelVPC]
	if ns == "" || name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: client.ObjectKey{Namespace: ns, Name: name}}}
}

// mapVPCGatewayToVPC re-drives the VPC whose boundary changed.
func (r *GatewayReconciler) mapVPCGatewayToVPC(ctx context.Context, obj client.Object) []ctrl.Request {
	gw, ok := obj.(*sdnv1alpha1.VPCGateway)
	if !ok || !vpnlimits.ObjectName(gw.Spec.VPCRef.Name) {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Namespace: gw.Namespace, Name: gw.Spec.VPCRef.Name,
	}}}
}
