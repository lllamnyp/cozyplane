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
)

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
			return ctrl.Result{}, r.deleteGateways(ctx, req.Namespace, req.Name)
		}
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}

	// The door is a VPCGateway now, not a field on the VPC: opening one onto an
	// ExternalPool is the operator's grant, and a tenant must not be able to give
	// itself internet by flipping a bool on an object it owns (docs/north-south.md).
	// The VPC's boundary is its OLDEST gateway; a second one realizes nothing.
	var gws sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &gws, client.InNamespace(vpc.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list VPCGateways: %w", err)
	}
	gw := sdnv1alpha1.EffectiveGateway(gws.Items, vpc.Name)
	if gw == nil || !gw.Spec.NAT.Enabled {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name)
	}
	// A gateway with a NAT identity is realized in eBPF — SNAT at the pod's own
	// veth, straight out the uplink (docs/north-south.md § increment 2). No pod, no
	// hairpin, no per-VPC single point of failure, and the tenant's traffic wears
	// its own address instead of the node's. The pod remains only for a gateway
	// with no pool to draw an identity from, and goes away with it.
	if gw.Status.NATAddress != "" {
		return ctrl.Result{}, r.deleteGateways(ctx, vpc.Namespace, vpc.Name)
	}
	if vpc.Status.VNI == 0 {
		return ctrl.Result{}, nil // requeued by the VPC status update
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
		if !equality.Semantic.DeepDerivative(desired.Spec.Template.Spec.Containers, existing.Spec.Template.Spec.Containers) ||
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

	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, sel); err != nil {
		return fmt.Errorf("list gateway ports: %w", err)
	}
	havePort := map[string]bool{} // pod name -> claimed a gateway Port
	for i := range ports.Items {
		if ports.Items[i].Spec.Gateway {
			havePort[ports.Items[i].Spec.PodName] = true
		}
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(r.Config.Namespace), sel); err != nil {
		return fmt.Errorf("list gateway pods: %w", err)
	}
	for i := range pods.Items {
		pod := &pods.Items[i]
		if !pod.DeletionTimestamp.IsZero() || !podReady(pod) || havePort[pod.Name] {
			continue
		}
		if err := r.Delete(ctx, pod); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete severed gateway pod %q: %w", pod.Name, err)
		}
		log.FromContext(ctx).Info("recreating severed gateway pod (Ready but its gateway Port is gone)",
			"pod", pod.Name, "vpc", vpc.Namespace+"/"+vpc.Name)
	}
	return nil
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
func (r *GatewayReconciler) deleteGateways(ctx context.Context, vpcNS, vpcName string) error {
	var list appsv1.DeploymentList
	if err := r.List(ctx, &list, client.InNamespace(r.Config.Namespace), client.MatchingLabels{
		"app":                         "cozyplane-gateway",
		sdnv1alpha1.LabelVPC:          vpcName,
		sdnv1alpha1.LabelVPCNamespace: vpcNS,
	}); err != nil {
		return fmt.Errorf("list gateway deployments: %w", err)
	}
	for i := range list.Items {
		if err := r.Delete(ctx, &list.Items[i]); err != nil && !apierrors.IsNotFound(err) {
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
			Name:      fmt.Sprintf("cozyplane-gateway-%d", vpc.Status.VNI),
			Namespace: r.Config.Namespace,
			Labels:    labels,
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
					Containers: []corev1.Container{{
						Name:    "gateway",
						Image:   r.Config.Image,
						Command: []string{"/usr/local/bin/cozyplane-gateway"},
						Args:    args,
						// Privileged: iptables + sysctls in its own netns only.
						SecurityContext: &corev1.SecurityContext{Privileged: new(true)},
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
	if !ok || gw.Spec.VPCRef.Name == "" {
		return nil
	}
	return []ctrl.Request{{NamespacedName: types.NamespacedName{
		Namespace: gw.Namespace, Name: gw.Spec.VPCRef.Name,
	}}}
}
