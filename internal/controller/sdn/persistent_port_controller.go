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

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// PersistentPortReconciler drives live migration for a VM NIC's persistent Port
// (one carrying the sdn.cozystack.io/vm-name label). Its two jobs:
//
//   - Cutover: keep the Port's active binding (spec.node/nodeIP/fabricIP + the
//     pod labels) pointing at the *active* virt-launcher pod — the one whose
//     kubevirt.io/nodeName equals its own node (KubeVirt sets that on the
//     migration target only after cutover). The agent turns spec.node into the
//     `remotes` location, so re-pointing here re-routes the VPC IP to the node
//     the VM now runs on; the VPC IP + MAC never change. This is the same move
//     OVN-Kubernetes makes on a logical-switch-port that changes chassis.
//   - GC: delete the persistent Port once no virt-launcher pod for its VM exists
//     (the VM was stopped or deleted). A single pod's CNI DEL never deletes it,
//     so the IP + MAC survive pod churn and migration.
type PersistentPortReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile keeps one persistent Port's binding on the active virt-launcher pod,
// or GCs it when the VM's pods are gone.
func (r *PersistentPortReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	port := &sdnv1alpha1.Port{}
	if err := r.Get(ctx, req.NamespacedName, port); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	vmName := port.Labels[sdnv1alpha1.LabelVMName]
	if vmName == "" || !port.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // not a persistent Port, or already terminating
	}

	// All virt-launcher pods of this VM (any phase), in the pod's namespace.
	var pods corev1.PodList
	if err := r.List(ctx, &pods,
		client.InNamespace(port.Spec.PodNamespace),
		client.MatchingLabels{sdnv1alpha1.KubeVirtLabelVMName: vmName},
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("list virt-launcher pods for vm %q: %w", vmName, err)
	}

	// No pods (any phase) ⇒ the VM is gone; GC the Port so its IP is freed. The
	// sever finalizer still drains the owning node's datapath first.
	if len(pods.Items) == 0 {
		if err := r.Delete(ctx, port); err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("gc persistent port %s: %w", port.Name, err)
		}
		log.FromContext(ctx).Info("GC'd persistent port; no virt-launcher pods remain", "port", port.Name, "vm", vmName)
		return ctrl.Result{}, nil
	}

	// The active pod is the running launcher whose kubevirt.io/nodeName equals its
	// own node. During a migration only the source has it until cutover, when
	// KubeVirt moves it to the target — which is exactly the flip we mirror.
	active := activeLauncher(pods.Items)
	if active == nil {
		return ctrl.Result{}, nil // all pods still starting; keep the current binding
	}

	nodeIP, err := r.nodeInternalIP(ctx, active.Spec.NodeName)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The active pod's status.podIP is its fabric IP (cozyplane reports the fabric
	// IP as the pod IP). It changes per pod; the VPC IP/MAC do not.
	if port.Spec.Node == active.Spec.NodeName &&
		port.Spec.NodeIP == nodeIP &&
		port.Spec.FabricIP == active.Status.PodIP &&
		port.Labels[sdnv1alpha1.LabelPodUID] == string(active.UID) {
		return ctrl.Result{}, nil // binding already current
	}

	port.Spec.Node = active.Spec.NodeName
	port.Spec.NodeIP = nodeIP
	if active.Status.PodIP != "" {
		port.Spec.FabricIP = active.Status.PodIP
	}
	port.Spec.PodNamespace = active.Namespace
	port.Spec.PodName = active.Name
	if port.Labels == nil {
		port.Labels = map[string]string{}
	}
	port.Labels[sdnv1alpha1.LabelPodNamespace] = active.Namespace
	port.Labels[sdnv1alpha1.LabelPodName] = active.Name
	port.Labels[sdnv1alpha1.LabelPodUID] = string(active.UID)
	if err := r.Update(ctx, port); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("re-point persistent port %s to %s: %w", port.Name, active.Spec.NodeName, err)
	}
	log.FromContext(ctx).Info("migration cutover: persistent port re-pointed",
		"port", port.Name, "vm", vmName, "node", active.Spec.NodeName, "vpcIP", port.Spec.IP)
	return ctrl.Result{}, nil
}

// activeLauncher returns the running virt-launcher pod that currently owns the
// VM (kubevirt.io/nodeName == its node), or nil if none is active yet.
func activeLauncher(pods []corev1.Pod) *corev1.Pod {
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp != nil || p.Status.Phase != corev1.PodRunning {
			continue
		}
		if p.Spec.NodeName != "" && p.Labels[sdnv1alpha1.KubeVirtLabelNodeName] == p.Spec.NodeName {
			return p
		}
	}
	return nil
}

func (r *PersistentPortReconciler) nodeInternalIP(ctx context.Context, name string) (string, error) {
	var node corev1.Node
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &node); err != nil {
		return "", fmt.Errorf("get node %q: %w", name, err)
	}
	for _, a := range node.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			return a.Address, nil
		}
	}
	return "", fmt.Errorf("node %q has no InternalIP", name)
}

// SetupWithManager registers the reconciler: persistent Ports drive it, and a
// virt-launcher pod change re-enqueues the persistent Port of its VM (so the
// cutover fires when KubeVirt sets kubevirt.io/nodeName on the target).
func (r *PersistentPortReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Port{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToPort)).
		Named("persistentport").
		Complete(r)
}

func (r *PersistentPortReconciler) mapPodToPort(ctx context.Context, obj client.Object) []ctrl.Request {
	vmName := obj.GetLabels()[sdnv1alpha1.KubeVirtLabelVMName]
	if vmName == "" {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelVMName: vmName,
	}); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		if ports.Items[i].Spec.PodNamespace == obj.GetNamespace() {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: ports.Items[i].Name}})
		}
	}
	return reqs
}
