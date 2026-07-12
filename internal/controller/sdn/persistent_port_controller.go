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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	// watchVMI is set when the cluster serves KubeVirt's VirtualMachineInstance
	// (kubevirt.io/v1). When true the cutover keys on the VMI's migration
	// lifecycle (status.nodeName + status.migrationState — the Kube-OVN model);
	// otherwise it falls back to the launcher pod's kubevirt.io/nodeName label.
	watchVMI bool
}

// vmiGVK is the KubeVirt VirtualMachineInstance kind, read as unstructured to
// avoid importing the (heavy) kubevirt.io/api module.
var vmiGVK = schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "VirtualMachineInstance"}

func newVMI() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetGroupVersionKind(vmiGVK)
	return u
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

	// Determine the node the VM runs on now — the cutover signal. Preferred
	// source (the Kube-OVN model): the VMI's status.nodeName, which KubeVirt
	// flips to the target at cutover. Fallback (no KubeVirt, or VMI not yet
	// readable): the launcher pod's kubevirt.io/nodeName label. Either way we
	// then bind to the launcher pod ON that node (for its fabric IP + identity).
	winnerNode := ""
	if r.watchVMI {
		if node, target, failed, ok := r.vmiCutoverState(ctx, port.Spec.PodNamespace, vmName); ok {
			winnerNode = node
			// Defer to a guest-announcement cutover (stage 3): if the Port already
			// points at the in-flight migration's target and that migration hasn't
			// failed, the guest announced itself there — the target agent flipped
			// spec.node ahead of VMI.status.nodeName. Don't revert it to the
			// lagging source; that revert is the flap the announcement is meant to
			// skip. On failure, fall through to status.nodeName (the source).
			if !failed && target != "" && port.Spec.Node == target {
				winnerNode = target
			}
		}
	}
	var active *corev1.Pod
	if winnerNode != "" {
		active = launcherOnNode(pods.Items, winnerNode)
	} else {
		active = activeLauncher(pods.Items)
	}
	if active == nil {
		return ctrl.Result{}, nil // no active launcher yet; keep the current binding
	}

	nodeIP, err := r.nodeInternalIP(ctx, active.Spec.NodeName)
	if err != nil {
		return ctrl.Result{}, err
	}
	// The cutover re-points the Port at the active launcher. It no longer copies
	// the pod's fabric address into the Port: the underlay address lives in the
	// launcher's own FabricIP object (docs/api-groups.md), so a migration that
	// changes it updates exactly one object. This used to be the sharpest
	// instance of the stale-copy bug — the fabric IP churned on every cutover
	// and the Port carried a duplicate that had to be chased.
	if port.Spec.Node == active.Spec.NodeName &&
		port.Spec.NodeIP == nodeIP &&
		port.Labels[sdnv1alpha1.LabelPodUID] == string(active.UID) {
		return ctrl.Result{}, nil // binding already current
	}

	port.Spec.Node = active.Spec.NodeName
	port.Spec.NodeIP = nodeIP
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
// VM (kubevirt.io/nodeName == its node), or nil if none is active yet. The
// fallback signal when the VMI is not available.
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

// launcherOnNode returns the running virt-launcher pod scheduled on node — the
// pod that realizes the VM on the VMI's current node (its status.podIP is the
// fabric IP the Port must point at).
func launcherOnNode(pods []corev1.Pod, node string) *corev1.Pod {
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp == nil && p.Status.Phase == corev1.PodRunning && p.Spec.NodeName == node {
			return p
		}
	}
	return nil
}

// vmiActiveNode reads the VM's current node from the VMI: status.nodeName (the
// node the active virt-launcher runs on, flipped to the target at cutover). ok
// is false when the VMI is absent or has no node yet, so the caller falls back.
func (r *PersistentPortReconciler) vmiActiveNode(ctx context.Context, namespace, vmName string) (string, bool) {
	node, _, _, ok := r.vmiCutoverState(ctx, namespace, vmName)
	return node, ok
}

// vmiCutoverState reads the VMI's cutover signals: the active node
// (status.nodeName), the in-flight migration's target node, and whether that
// migration failed. ok is false when the VMI is absent or has no node yet.
func (r *PersistentPortReconciler) vmiCutoverState(ctx context.Context, namespace, vmName string) (node, target string, failed, ok bool) {
	vmi := newVMI()
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: vmName}, vmi); err != nil {
		return "", "", false, false // no VMI (KubeVirt absent, or not this pod's VM): fall back
	}
	node, _, _ = unstructured.NestedString(vmi.Object, "status", "nodeName")
	target, _, _ = unstructured.NestedString(vmi.Object, "status", "migrationState", "targetNode")
	failed, _, _ = unstructured.NestedBool(vmi.Object, "status", "migrationState", "failed")
	return node, target, failed, node != ""
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
// virt-launcher pod change re-enqueues the persistent Port of its VM. When
// KubeVirt is installed it also watches VirtualMachineInstances, whose
// status.nodeName / status.migrationState is the phase-explicit cutover signal
// (the Kube-OVN model); otherwise it keys on the launcher pod's
// kubevirt.io/nodeName label as before.
func (r *PersistentPortReconciler) SetupWithManager(mgr ctrl.Manager) error {
	b := ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Port{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToPort)).
		Named("persistentport")

	// Watch VMIs only when the CRD is served — a cache informer on an absent
	// GVK would fail to start (cozyplane runs on clusters without KubeVirt).
	if _, err := mgr.GetRESTMapper().RESTMapping(vmiGVK.GroupKind(), vmiGVK.Version); err == nil {
		r.watchVMI = true
		b = b.Watches(newVMI(), handler.EnqueueRequestsFromMapFunc(r.mapVMIToPort))
	}
	return b.Complete(r)
}

// mapVMIToPort re-enqueues the persistent Port(s) of the VM a VMI describes
// (its name is the VM name; namespace matches the Port's pod namespace).
func (r *PersistentPortReconciler) mapVMIToPort(ctx context.Context, obj client.Object) []ctrl.Request {
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{sdnv1alpha1.LabelVMName: obj.GetName()}); err != nil {
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
