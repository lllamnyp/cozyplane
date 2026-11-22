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
	"slices"

	corev1 "k8s.io/api/core/v1"
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

// PodPortClaimIndex indexes pods by the PortClaim their annotation names.
const PodPortClaimIndex = "sdn.cozystack.io/port-claim"

// PodPortClaim is the PodPortClaimIndex index function.
func PodPortClaim(obj client.Object) []string {
	if v := obj.GetAnnotations()[sdnv1alpha1.AnnotationPortClaim]; v != "" {
		return []string{v}
	}
	return nil
}

// PortClaimReconciler ties a claimed Port to its PortClaim's lifetime and active pod (docs/live-migration.md).
type PortClaimReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=portclaims,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=portclaims/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=portclaims/finalizers,verbs=update
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile converges one PortClaim and the Port bound to it.
func (r *PortClaimReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	claim := &sdnv1alpha1.PortClaim{}
	if err := r.Get(ctx, req.NamespacedName, claim); err != nil {
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		claim = nil
	}

	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelClaimNamespace: req.Namespace,
		sdnv1alpha1.LabelClaimName:      req.Name,
	}); err != nil {
		return ctrl.Result{}, fmt.Errorf("list ports of portclaim %s: %w", req, err)
	}

	if claim == nil || !claim.DeletionTimestamp.IsZero() {
		return r.release(ctx, claim, ports.Items)
	}

	// A Port of an earlier claim with the same name outlived it.
	var port *sdnv1alpha1.Port
	for i := range ports.Items {
		p := &ports.Items[i]
		if p.Labels[sdnv1alpha1.LabelClaimUID] == string(claim.UID) {
			port = p
			continue
		}
		if err := r.deletePort(ctx, p, "port of a deleted portclaim"); err != nil {
			return ctrl.Result{}, err
		}
	}
	if port == nil {
		adopted, err := r.adopt(ctx, claim)
		if err != nil {
			return ctrl.Result{}, err
		}
		port = adopted
	}

	bound := false
	if port != nil && port.DeletionTimestamp.IsZero() {
		var err error
		if bound, err = r.bind(ctx, claim, port); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, r.updateStatus(ctx, claim, port, bound)
}

// release deletes a gone or terminating claim's Ports, then drops its finalizer.
func (r *PortClaimReconciler) release(ctx context.Context, claim *sdnv1alpha1.PortClaim, ports []sdnv1alpha1.Port) (ctrl.Result, error) {
	for i := range ports {
		if err := r.deletePort(ctx, &ports[i], "portclaim deleted"); err != nil {
			return ctrl.Result{}, err
		}
	}
	if claim == nil || len(ports) > 0 || !slices.Contains(claim.Finalizers, sdnv1alpha1.FinalizerPortClaim) {
		return ctrl.Result{}, nil // the Port's deletion re-enqueues the claim
	}
	claim.Finalizers = slices.DeleteFunc(claim.Finalizers, func(f string) bool { return f == sdnv1alpha1.FinalizerPortClaim })
	if err := r.Update(ctx, claim); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("release portclaim finalizer: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *PortClaimReconciler) deletePort(ctx context.Context, p *sdnv1alpha1.Port, why string) error {
	if !p.DeletionTimestamp.IsZero() {
		return nil
	}
	if err := r.Delete(ctx, p); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete port %s: %w", p.Name, err)
	}
	log.FromContext(ctx).Info("deleted claimed port", "port", p.Name, "reason", why)
	return nil
}

// adopt binds a pre-PortClaim VM Port whose vm-name is the claim's name to the claim.
func (r *PortClaimReconciler) adopt(ctx context.Context, claim *sdnv1alpha1.PortClaim) (*sdnv1alpha1.Port, error) {
	var legacy sdnv1alpha1.PortList
	if err := r.List(ctx, &legacy, client.MatchingLabels{
		sdnv1alpha1.LabelVMName:       claim.Name,
		sdnv1alpha1.LabelPodNamespace: claim.Namespace,
		sdnv1alpha1.LabelVPCNamespace: claim.Spec.VPCRef.Namespace,
		sdnv1alpha1.LabelVPC:          claim.Spec.VPCRef.Name,
	}); err != nil {
		return nil, fmt.Errorf("list legacy ports for portclaim %s/%s: %w", claim.Namespace, claim.Name, err)
	}
	for i := range legacy.Items {
		p := &legacy.Items[i]
		if !p.DeletionTimestamp.IsZero() || p.Labels[sdnv1alpha1.LabelClaimUID] != "" ||
			(claim.Spec.IP != "" && claim.Spec.IP != p.Spec.IP) {
			continue
		}
		delete(p.Labels, sdnv1alpha1.LabelVMName)
		p.Labels[sdnv1alpha1.LabelClaimNamespace] = claim.Namespace
		p.Labels[sdnv1alpha1.LabelClaimName] = claim.Name
		p.Labels[sdnv1alpha1.LabelClaimUID] = string(claim.UID)
		if claim.Spec.MAC != "" {
			p.Spec.MAC = claim.Spec.MAC
		}
		if err := r.Update(ctx, p); err != nil {
			return nil, fmt.Errorf("adopt port %s: %w", p.Name, err)
		}
		log.FromContext(ctx).Info("adopted legacy VM port", "port", p.Name, "portclaim", claim.Namespace+"/"+claim.Name)
		return p, nil
	}
	return nil, nil
}

// bind points the Port at the claim's active pod or detaches it, and reports whether a pod holds it.
func (r *PortClaimReconciler) bind(ctx context.Context, claim *sdnv1alpha1.PortClaim, port *sdnv1alpha1.Port) (bool, error) {
	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(claim.Namespace),
		client.MatchingFields{PodPortClaimIndex: claim.Name}); err != nil {
		return false, fmt.Errorf("list pods of portclaim %s/%s: %w", claim.Namespace, claim.Name, err)
	}
	active := activePod(livePods(pods.Items), port.Spec.Node)

	if active == nil {
		if port.Spec.Node == "" || len(livePods(pods.Items)) > 0 {
			return false, nil // detached already, or several candidates and none current
		}
		port.Spec.Node, port.Spec.NodeIP = "", ""
		if err := r.Update(ctx, port); err != nil {
			return false, err
		}
		log.FromContext(ctx).Info("detached claimed port; no pod holds it", "port", port.Name)
		return false, nil
	}

	nodeIP, err := r.nodeInternalIP(ctx, active.Spec.NodeName)
	if err != nil {
		return true, err
	}
	if port.Spec.Node == active.Spec.NodeName && port.Spec.NodeIP == nodeIP &&
		port.Labels[sdnv1alpha1.LabelPodUID] == string(active.UID) {
		return true, nil
	}
	moved := port.Spec.Node != active.Spec.NodeName
	port.Spec.Node = active.Spec.NodeName
	port.Spec.NodeIP = nodeIP
	port.Spec.PodNamespace = active.Namespace
	port.Spec.PodName = active.Name
	port.Labels[sdnv1alpha1.LabelPodNamespace] = active.Namespace
	port.Labels[sdnv1alpha1.LabelPodName] = active.Name
	port.Labels[sdnv1alpha1.LabelPodUID] = string(active.UID)
	if err := r.Update(ctx, port); err != nil {
		return true, err
	}
	if moved {
		log.FromContext(ctx).Info("claimed port re-pointed", "port", port.Name, "node", active.Spec.NodeName, "pod", active.Name)
	}
	return true, nil
}

// livePods returns the pods that are scheduled and neither terminating nor finished.
func livePods(pods []corev1.Pod) []*corev1.Pod {
	var live []*corev1.Pod
	for i := range pods {
		p := &pods[i]
		if p.DeletionTimestamp == nil && p.Spec.NodeName != "" &&
			p.Status.Phase != corev1.PodSucceeded && p.Status.Phase != corev1.PodFailed {
			live = append(live, p)
		}
	}
	return live
}

// activePod returns the live pod on the Port's node, else the only live pod, else nil.
func activePod(live []*corev1.Pod, node string) *corev1.Pod {
	for _, p := range live {
		if node != "" && p.Spec.NodeName == node {
			return p
		}
	}
	if len(live) == 1 {
		return live[0]
	}
	return nil
}

func (r *PortClaimReconciler) updateStatus(ctx context.Context, claim *sdnv1alpha1.PortClaim, port *sdnv1alpha1.Port, bound bool) error {
	status := *claim.Status.DeepCopy()
	if port != nil {
		status.IP, status.MAC = port.Spec.IP, port.Spec.MAC
	}
	cond := metav1.Condition{Type: sdnv1alpha1.PortClaimConditionBound, Status: metav1.ConditionTrue,
		Reason: "PodBound", Message: "a live pod holds the claim's Port", ObservedGeneration: claim.Generation}
	switch {
	case port == nil:
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "NoPort", "no pod has bound the claim yet"
	case !bound:
		cond.Status, cond.Reason, cond.Message = metav1.ConditionFalse, "Detached", "the claim's Port is reserved; no pod holds it"
	}
	meta.SetStatusCondition(&status.Conditions, cond)
	if status.IP == claim.Status.IP && status.MAC == claim.Status.MAC &&
		meta.IsStatusConditionPresentAndEqual(claim.Status.Conditions, cond.Type, cond.Status) &&
		meta.FindStatusCondition(claim.Status.Conditions, cond.Type).Reason == cond.Reason {
		return nil
	}
	claim.Status = status
	if err := r.Status().Update(ctx, claim); err != nil && !apierrors.IsConflict(err) {
		return fmt.Errorf("update portclaim status: %w", err)
	}
	return nil
}

func (r *PortClaimReconciler) nodeInternalIP(ctx context.Context, name string) (string, error) {
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

// SetupWithManager registers the reconciler, re-enqueued by changes to its Ports and pods.
func (r *PortClaimReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &corev1.Pod{}, PodPortClaimIndex, PodPortClaim); err != nil {
		return fmt.Errorf("index pods by portclaim: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.PortClaim{}).
		Watches(&sdnv1alpha1.Port{}, handler.EnqueueRequestsFromMapFunc(mapPortToClaim)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(mapPodToClaim)).
		Named("portclaim").
		Complete(r)
}

// mapPortToClaim enqueues the claim a Port belongs to, or the one that would adopt it.
func mapPortToClaim(_ context.Context, obj client.Object) []ctrl.Request {
	l := obj.GetLabels()
	switch {
	case l[sdnv1alpha1.LabelClaimName] != "":
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: l[sdnv1alpha1.LabelClaimNamespace], Name: l[sdnv1alpha1.LabelClaimName]}}}
	case l[sdnv1alpha1.LabelVMName] != "":
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: l[sdnv1alpha1.LabelPodNamespace], Name: l[sdnv1alpha1.LabelVMName]}}}
	}
	return nil
}

// mapPodToClaim enqueues the claim a pod's annotation names.
func mapPodToClaim(_ context.Context, obj client.Object) []ctrl.Request {
	if names := PodPortClaim(obj); len(names) == 1 {
		return []ctrl.Request{{NamespacedName: types.NamespacedName{Namespace: obj.GetNamespace(), Name: names[0]}}}
	}
	return nil
}
