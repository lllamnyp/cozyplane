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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// PortGCReconciler reaps abandoned Ports the normal lifecycle misses:
//
//   - it strips the sever finalizer from *terminating* Ports whose node no
//     longer exists — the agent that would acknowledge the sever is never
//     coming back, and the workload died with its node;
//   - it deletes *live* Ports whose claimant pod is gone (the pod in the
//     Port's pod labels no longer exists, or its UID differs). A pod that dies
//     uncleanly (node reboot, forced eviction) never runs CNI DEL, so its Port
//     leaks; for a gateway pod that wedges the replacement forever — the fixed
//     .1 claim fails AlreadyExists and the pod stays ContainerCreating. GC
//     frees the name; the kubelet's next ADD retry claims it fresh. VM
//     persistent Ports are exempt: the PersistentPortReconciler owns their
//     lifecycle, and a launcher pod's absence must not release the pinned
//     IP+MAC.
type PortGCReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// Reader confirms a claimant pod's absence against the API server directly
	// (mgr.GetAPIReader()): the informer cache can lag a just-created pod, and
	// GC must not kill a newborn Port on a stale read. Falls back to Client
	// when nil (tests).
	Reader client.Reader
}

func (r *PortGCReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

const (
	gcPortNodeIndex = "cozyplane.portgc.node"
	gcPortPodIndex  = "cozyplane.portgc.pod"
)

func gcPortNodeKeys(obj client.Object) []string {
	port := obj.(*sdnv1alpha1.Port)
	if port.Spec.Node == "" {
		return nil
	}
	return []string{port.Spec.Node}
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

// Reconcile releases the sever finalizer when the Port's node is gone, and
// deletes a live Port whose claimant pod is gone.
func (r *PortGCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	port := &sdnv1alpha1.Port{}
	if err := r.Get(ctx, req.NamespacedName, port); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if port.DeletionTimestamp.IsZero() {
		return r.reapIfAbandoned(ctx, port)
	}
	if !slices.Contains(port.Finalizers, sdnv1alpha1.FinalizerSever) {
		return ctrl.Result{}, nil
	}
	if port.Spec.Node != "" {
		err := r.Get(ctx, types.NamespacedName{Name: port.Spec.Node}, &corev1.Node{})
		if err == nil {
			return ctrl.Result{}, nil // the node's agent owns the acknowledgement
		}
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("get node %q: %w", port.Spec.Node, err)
		}
		err = r.reader().Get(ctx, types.NamespacedName{Name: port.Spec.Node}, &corev1.Node{})
		if err == nil {
			return ctrl.Result{}, nil // cache has not observed the live node yet
		}
		if !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("confirm node %q absent: %w", port.Spec.Node, err)
		}
	}

	port.Finalizers = slices.DeleteFunc(port.Finalizers, func(f string) bool {
		return f == sdnv1alpha1.FinalizerSever
	})
	if err := r.Update(ctx, port); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("release sever finalizer: %w", err)
	}
	log.FromContext(ctx).Info("released sever finalizer for a port whose node is gone",
		"port", port.Name, "node", port.Spec.Node)
	return ctrl.Result{}, nil
}

// reapIfAbandoned deletes a live Port whose claimant pod is gone. The claimant
// is the pod recorded in the Port's pod labels at claim time; UID mismatch
// means the name was reused by a new pod, so the old claimant is gone too.
func (r *PortGCReconciler) reapIfAbandoned(ctx context.Context, port *sdnv1alpha1.Port) (ctrl.Result, error) {
	if port.Labels[sdnv1alpha1.LabelVMName] != "" {
		return ctrl.Result{}, nil // persistent: PersistentPortReconciler owns it
	}
	podNS := port.Labels[sdnv1alpha1.LabelPodNamespace]
	podName := port.Labels[sdnv1alpha1.LabelPodName]
	podUID := port.Labels[sdnv1alpha1.LabelPodUID]
	if podNS == "" || podName == "" {
		return ctrl.Result{}, nil // no recorded claimant; not ours to judge
	}
	key := types.NamespacedName{Namespace: podNS, Name: podName}
	pod := &corev1.Pod{}
	claimantActive := func() bool {
		return podUID == "" || string(pod.UID) == podUID &&
			pod.Status.Phase != corev1.PodSucceeded && pod.Status.Phase != corev1.PodFailed
	}
	err := r.Get(ctx, key, pod)
	if err == nil && claimantActive() {
		return r.reapObsoleteSandbox(ctx, port, pod)
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("get claimant pod %s: %w", key, err)
	}
	// The cache says gone, reused or terminal — confirm live before deleting: a stale
	// read on a just-created pod must not kill its newborn Port.
	err = r.reader().Get(ctx, key, pod)
	if err == nil && claimantActive() {
		return ctrl.Result{}, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("confirm claimant pod %s: %w", key, err)
	}
	if err := r.Delete(ctx, port, client.Preconditions{UID: &port.UID, ResourceVersion: &port.ResourceVersion}); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("gc abandoned port %s: %w", port.Name, err)
	}
	log.FromContext(ctx).Info("GC'd abandoned port; claimant pod is gone or terminal",
		"port", port.Name, "pod", podNS+"/"+podName, "gateway", port.Spec.Gateway)
	return ctrl.Result{}, nil
}

// deletionsOnly admits only Delete events.
//
// Both auxiliary watches below exist for exactly one signal — an object going
// away — but without a predicate they fired on Add and Update too, and a Node
// Update is a heartbeat: every node posts one every few seconds. Each of those
// ran mapNodeToPorts, which lists EVERY Port in the cluster and filters in Go.
// On a hundred nodes that was a full Port list several times a second, and a
// re-enqueue of every Port each time, for events that can never change the
// answer. Nothing was wrong with the verdict; it was just being recomputed for
// no reason, forever.
//
// Delete-only is safe for the startup case too: a pod or node that vanished
// while the controller was down produces no Delete event on restart, but the
// For(&Port{}) informer's initial sync enqueues every Port anyway, so the sweep
// still happens.
var deletionsOnly = predicate.Funcs{
	CreateFunc:  func(event.CreateEvent) bool { return false },
	UpdateFunc:  func(event.UpdateEvent) bool { return false },
	GenericFunc: func(event.GenericEvent) bool { return false },
	DeleteFunc:  func(event.DeleteEvent) bool { return true },
}

// SetupWithManager registers the reconciler: Port events drive it, a deleted
// Node re-enqueues that node's Ports (they may already be terminating, with no
// further Port event coming), and a deleted Pod re-enqueues the Ports it
// claims (an abandoned Port gets no further Port event either). Both auxiliary
// watches are delete-scoped — see deletionsOnly.
func (r *PortGCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	indexer := mgr.GetFieldIndexer()
	if err := indexer.IndexField(context.Background(), &sdnv1alpha1.Port{}, gcPortNodeIndex, gcPortNodeKeys); err != nil {
		return err
	}
	if err := indexer.IndexField(context.Background(), &sdnv1alpha1.Port{}, gcPortPodIndex, membershipPodKeys); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Port{}).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNodeToPorts)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToPorts)).
		Watches(&localv1alpha1.FabricIP{}, handler.EnqueueRequestsFromMapFunc(r.mapFabricIPToPorts)).
		Named("portgc").
		Complete(r)
}

// mapPodToPorts re-enqueues the Ports claimed by a pod (labels written at CNI
// ADD), so a pod deletion revisits the Ports it may have abandoned.
func (r *PortGCReconciler) mapPodToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.mapClaimantToPorts(ctx, obj.GetNamespace(), obj.GetName())
}

func (r *PortGCReconciler) mapFabricIPToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	claim := obj.(*localv1alpha1.FabricIP)
	return r.mapClaimantToPorts(ctx, claim.Spec.PodNamespace, claim.Spec.PodName)
}

func (r *PortGCReconciler) mapClaimantToPorts(ctx context.Context, namespace, name string) []ctrl.Request {
	if namespace == "" || name == "" {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingFields{gcPortPodIndex: namespace + "/" + name}); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: ports.Items[i].Name}})
	}
	return reqs
}

func (r *PortGCReconciler) mapNodeToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingFields{gcPortNodeIndex: obj.GetName()}); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		if ports.Items[i].Spec.Node == obj.GetName() {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: ports.Items[i].Name}})
		}
	}
	return reqs
}
