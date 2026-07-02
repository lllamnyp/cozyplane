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
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// PortGCReconciler strips the sever finalizer from terminating Ports whose
// node no longer exists: the agent that would acknowledge the sever is never
// coming back, and the workload died with its node. Without this, a Port
// reaped after a node's removal would stay terminating forever.
type PortGCReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch

// Reconcile releases the sever finalizer when the Port's node is gone.
func (r *PortGCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	port := &sdnv1alpha1.Port{}
	if err := r.Get(ctx, req.NamespacedName, port); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if port.DeletionTimestamp.IsZero() || !slices.Contains(port.Finalizers, sdnv1alpha1.FinalizerSever) {
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

// SetupWithManager registers the reconciler: Port events drive it, and a
// deleted Node re-enqueues that node's Ports (they may already be
// terminating, with no further Port event coming).
func (r *PortGCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Port{}).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNodeToPorts)).
		Named("portgc").
		Complete(r)
}

func (r *PortGCReconciler) mapNodeToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports); err != nil {
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
