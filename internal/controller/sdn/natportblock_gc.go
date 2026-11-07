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
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	localsdnv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// DefaultNATNodeGoneGrace is how long a lease outlives its node's Node object:
// one TCP-established timeout (docs/vpc-egress.md §4.3).
const DefaultNATNodeGoneGrace = 7440 * time.Second

// NATPortBlockGCReconciler deletes the leases of deleted NAT gateways, and of
// nodes whose Node object has been gone for the grace period.
type NATPortBlockGCReconciler struct {
	client.Client
	// NodeGoneGrace is how long a gone node's leases survive.
	NodeGoneGrace time.Duration

	mu       sync.Mutex
	goneSeen map[string]time.Time // node -> when this controller first saw it gone
}

// Reconcile deletes one lease if its NAT gateway or node is gone.
func (r *NATPortBlockGCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := &localsdnv1alpha1.NATPortBlock{}
	if err := r.Get(ctx, req.NamespacedName, l); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ref := l.Spec.NATGatewayRef
	ngw := &sdnv1alpha1.NATGateway{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, ngw)
	switch {
	case apierrors.IsNotFound(err) || (err == nil && ngw.UID != ref.UID):
		return ctrl.Result{}, r.delete(ctx, l, "its NAT gateway is gone")
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("fetch NATGateway: %w", err)
	}

	err = r.Get(ctx, types.NamespacedName{Name: l.Spec.Node}, &corev1.Node{})
	if err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("fetch Node: %w", err)
	}
	r.mu.Lock()
	if r.goneSeen == nil {
		r.goneSeen = map[string]time.Time{}
	}
	if err == nil {
		delete(r.goneSeen, l.Spec.Node)
		r.mu.Unlock()
		return ctrl.Result{}, nil
	}
	since, ok := r.goneSeen[l.Spec.Node]
	if !ok {
		since = time.Now()
		r.goneSeen[l.Spec.Node] = since
	}
	r.mu.Unlock()
	grace := r.NodeGoneGrace
	if grace <= 0 {
		grace = DefaultNATNodeGoneGrace
	}
	if left := grace - time.Since(since); left > 0 {
		return ctrl.Result{RequeueAfter: left}, nil
	}
	return ctrl.Result{}, r.delete(ctx, l, "its node has been gone for the grace period")
}

func (r *NATPortBlockGCReconciler) delete(ctx context.Context, l *localsdnv1alpha1.NATPortBlock, why string) error {
	if err := r.Delete(ctx, l); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("delete NATPortBlock: %w", err)
	}
	log.FromContext(ctx).Info("deleted NAT port block lease", "lease", l.Name, "reason", why)
	return nil
}

// SetupWithManager wires the controller. Node and NAT gateway events re-check
// the leases they hold.
func (r *NATPortBlockGCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&localsdnv1alpha1.NATPortBlock{}).
		Watches(&corev1.Node{}, handler.EnqueueRequestsFromMapFunc(r.mapNode)).
		Watches(&sdnv1alpha1.NATGateway{}, handler.EnqueueRequestsFromMapFunc(r.mapNATGateway)).
		Named("natportblock-gc").
		Complete(r)
}

func (r *NATPortBlockGCReconciler) mapNode(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.leases(ctx, client.MatchingLabels{localsdnv1alpha1.LabelNATBlockNode: obj.GetName()})
}

func (r *NATPortBlockGCReconciler) mapNATGateway(ctx context.Context, obj client.Object) []ctrl.Request {
	return r.leases(ctx, client.MatchingLabels{localsdnv1alpha1.LabelNATGatewayUID: string(obj.GetUID())})
}

func (r *NATPortBlockGCReconciler) leases(ctx context.Context, sel client.MatchingLabels) []ctrl.Request {
	var list localsdnv1alpha1.NATPortBlockList
	if err := r.List(ctx, &list, sel); err != nil {
		return nil
	}
	out := make([]ctrl.Request, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, ctrl.Request{NamespacedName: types.NamespacedName{Name: list.Items[i].Name}})
	}
	return out
}
