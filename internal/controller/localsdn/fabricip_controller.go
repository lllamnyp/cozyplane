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

package localsdn

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
)

// FabricIPReconciler reclaims underlay addresses whose pod is gone.
//
// This is the GC that host-local never had. Its file store released a
// reservation only when a CNI DEL ran, so a pod that vanished while kubelet was
// down leaked its address across the reboot — permanently, invisibly, until the
// node's range filled with ghosts and new pods hung in ContainerCreating with
// "no IP addresses available in range set". The address is an object now, so
// the pod going away is enough.
//
// The claim is keyed on pod UID, not name: a pod that reuses a dead pod's name
// must never have its address reaped out from under it. (Same lesson as Port's
// GC, which has keyed on UID from the start.)
type FabricIPReconciler struct {
	client.Client
}

// +kubebuilder:rbac:groups=local.sdn.cozystack.io,resources=fabricips,verbs=get;list;watch;create;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *FabricIPReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var fip localv1alpha1.FabricIP
	if err := r.Get(ctx, req.NamespacedName, &fip); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if fip.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}
	// A claim with no pod recorded is not ours to judge (hand-made, or a future
	// claimant like a node's own address). Leave it alone.
	if fip.Spec.PodNamespace == "" || fip.Spec.PodName == "" {
		return ctrl.Result{}, nil
	}

	var pod corev1.Pod
	err := r.Get(ctx, types.NamespacedName{Namespace: fip.Spec.PodNamespace, Name: fip.Spec.PodName}, &pod)
	switch {
	case apierrors.IsNotFound(err):
		// The pod is gone: reclaim.
	case err != nil:
		return ctrl.Result{}, fmt.Errorf("get claiming pod: %w", err)
	default:
		// A pod with this name exists. It is only the SAME pod if the UID
		// matches — otherwise the name was reused and this claim belongs to a
		// dead predecessor, which is exactly the case that must still be reaped.
		if fip.Spec.PodUID == "" || string(pod.UID) == fip.Spec.PodUID {
			return ctrl.Result{}, nil
		}
		logger.Info("reclaiming fabric IP: pod name reused by a different UID",
			"address", fip.Spec.Address, "pod", fip.Spec.PodName)
	}

	if err := r.Delete(ctx, &fip); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, fmt.Errorf("reclaim FabricIP %s: %w", fip.Name, err)
	}
	logger.Info("reclaimed fabric IP", "address", fip.Spec.Address,
		"pod", fip.Spec.PodNamespace+"/"+fip.Spec.PodName, "node", fip.Spec.Node)
	return ctrl.Result{}, nil
}

// mapPodToFabricIPs enqueues the claims a pod holds when the pod changes — the
// deletion event is what makes reclamation prompt rather than resync-bound.
func (r *FabricIPReconciler) mapPodToFabricIPs(ctx context.Context, obj client.Object) []ctrl.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	var fips localv1alpha1.FabricIPList
	if err := r.List(ctx, &fips); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range fips.Items {
		f := &fips.Items[i]
		if f.Spec.PodNamespace == pod.Namespace && f.Spec.PodName == pod.Name {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: f.Name}})
		}
	}
	return reqs
}

func (r *FabricIPReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&localv1alpha1.FabricIP{}).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToFabricIPs)).
		Named("fabricip").
		Complete(r)
}
