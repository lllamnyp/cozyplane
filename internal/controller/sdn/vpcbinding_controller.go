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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// vpcBindingFinalizer holds the binding until its authorized Ports are reaped,
// so deleting a VPCBinding actually severs the pods it permitted.
const vpcBindingFinalizer = "sdn.cozystack.io/reap-ports"

// VPCBindingReconciler reaps the Ports a VPCBinding authorized when it is
// deleted. A Port is reaped only if no *other* live binding in the same
// (consumer) namespace still authorizes the same VPC. Deleting the Ports makes
// the agents tear down the corresponding datapath (cross-node remote routes and,
// on the pod's own node, the live local datapath — see datapath.SeverLocal).
type VPCBindingReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcbindings,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;delete

// Reconcile maintains the reap finalizer and reaps Ports on deletion.
func (r *VPCBindingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	binding := &sdnv1alpha1.VPCBinding{}
	if err := r.Get(ctx, req.NamespacedName, binding); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if binding.DeletionTimestamp.IsZero() {
		if controllerutil.AddFinalizer(binding, vpcBindingFinalizer) {
			if err := r.Update(ctx, binding); err != nil {
				return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
			}
		}
		return ctrl.Result{}, nil
	}

	// Being deleted.
	if controllerutil.ContainsFinalizer(binding, vpcBindingFinalizer) {
		reaped, err := r.reapPorts(ctx, binding)
		if err != nil {
			return ctrl.Result{}, err
		}
		if reaped > 0 {
			logger.Info("reaped ports for revoked binding", "binding", req.NamespacedName.String(),
				"vpc", binding.Spec.VPCRef.Namespace+"/"+binding.Spec.VPCRef.Name, "count", reaped)
		}
		controllerutil.RemoveFinalizer(binding, vpcBindingFinalizer)
		if err := r.Update(ctx, binding); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
		}
	}
	return ctrl.Result{}, nil
}

// reapPorts deletes the Ports for pods in the binding's namespace attached to the
// referenced VPC, unless another live binding in that namespace still authorizes
// it. Returns the number of Ports deleted.
func (r *VPCBindingReconciler) reapPorts(ctx context.Context, binding *sdnv1alpha1.VPCBinding) (int, error) {
	ref := binding.Spec.VPCRef
	consumerNS := binding.Namespace

	// If another, still-live binding in this namespace authorizes the same VPC,
	// the pods stay; reaping waits until the last grant is gone.
	var bindings sdnv1alpha1.VPCBindingList
	if err := r.List(ctx, &bindings, client.InNamespace(consumerNS)); err != nil {
		return 0, fmt.Errorf("list vpcbindings: %w", err)
	}
	for i := range bindings.Items {
		other := &bindings.Items[i]
		if other.Name == binding.Name || !other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.Spec.VPCRef == ref {
			return 0, nil
		}
	}

	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelVPCNamespace: ref.Namespace,
		sdnv1alpha1.LabelVPC:          ref.Name,
		sdnv1alpha1.LabelPodNamespace: consumerNS,
	}); err != nil {
		return 0, fmt.Errorf("list ports: %w", err)
	}

	reaped := 0
	for i := range ports.Items {
		if err := r.Delete(ctx, &ports.Items[i]); err != nil {
			if apierrors.IsNotFound(err) {
				continue
			}
			return reaped, fmt.Errorf("delete port %q: %w", ports.Items[i].Name, err)
		}
		reaped++
	}
	return reaped, nil
}

// SetupWithManager registers the reconciler with the manager.
func (r *VPCBindingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCBinding{}).
		Named("vpcbinding").
		Complete(r)
}
