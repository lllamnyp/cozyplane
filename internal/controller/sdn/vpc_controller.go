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
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// firstVNI is the lowest network id handed out to VPCs. Ids below it are
// reserved (0 is the default/system network).
const firstVNI int32 = 100

// VPCReconciler assigns each VPC a unique network id (VNI) and marks it Ready.
// The datapath (agent) keys isolation and the overlay on this id.
type VPCReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs/status,verbs=get;update;patch

// Reconcile assigns a VNI to the VPC if it has none, then sets phase Ready.
func (r *VPCReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, req.NamespacedName, vpc); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
	}

	if vpc.Status.VNI == 0 {
		vni, err := r.allocateVNI(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		vpc.Status.VNI = vni
	}
	vpc.Status.Phase = sdnv1alpha1.VPCPhaseReady

	if err := r.Status().Update(ctx, vpc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPC status: %w", err)
	}

	logger.Info("VPC ready", "name", vpc.Name, "vni", vpc.Status.VNI)
	return ctrl.Result{}, nil
}

// allocateVNI returns the lowest VNI >= firstVNI not used by any other VPC.
func (r *VPCReconciler) allocateVNI(ctx context.Context) (int32, error) {
	var list sdnv1alpha1.VPCList
	if err := r.List(ctx, &list); err != nil {
		return 0, fmt.Errorf("list VPCs: %w", err)
	}
	used := map[int32]bool{}
	for i := range list.Items {
		if v := list.Items[i].Status.VNI; v != 0 {
			used[v] = true
		}
	}
	for vni := firstVNI; ; vni++ {
		if !used[vni] {
			return vni, nil
		}
	}
}

// SetupWithManager registers the reconciler with the manager.
func (r *VPCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPC{}).
		Named("vpc").
		Complete(r)
}
