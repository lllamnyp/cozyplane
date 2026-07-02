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
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
//
// INTERIM (stage 1): a VPC whose CIDR overlaps an already-Ready VPC or a
// reserved cluster CIDR is held Pending. Overlap is the design target
// (isolation is by overlay, not address space), but the stage-1 datapath
// delivers by IP-keyed maps and kernel /32 routes, so two VPCs claiming the
// same address today would cross traffic. This gate — not the API — is the
// enforcement point, and it is deleted when stage-2 (VNI-scoped) delivery
// lands. The permanent rule that survives stage 2 is only that *peered* VPCs
// be disjoint.
type VPCReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// ReservedCIDRs are cluster networks (pod, service) a stage-1 VPC may not
	// overlap. Removed together with the gate at stage 2.
	ReservedCIDRs []string
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

	// INTERIM stage-1 gate: withhold the VNI while the CIDR collides (see the
	// reconciler comment). Requeue on a timer — the conflicting VPC's removal
	// does not enqueue this one.
	if vpc.Status.VNI == 0 {
		if conflict, err := r.cidrConflict(ctx, vpc); err != nil {
			return ctrl.Result{}, err
		} else if conflict != "" {
			vpc.Status.Phase = sdnv1alpha1.VPCPhasePending
			meta.SetStatusCondition(&vpc.Status.Conditions, metav1.Condition{
				Type:    "CIDRAvailable",
				Status:  metav1.ConditionFalse,
				Reason:  "CIDROverlap",
				Message: "CIDR overlaps " + conflict + "; overlapping VPC CIDRs await VNI-scoped (stage-2) datapath delivery",
			})
			if err := r.Status().Update(ctx, vpc); err != nil && !apierrors.IsConflict(err) {
				return ctrl.Result{}, fmt.Errorf("update VPC status: %w", err)
			}
			return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
		}
		vni, err := r.allocateVNI(ctx)
		if err != nil {
			return ctrl.Result{}, err
		}
		vpc.Status.VNI = vni
	}
	vpc.Status.Phase = sdnv1alpha1.VPCPhaseReady
	meta.SetStatusCondition(&vpc.Status.Conditions, metav1.Condition{
		Type:   "CIDRAvailable",
		Status: metav1.ConditionTrue,
		Reason: "CIDRAvailable",
	})

	if err := r.Status().Update(ctx, vpc); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPC status: %w", err)
	}

	logger.Info("VPC ready", "name", vpc.Name, "vni", vpc.Status.VNI)
	return ctrl.Result{}, nil
}

// cidrConflict returns a description of what the VPC's CIDR collides with —
// a VPC that already holds a VNI, or a reserved cluster CIDR — or "".
func (r *VPCReconciler) cidrConflict(ctx context.Context, vpc *sdnv1alpha1.VPC) (string, error) {
	if sdnv1alpha1.CIDRsOverlap(vpc.Spec.CIDRs, r.ReservedCIDRs) {
		return "a reserved cluster CIDR", nil
	}
	var list sdnv1alpha1.VPCList
	if err := r.List(ctx, &list); err != nil {
		return "", fmt.Errorf("list VPCs: %w", err)
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Status.VNI == 0 || (other.Namespace == vpc.Namespace && other.Name == vpc.Name) {
			continue
		}
		if sdnv1alpha1.CIDRsOverlap(vpc.Spec.CIDRs, other.Spec.CIDRs) {
			return "VPC " + other.Namespace + "/" + other.Name, nil
		}
	}
	return "", nil
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
