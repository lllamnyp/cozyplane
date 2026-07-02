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

// VPCPeeringReconciler surfaces a peering half's liveness in its status: it is
// Ready when a reciprocal half exists and both VPCs are Ready. Status is
// observability only — the agents key the datapath on the halves' specs
// directly, so a stale status can neither hold a revoked peering open nor
// block a live one.
type VPCPeeringReconciler struct {
	client.Client

	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcpeerings,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcpeerings/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcs,verbs=get;list;watch

// Reconcile computes the peering half's phase and conditions.
func (r *VPCPeeringReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	peering := &sdnv1alpha1.VPCPeering{}
	if err := r.Get(ctx, req.NamespacedName, peering); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	matched, err := r.findReciprocal(ctx, peering)
	if err != nil {
		return ctrl.Result{}, err
	}
	localVPC := r.getVPC(ctx, peering.Namespace, peering.Spec.VPCRef.Name)
	peerVPC := r.getVPC(ctx, peering.Spec.PeerRef.Namespace, peering.Spec.PeerRef.Name)

	// Peered traffic is routed natively: overlapping VPCs may coexist, but
	// they can never peer. The agents enforce the same rule in the datapath.
	disjoint := localVPC != nil && peerVPC != nil &&
		!sdnv1alpha1.CIDRsOverlap(localVPC.Spec.CIDRs, peerVPC.Spec.CIDRs)

	status := sdnv1alpha1.VPCPeeringStatus{Phase: sdnv1alpha1.VPCPeeringPhasePending}
	setCondition(&status, sdnv1alpha1.VPCPeeringConditionMatched, matched != nil,
		"ReciprocalHalf", "a VPCPeering in the peer namespace references this half's VPC")
	setCondition(&status, sdnv1alpha1.VPCPeeringConditionVPCReady, vpcReady(localVPC),
		"VPCReady", "the local VPC exists and has a VNI")
	setCondition(&status, sdnv1alpha1.VPCPeeringConditionPeerVPCReady, vpcReady(peerVPC),
		"PeerVPCReady", "the peer VPC exists and has a VNI")
	setCondition(&status, sdnv1alpha1.VPCPeeringConditionDisjoint, disjoint,
		"CIDRsDisjoint", "the two VPCs' CIDRs do not overlap")
	if peerVPC != nil {
		status.PeerVNI = peerVPC.Status.VNI
	}
	if matched != nil && vpcReady(localVPC) && vpcReady(peerVPC) && disjoint {
		status.Phase = sdnv1alpha1.VPCPeeringPhaseReady
	}

	if statusEqual(peering.Status, status) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = peering.Generation
	}
	peering.Status = status
	if err := r.Status().Update(ctx, peering); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPCPeering status: %w", err)
	}

	logger.Info("VPCPeering status updated", "peering", req.NamespacedName.String(), "phase", status.Phase)
	return ctrl.Result{}, nil
}

// findReciprocal returns the half in the peer namespace that references this
// half's VPC back, or nil.
func (r *VPCPeeringReconciler) findReciprocal(ctx context.Context, peering *sdnv1alpha1.VPCPeering) (*sdnv1alpha1.VPCPeering, error) {
	var list sdnv1alpha1.VPCPeeringList
	if err := r.List(ctx, &list, client.InNamespace(peering.Spec.PeerRef.Namespace)); err != nil {
		return nil, fmt.Errorf("list vpcpeerings in peer namespace: %w", err)
	}
	for i := range list.Items {
		other := &list.Items[i]
		if peering.Matches(other) {
			return other, nil
		}
	}
	return nil, nil
}

func (r *VPCPeeringReconciler) getVPC(ctx context.Context, namespace, name string) *sdnv1alpha1.VPC {
	vpc := &sdnv1alpha1.VPC{}
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, vpc); err != nil {
		return nil
	}
	return vpc
}

func vpcReady(vpc *sdnv1alpha1.VPC) bool {
	return vpc != nil && vpc.Status.VNI != 0
}

func setCondition(status *sdnv1alpha1.VPCPeeringStatus, condType string, ok bool, reason, message string) {
	cond := metav1.Condition{Type: condType, Status: metav1.ConditionFalse, Reason: reason + "Missing", Message: "not " + message}
	if ok {
		cond.Status = metav1.ConditionTrue
		cond.Reason = reason
		cond.Message = message
	}
	meta.SetStatusCondition(&status.Conditions, cond)
}

// statusEqual compares status ignoring condition timestamps/generation, so
// reconciles converge instead of updating forever.
func statusEqual(a, b sdnv1alpha1.VPCPeeringStatus) bool {
	if a.Phase != b.Phase || a.PeerVNI != b.PeerVNI || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for _, ca := range a.Conditions {
		cb := meta.FindStatusCondition(b.Conditions, ca.Type)
		if cb == nil || cb.Status != ca.Status || cb.Reason != ca.Reason || cb.Message != ca.Message {
			return false
		}
	}
	return true
}

// SetupWithManager registers the reconciler with the manager. Beyond its own
// object, a half must be re-reconciled when its reciprocal half appears or
// disappears (in another namespace) and when either referenced VPC changes.
func (r *VPCPeeringReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCPeering{}).
		Watches(&sdnv1alpha1.VPCPeering{}, handler.EnqueueRequestsFromMapFunc(r.mapToReciprocal)).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCToPeerings)).
		Named("vpcpeering").
		Complete(r)
}

// mapToReciprocal enqueues the halves in a changed half's peer namespace that
// point back at it — the reciprocal's status depends on this half's existence.
func (r *VPCPeeringReconciler) mapToReciprocal(ctx context.Context, obj client.Object) []ctrl.Request {
	peering, ok := obj.(*sdnv1alpha1.VPCPeering)
	if !ok {
		return nil
	}
	var list sdnv1alpha1.VPCPeeringList
	if err := r.List(ctx, &list, client.InNamespace(peering.Spec.PeerRef.Namespace)); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range list.Items {
		other := &list.Items[i]
		if peering.Matches(other) {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: other.Namespace, Name: other.Name}})
		}
	}
	return reqs
}

// mapVPCToPeerings enqueues every half that references the changed VPC as its
// local or peer VPC.
func (r *VPCPeeringReconciler) mapVPCToPeerings(ctx context.Context, obj client.Object) []ctrl.Request {
	vpc, ok := obj.(*sdnv1alpha1.VPC)
	if !ok {
		return nil
	}
	var list sdnv1alpha1.VPCPeeringList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	ref := sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}
	var reqs []ctrl.Request
	for i := range list.Items {
		p := &list.Items[i]
		if p.LocalRef() == ref || p.Spec.PeerRef == ref {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: p.Namespace, Name: p.Name}})
		}
	}
	return reqs
}
