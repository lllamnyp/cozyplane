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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// VPCGatewayReconciler owns a VPCGateway's status: does its VPC exist, does its
// pool exist, and is it the VPC's *only* gateway (docs/north-south.md).
//
// It realizes nothing itself. The gateway pod is GatewayReconciler's job, the
// LoadBalancer-ingress gate is the agent's, and the counters are the datapath's —
// what this controller establishes is whether the boundary is legitimate, which
// all three of them then read.
type VPCGatewayReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcgateways,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=vpcgateways/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=externalpools,verbs=get;list;watch

// Reconcile computes the gateway's phase and conditions.
func (r *VPCGatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	gw := &sdnv1alpha1.VPCGateway{}
	if err := r.Get(ctx, req.NamespacedName, gw); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	vpcOK := false
	vpc := &sdnv1alpha1.VPC{}
	if name := gw.Spec.VPCRef.Name; name != "" {
		err := r.Get(ctx, types.NamespacedName{Namespace: gw.Namespace, Name: name}, vpc)
		vpcOK = err == nil
		if err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch VPC: %w", err)
		}
	}

	// An empty poolRef is allowed for a NAT-only door today (the gateway pod
	// masquerades to its own address). It becomes required once the VPC has an
	// egress identity of its own to draw (docs/north-south.md § increment 2).
	poolOK := true
	if name := gw.Spec.PoolRef.Name; name != "" {
		pool := &sdnv1alpha1.ExternalPool{}
		err := r.Get(ctx, types.NamespacedName{Name: name}, pool)
		poolOK = err == nil
		if err != nil && !apierrors.IsNotFound(err) {
			return ctrl.Result{}, fmt.Errorf("fetch ExternalPool: %w", err)
		}
	}

	conflict, err := r.conflictingGateway(ctx, gw)
	if err != nil {
		return ctrl.Result{}, err
	}
	exclusive := conflict == ""

	status := sdnv1alpha1.VPCGatewayStatus{Phase: sdnv1alpha1.VPCGatewayPhasePending}
	setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionVPCResolved, vpcOK,
		"VPCResolved", "spec.vpcRef names a VPC in this namespace")
	setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionPoolResolved, poolOK,
		"PoolResolved", "spec.poolRef names an existing ExternalPool")
	if exclusive {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionExclusive, true,
			"Exclusive", "this is the VPC's only gateway")
	} else {
		setGWCondition(&status, sdnv1alpha1.VPCGatewayConditionExclusive, false,
			"GatewayConflict",
			fmt.Sprintf("VPCGateway %q is already this VPC's boundary; a VPC has exactly one", conflict))
	}
	if vpcOK && poolOK && exclusive {
		status.Phase = sdnv1alpha1.VPCGatewayPhaseReady
	}

	if gwStatusEqual(gw.Status, status) {
		return ctrl.Result{}, nil
	}
	for i := range status.Conditions {
		status.Conditions[i].ObservedGeneration = gw.Generation
	}
	gw.Status = status
	if err := r.Status().Update(ctx, gw); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update VPCGateway status: %w", err)
	}
	logger.Info("VPCGateway status updated", "vpcgateway", req.NamespacedName.String(), "phase", status.Phase)
	return ctrl.Result{}, nil
}

// conflictingGateway returns the name of an older VPCGateway that already binds
// this one's VPC, or "" when this gateway owns it. A VPC has exactly one boundary
// — that is what makes "everything crosses it" checkable and the per-VPC counters
// unambiguous. First writer wins, ties broken by name so replicas agree.
func (r *VPCGatewayReconciler) conflictingGateway(ctx context.Context, gw *sdnv1alpha1.VPCGateway) (string, error) {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list, client.InNamespace(gw.Namespace)); err != nil {
		return "", fmt.Errorf("list VPCGateways: %w", err)
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.Name == gw.Name ||
			other.Spec.VPCRef.Name != gw.Spec.VPCRef.Name ||
			!other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.CreationTimestamp.Time.Before(gw.CreationTimestamp.Time) ||
			(other.CreationTimestamp.Equal(&gw.CreationTimestamp) && other.Name < gw.Name) {
			return other.Name, nil
		}
	}
	return "", nil
}

func setGWCondition(status *sdnv1alpha1.VPCGatewayStatus, condType string, ok bool, reason, msg string) {
	st := metav1.ConditionFalse
	if ok {
		st = metav1.ConditionTrue
	}
	status.Conditions = append(status.Conditions, metav1.Condition{
		Type:    condType,
		Status:  st,
		Reason:  reason,
		Message: msg,
	})
}

func gwStatusEqual(a, b sdnv1alpha1.VPCGatewayStatus) bool {
	if a.Phase != b.Phase || len(a.Conditions) != len(b.Conditions) {
		return false
	}
	for i := range a.Conditions {
		if a.Conditions[i].Type != b.Conditions[i].Type ||
			a.Conditions[i].Status != b.Conditions[i].Status ||
			a.Conditions[i].Reason != b.Conditions[i].Reason ||
			a.Conditions[i].Message != b.Conditions[i].Message {
			return false
		}
	}
	return true
}

// SetupWithManager wires the controller.
func (r *VPCGatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPCGateway{}).
		Watches(&sdnv1alpha1.VPC{}, handler.EnqueueRequestsFromMapFunc(r.mapVPCToGateways)).
		Watches(&sdnv1alpha1.ExternalPool{}, handler.EnqueueRequestsFromMapFunc(r.mapPoolToGateways)).
		Named("vpcgateway").
		Complete(r)
}

func (r *VPCGatewayReconciler) mapVPCToGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list, client.InNamespace(obj.GetNamespace())); err != nil {
		return nil
	}
	var out []ctrl.Request
	for i := range list.Items {
		if list.Items[i].Spec.VPCRef.Name == obj.GetName() {
			out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}

func (r *VPCGatewayReconciler) mapPoolToGateways(ctx context.Context, obj client.Object) []ctrl.Request {
	var list sdnv1alpha1.VPCGatewayList
	if err := r.List(ctx, &list); err != nil {
		return nil
	}
	var out []ctrl.Request
	for i := range list.Items {
		if list.Items[i].Spec.PoolRef.Name == obj.GetName() {
			out = append(out, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&list.Items[i])})
		}
	}
	return out
}
