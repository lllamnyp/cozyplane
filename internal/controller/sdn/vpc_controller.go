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
// VPC CIDRs may overlap freely (isolation is by overlay, not address space):
// everything a tenant addresses is delivered by (net id, IP), so two VPCs can
// share a CIDR — even the cluster pod CIDR — and stay distinct. The one
// restriction is that overlapping VPCs cannot *peer* (peered traffic is routed
// natively), enforced in the peering path, not here.
type VPCReconciler struct {
	client.Client

	Scheme *runtime.Scheme

	// Reader reads VPCs from the API server directly, bypassing the informer
	// cache (mgr.GetAPIReader()). Allocation MUST NOT use the cache: it lags the
	// reconciler's own status writes, so two back-to-back reconciles of fresh
	// VPCs could both see a VNI as free and assign it twice — two tenants
	// sharing a network id is a cross-tenant isolation break. Reconciles are
	// serial (default MaxConcurrentReconciles), so a live list plus
	// assign-before-return is race-free. Falls back to Client when nil (tests).
	Reader client.Reader
}

// reader returns the live API reader, or the (already live in tests) client.
func (r *VPCReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
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
	} else if lost, err := r.lostVNIToDuplicate(ctx, vpc); err != nil {
		return ctrl.Result{}, err
	} else if lost {
		// Duplicate repair (pre-live-list clusters): another VPC holds this VNI
		// and wins the deterministic tiebreak; yield and reallocate. The agents
		// re-key the datapath from the new id at watch latency.
		logger.Info("VPC yields duplicate VNI", "name", vpc.Name, "vni", vpc.Status.VNI)
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
// The list is a live API read (see Reader) — never the informer cache.
func (r *VPCReconciler) allocateVNI(ctx context.Context) (int32, error) {
	var list sdnv1alpha1.VPCList
	if err := r.reader().List(ctx, &list); err != nil {
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

// lostVNIToDuplicate reports whether vpc shares its VNI with another VPC that
// wins the deterministic tiebreak — older creationTimestamp first, then
// namespace/name. Exactly one side of a duplicate pair yields, so repair
// converges without the two reconciles fighting. Live read, like allocation.
func (r *VPCReconciler) lostVNIToDuplicate(ctx context.Context, vpc *sdnv1alpha1.VPC) (bool, error) {
	var list sdnv1alpha1.VPCList
	if err := r.reader().List(ctx, &list); err != nil {
		return false, fmt.Errorf("list VPCs: %w", err)
	}
	self := vpcClaimKey(vpc)
	for i := range list.Items {
		o := &list.Items[i]
		if vpcClaimKey(o).name == self.name || o.Status.VNI != vpc.Status.VNI {
			continue
		}
		if vpcClaimOlder(vpcClaimKey(o), self) {
			return true, nil // the other VPC's claim wins; yield
		}
	}
	return false, nil
}

type vpcClaim struct {
	created metav1.Time
	name    string // namespace/name, the total-order tiebreak
}

func vpcClaimKey(v *sdnv1alpha1.VPC) vpcClaim {
	return vpcClaim{created: v.CreationTimestamp, name: v.Namespace + "/" + v.Name}
}

// vpcClaimOlder reports whether a precedes b in claim order (total order).
func vpcClaimOlder(a, b vpcClaim) bool {
	if !a.created.Equal(&b.created) {
		return a.created.Before(&b.created)
	}
	return a.name < b.name
}

// SetupWithManager registers the reconciler with the manager.
func (r *VPCReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.VPC{}).
		Named("vpc").
		Complete(r)
}
