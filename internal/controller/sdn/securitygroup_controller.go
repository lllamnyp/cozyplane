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
	"encoding/json"
	"fmt"
	"slices"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// SecurityGroupReconciler allocates each SecurityGroup a per-VPC numeric id
// (1..MaxSecurityGroupsPerVPC-1 — id MaxSecurityGroupsPerVPC is the reserved
// north-south pseudo-group in the datapath) and reports readiness. The id is
// the datapath's wire identity, scoped to the VPC (net), so distinct VPCs reuse
// the same ids freely. Allocation is a live API read, with the same
// deterministic duplicate repair as VNI allocation.
type SecurityGroupReconciler struct {
	client.Client

	// Reader reads live for ALLOCATION (never the lagging informer cache — the
	// VNI-duplicate lesson). Falls back to Client (tests).
	Reader client.Reader
}

// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=securitygroups,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=securitygroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports,verbs=get;list;watch
// +kubebuilder:rbac:groups=sdn.cozystack.io,resources=ports/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

func (r *SecurityGroupReconciler) reader() client.Reader {
	if r.Reader != nil {
		return r.Reader
	}
	return r.Client
}

func (r *SecurityGroupReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var sg sdnv1alpha1.SecurityGroup
	if err := r.Get(ctx, req.NamespacedName, &sg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if sg.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	// Allocate an id, or repair a duplicate (younger claim yields), or keep the
	// current one.
	id := sg.Status.ID
	if id == 0 {
		var err error
		if id, err = r.allocateID(ctx, &sg); err != nil {
			return ctrl.Result{}, err
		}
	} else if lost, err := r.lostIDToDuplicate(ctx, &sg); err != nil {
		return ctrl.Result{}, err
	} else if lost {
		id = 0 // release and re-allocate next pass
	}

	changed := sg.Status.ID != id
	sg.Status.ID = id
	phase := sdnv1alpha1.SecurityGroupPhasePending
	if id != 0 {
		phase = sdnv1alpha1.SecurityGroupPhaseReady
	}
	if sg.Status.Phase != phase {
		sg.Status.Phase = phase
		changed = true
	}
	if changed {
		if err := r.Status().Update(ctx, &sg); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, fmt.Errorf("update SecurityGroup status: %w", err)
		}
		logger.Info("SecurityGroup id assigned", "name", sg.Name, "namespace", sg.Namespace, "id", id)
	}
	return ctrl.Result{}, nil
}

// allocateID returns the lowest id in [1, MaxSecurityGroupsPerVPC) not used by
// another SecurityGroup in the SAME VPC (owner namespace + local VPC name). A
// live read, like VNI allocation. Returns 0 when the VPC is already full.
func (r *SecurityGroupReconciler) allocateID(ctx context.Context, sg *sdnv1alpha1.SecurityGroup) (int32, error) {
	used, err := r.usedIDs(ctx, sg)
	if err != nil {
		return 0, err
	}
	for id := int32(1); id < sdnv1alpha1.MaxSecurityGroupsPerVPC; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, nil // VPC is out of group ids
}

// usedIDs is the set of ids taken by other SecurityGroups in sg's VPC.
func (r *SecurityGroupReconciler) usedIDs(ctx context.Context, sg *sdnv1alpha1.SecurityGroup) (map[int32]bool, error) {
	var list sdnv1alpha1.SecurityGroupList
	if err := r.reader().List(ctx, &list, client.InNamespace(sg.Namespace)); err != nil {
		return nil, fmt.Errorf("list SecurityGroups: %w", err)
	}
	used := map[int32]bool{}
	for i := range list.Items {
		o := &list.Items[i]
		if o.Name == sg.Name || o.Spec.VPCRef.Name != sg.Spec.VPCRef.Name {
			continue
		}
		if o.Status.ID != 0 {
			used[o.Status.ID] = true
		}
	}
	return used, nil
}

// lostIDToDuplicate reports whether sg shares its id with another group in the
// same VPC that wins the deterministic tiebreak (older creationTimestamp, then
// name). Exactly one side yields, so repair converges without a fight.
func (r *SecurityGroupReconciler) lostIDToDuplicate(ctx context.Context, sg *sdnv1alpha1.SecurityGroup) (bool, error) {
	var list sdnv1alpha1.SecurityGroupList
	if err := r.reader().List(ctx, &list, client.InNamespace(sg.Namespace)); err != nil {
		return false, fmt.Errorf("list SecurityGroups: %w", err)
	}
	for i := range list.Items {
		o := &list.Items[i]
		if o.Name == sg.Name || o.Spec.VPCRef.Name != sg.Spec.VPCRef.Name || o.Status.ID != sg.Status.ID {
			continue
		}
		if sgClaimOlder(o, sg) {
			return true, nil // the other group's claim wins; yield
		}
	}
	return false, nil
}

// sgClaimOlder reports whether a's claim beats b's: older creationTimestamp
// first, then name as a stable tiebreak.
func sgClaimOlder(a, b *sdnv1alpha1.SecurityGroup) bool {
	if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
		return a.CreationTimestamp.Before(&b.CreationTimestamp)
	}
	return a.Name < b.Name
}

// mapPortToSG re-enqueues nothing for the SecurityGroup controller; SG changes
// re-enqueue Ports through the membership controller instead.

func (r *SecurityGroupReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.SecurityGroup{}).
		Named("securitygroup").
		Complete(r)
}

// PortMembershipReconciler resolves a Port's SecurityGroup membership from the
// pod's LIVE labels, writing the group ids into Port.status.groups — the input
// the agent folds into the datapath membership bitmap. Membership FOLLOWS
// labels (docs/security-groups.md § Membership): it is recomputed on Port
// creation, on any SecurityGroup change in the Port's VPC, and on the pod's own
// label edits — the contract NetworkPolicy has always had. The CNI's pod-labels
// annotation is only the fallback for when the Port has no live pod (a
// persistent VM Port between launchers; a CRD-mode install with no pod access),
// so membership holds steady instead of collapsing to "no groups".
type PortMembershipReconciler struct {
	client.Client
}

// podLabelsFor returns the labels to evaluate selectors against: the live pod's
// if the Port names one that exists, else the claim-time snapshot.
func (r *PortMembershipReconciler) podLabelsFor(ctx context.Context, port *sdnv1alpha1.Port) map[string]string {
	ns := port.Labels[sdnv1alpha1.LabelPodNamespace]
	name := port.Labels[sdnv1alpha1.LabelPodName]
	if ns != "" && name != "" {
		var pod corev1.Pod
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err == nil {
			if pod.DeletionTimestamp == nil {
				return pod.Labels
			}
		}
	}
	return decodePodLabels(port.Annotations[sdnv1alpha1.AnnotationPodLabels])
}

func (r *PortMembershipReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var port sdnv1alpha1.Port
	if err := r.Get(ctx, req.NamespacedName, &port); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if port.DeletionTimestamp != nil {
		return ctrl.Result{}, nil
	}

	podLabels := r.podLabelsFor(ctx, &port)

	// Evaluate every SecurityGroup in the Port's VPC (owner namespace + name).
	var groups sdnv1alpha1.SecurityGroupList
	if err := r.List(ctx, &groups, client.InNamespace(port.Spec.VPCRef.Namespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list SecurityGroups: %w", err)
	}
	var ids []int32
	for i := range groups.Items {
		sg := &groups.Items[i]
		if sg.Spec.VPCRef.Name != port.Spec.VPCRef.Name || sg.Status.ID == 0 {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&sg.Spec.PodSelector)
		if err != nil {
			logger.Error(err, "invalid podSelector", "securityGroup", sg.Name)
			continue
		}
		if sel.Matches(labels.Set(podLabels)) {
			ids = append(ids, sg.Status.ID)
		}
	}
	slices.Sort(ids)

	if slices.Equal(port.Status.Groups, ids) {
		return ctrl.Result{}, nil
	}
	port.Status.Groups = ids
	if err := r.Status().Update(ctx, &port); err != nil {
		if apierrors.IsConflict(err) {
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, fmt.Errorf("update Port status.groups: %w", err)
	}
	logger.Info("Port membership resolved", "port", port.Name, "groups", ids)
	return ctrl.Result{}, nil
}

// mapSGToPorts re-enqueues every Port in a SecurityGroup's VPC when the group
// changes — a selector or id change can move any Port in or out of the group.
func (r *PortMembershipReconciler) mapSGToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	sg, ok := obj.(*sdnv1alpha1.SecurityGroup)
	if !ok {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		p := &ports.Items[i]
		if p.Spec.VPCRef.Namespace == sg.Namespace && p.Spec.VPCRef.Name == sg.Spec.VPCRef.Name {
			reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: p.Name}})
		}
	}
	return reqs
}

// mapPodToPorts re-enqueues the Port(s) a pod owns when the pod changes — the
// label-follows trigger. The CNI stamps pod-namespace/pod-name on every Port it
// creates, so the reverse index is a plain list filter (Ports are cluster-scoped
// and few per node; a field index is the optimization if this ever shows up).
func (r *PortMembershipReconciler) mapPodToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingLabels{
		sdnv1alpha1.LabelPodNamespace: pod.Namespace,
		sdnv1alpha1.LabelPodName:      pod.Name,
	}); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: ports.Items[i].Name}})
	}
	return reqs
}

func (r *PortMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sdnv1alpha1.Port{}).
		Watches(&sdnv1alpha1.SecurityGroup{}, handler.EnqueueRequestsFromMapFunc(r.mapSGToPorts)).
		Watches(&corev1.Pod{}, handler.EnqueueRequestsFromMapFunc(r.mapPodToPorts)).
		Named("portmembership").
		Complete(r)
}

// decodePodLabels parses the JSON pod-labels annotation; a missing or malformed
// value yields an empty set (the Port simply matches only empty selectors).
func decodePodLabels(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil
	}
	return m
}
