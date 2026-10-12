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
	"time"

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
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"github.com/lllamnyp/cozyplane/internal/sgidentity"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
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
	if !vpnlimits.ObjectName(sg.Spec.VPCRef.Name) {
		id = 0 // An unusable legacy anchor cannot reserve an ID or expand a scan.
	} else if id <= 0 || id >= sdnv1alpha1.MaxSecurityGroupsPerVPC {
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
	if id == 0 {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
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
	used := map[int32]bool{}
	err := walkSecurityGroupClaims(ctx, r.reader(), sg.Namespace, func(o *sdnv1alpha1.SecurityGroup) {
		if o.Name == sg.Name || o.Spec.VPCRef.Name != sg.Spec.VPCRef.Name {
			return
		}
		if o.Status.ID > 0 && o.Status.ID < sdnv1alpha1.MaxSecurityGroupsPerVPC {
			used[o.Status.ID] = true
		}
	})
	if err != nil {
		return nil, err
	}
	return used, nil
}

func walkSecurityGroupClaims(ctx context.Context, reader client.Reader, namespace string, visit func(*sdnv1alpha1.SecurityGroup)) error {
	err := ipam.WalkClaims(ctx, func(limit int64, continuation string) ([]sdnv1alpha1.SecurityGroup, string, error) {
		var list sdnv1alpha1.SecurityGroupList
		if err := reader.List(ctx, &list, client.InNamespace(namespace), client.Limit(limit), client.Continue(continuation)); err != nil {
			return nil, "", err
		}
		return list.Items, list.Continue, nil
	}, visit)
	if err != nil {
		return fmt.Errorf("list SecurityGroup ID claims: %w", err)
	}
	return nil
}

// lostIDToDuplicate reports whether sg shares its id with another group in the
// same VPC that wins the deterministic tiebreak (older creationTimestamp, then
// name). Exactly one side yields, so repair converges without a fight.
func (r *SecurityGroupReconciler) lostIDToDuplicate(ctx context.Context, sg *sdnv1alpha1.SecurityGroup) (bool, error) {
	lost := false
	err := walkSecurityGroupClaims(ctx, r.reader(), sg.Namespace, func(o *sdnv1alpha1.SecurityGroup) {
		if o.Name == sg.Name || o.Spec.VPCRef.Name != sg.Spec.VPCRef.Name || o.Status.ID != sg.Status.ID {
			return
		}
		if sgClaimOlder(o, sg) {
			lost = true // the other group's claim wins; yield after a complete scan
		}
	})
	return lost, err
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
	SentinelReady func(context.Context) (bool, error)
}

const (
	membershipVPCIndex  = "cozyplane.membership.vpc"
	membershipPodIndex  = "cozyplane.membership.pod"
	membershipWorkLimit = 65536
)

func membershipVPCKeys(obj client.Object) []string {
	var namespace, name string
	switch o := obj.(type) {
	case *sdnv1alpha1.Port:
		namespace, name = o.Spec.VPCRef.Namespace, o.Spec.VPCRef.Name
	case *sdnv1alpha1.SecurityGroup:
		namespace, name = o.Namespace, o.Spec.VPCRef.Name
	}
	if !vpnlimits.NamespaceName(namespace) || !vpnlimits.ObjectName(name) {
		return nil
	}
	return []string{namespace + "/" + name}
}

func membershipPodKeys(obj client.Object) []string {
	ns, name := obj.GetLabels()[sdnv1alpha1.LabelPodNamespace], obj.GetLabels()[sdnv1alpha1.LabelPodName]
	if ns == "" || name == "" {
		return nil
	}
	return []string{ns + "/" + name}
}

func membershipInputWork(ctx context.Context, groups []sdnv1alpha1.SecurityGroup) error {
	if len(groups) > membershipWorkLimit {
		return fmt.Errorf("membership exceeds %d groups", membershipWorkLimit)
	}
	work := len(groups)
	for i := range groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !groups[i].DeletionTimestamp.IsZero() {
			continue
		}
		s := &groups[i].Spec.PodSelector
		work += len(s.MatchLabels) + len(s.MatchExpressions)
		if work > membershipWorkLimit {
			return fmt.Errorf("membership exceeds selector work budget")
		}
		for _, e := range s.MatchExpressions {
			work += len(e.Values)
			if work > membershipWorkLimit {
				return fmt.Errorf("membership exceeds selector value budget")
			}
		}
	}
	return ctx.Err()
}

// podLabelsFor returns the labels to evaluate selectors against: the live pod's
// if the Port names one that exists, else the claim-time snapshot.
func (r *PortMembershipReconciler) podLabelsFor(ctx context.Context, port *sdnv1alpha1.Port) map[string]string {
	ns := port.Labels[sdnv1alpha1.LabelPodNamespace]
	name := port.Labels[sdnv1alpha1.LabelPodName]
	uid := port.Labels[sdnv1alpha1.LabelPodUID]
	if ns != "" && name != "" && uid != "" {
		var pod corev1.Pod
		if err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &pod); err == nil {
			if pod.DeletionTimestamp == nil && string(pod.UID) == uid {
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
	var inputErr error
	keys := membershipVPCKeys(&port)
	if len(keys) == 0 {
		inputErr = fmt.Errorf("invalid Port VPC reference")
	} else {
		if err := r.List(ctx, &groups, client.MatchingFields{membershipVPCIndex: keys[0]}); err != nil {
			return ctrl.Result{}, fmt.Errorf("list SecurityGroups: %w", err)
		}
		inputErr = membershipInputWork(ctx, groups.Items)
	}
	var ids []int32
	var refs []sdnv1alpha1.SecurityGroupMembership
	if err := ctx.Err(); err != nil {
		return ctrl.Result{}, err
	}
	index := sgidentity.Index{}
	for i := 0; inputErr == nil && i < len(groups.Items); i++ {
		if groups.Items[i].Spec.VPCRef.Name == port.Spec.VPCRef.Name {
			index.Add(&groups.Items[i])
		}
	}
	var selected uint64
	for i := 0; inputErr == nil && i < len(groups.Items); i++ {
		if err := ctx.Err(); err != nil {
			return ctrl.Result{}, err
		}
		sg := &groups.Items[i]
		if sg.Spec.VPCRef.Name != port.Spec.VPCRef.Name || !sg.DeletionTimestamp.IsZero() {
			continue
		}
		sel, err := metav1.LabelSelectorAsSelector(&sg.Spec.PodSelector)
		if err != nil {
			inputErr = fmt.Errorf("invalid podSelector for SecurityGroup %s", sg.Name)
			break
		}
		if sel.Matches(labels.Set(podLabels)) {
			id := sg.Status.ID
			if id <= 0 || id >= sdnv1alpha1.MaxSecurityGroupsPerVPC || sg.UID == "" || index[port.Spec.VPCRef][id] != sg.UID {
				id = 0 // selected but unresolved: never become legacy allow
			} else {
				refs = append(refs, sdnv1alpha1.SecurityGroupMembership{ID: id, UID: sg.UID})
			}
			selected |= 1 << uint(id)
		}
	}
	if inputErr != nil {
		logger.Error(inputErr, "membership guarded", "port", port.Name)
		selected, refs = 1, nil
	}
	for id := int32(0); id < sdnv1alpha1.MaxSecurityGroupsPerVPC; id++ {
		if selected&(1<<uint(id)) != 0 {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(refs, func(a, b sdnv1alpha1.SecurityGroupMembership) int { return int(a.ID - b.ID) })
	podUID := types.UID(port.Labels[sdnv1alpha1.LabelPodUID])

	if slices.Equal(port.Status.Groups, ids) && slices.Equal(port.Status.GroupRefs, refs) && port.Status.GroupPodUID == podUID {
		return ctrl.Result{}, nil
	}
	port.Status.Groups = ids
	port.Status.GroupRefs = refs
	port.Status.GroupPodUID = podUID
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
	keys := membershipVPCKeys(sg)
	if len(keys) == 0 {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingFields{membershipVPCIndex: keys[0]}); err != nil {
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
// creates; the cache index selects that exact pair without a cluster-wide copy.
func (r *PortMembershipReconciler) mapPodToPorts(ctx context.Context, obj client.Object) []ctrl.Request {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return nil
	}
	var ports sdnv1alpha1.PortList
	if err := r.List(ctx, &ports, client.MatchingFields{membershipPodIndex: pod.Namespace + "/" + pod.Name}); err != nil {
		return nil
	}
	var reqs []ctrl.Request
	for i := range ports.Items {
		reqs = append(reqs, ctrl.Request{NamespacedName: types.NamespacedName{Name: ports.Items[i].Name}})
	}
	return reqs
}

func (r *PortMembershipReconciler) SetupWithManager(mgr ctrl.Manager) error {
	for _, obj := range []client.Object{&sdnv1alpha1.Port{}, &sdnv1alpha1.SecurityGroup{}} {
		if err := mgr.GetFieldIndexer().IndexField(context.Background(), obj, membershipVPCIndex, membershipVPCKeys); err != nil {
			return err
		}
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &sdnv1alpha1.Port{}, membershipPodIndex, membershipPodKeys); err != nil {
		return err
	}
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
