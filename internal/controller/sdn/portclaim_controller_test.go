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
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

const claimPortName = "v100.10-10-0-4"

func pcScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = sdnv1alpha1.AddToScheme(s)
	return s
}

func newPortClaim(name, uid string) *sdnv1alpha1.PortClaim {
	return &sdnv1alpha1.PortClaim{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: name, UID: types.UID(uid),
			Finalizers: []string{sdnv1alpha1.FinalizerPortClaim}},
		Spec: sdnv1alpha1.PortClaimSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "vpc"}},
	}
}

func claimedPortOn(claim, uid, node, podUID string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:       claimPortName,
			Finalizers: []string{sdnv1alpha1.FinalizerSever},
			Labels: map[string]string{
				sdnv1alpha1.LabelVPCNamespace:   "tenant",
				sdnv1alpha1.LabelVPC:            "vpc",
				sdnv1alpha1.LabelPodNamespace:   "tenant",
				sdnv1alpha1.LabelPodUID:         podUID,
				sdnv1alpha1.LabelClaimNamespace: "tenant",
				sdnv1alpha1.LabelClaimName:      claim,
				sdnv1alpha1.LabelClaimUID:       uid,
			},
		},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "vpc"},
			IP:     "10.10.0.4", MAC: "02:00:00:00:00:04",
			Node: node, NodeIP: nodeIPs[node], PodNamespace: "tenant",
		},
	}
}

var nodeIPs = map[string]string{"node-a": "192.0.2.1", "node-b": "192.0.2.2"}

func claimPod(name, uid, node string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: name, UID: types.UID(uid),
			Annotations: map[string]string{sdnv1alpha1.AnnotationPortClaim: "vm1"}},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: phase},
	}
}

func testNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: nodeIPs[name]}}},
	}
}

func newPCReconciler(t *testing.T, objs ...client.Object) *PortClaimReconciler {
	t.Helper()
	objs = append(objs, testNode("node-a"), testNode("node-b"))
	c := fake.NewClientBuilder().WithScheme(pcScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.PortClaim{}).
		WithIndex(&corev1.Pod{}, PodPortClaimIndex, PodPortClaim).
		Build()
	return &PortClaimReconciler{Client: c}
}

func reconcileClaim(t *testing.T, r *PortClaimReconciler, name string) {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "tenant", Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func getClaimPort(t *testing.T, r *PortClaimReconciler) *sdnv1alpha1.Port {
	t.Helper()
	p := &sdnv1alpha1.Port{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: claimPortName}, p); err != nil {
		t.Fatalf("get port: %v", err)
	}
	return p
}

func getClaim(t *testing.T, r *PortClaimReconciler, name string) *sdnv1alpha1.PortClaim {
	t.Helper()
	c := &sdnv1alpha1.PortClaim{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "tenant", Name: name}, c); err != nil {
		t.Fatalf("get portclaim: %v", err)
	}
	return c
}

// Stopping a VM deletes its pods; the Port stays, detached, with IP and MAC pinned.
func TestPortClaimKeepsPortWithoutPods(t *testing.T) {
	r := newPCReconciler(t, newPortClaim("vm1", "u1"), claimedPortOn("vm1", "u1", "node-a", "pod-a"))
	reconcileClaim(t, r, "vm1")

	p := getClaimPort(t, r)
	if !p.DeletionTimestamp.IsZero() {
		t.Fatal("port deleted with its pods")
	}
	if p.Spec.Node != "" || p.Spec.NodeIP != "" {
		t.Errorf("port not detached: node %q/%q", p.Spec.Node, p.Spec.NodeIP)
	}
	claim := getClaim(t, r, "vm1")
	if claim.Status.IP != "10.10.0.4" || claim.Status.MAC != "02:00:00:00:00:04" {
		t.Errorf("status = %+v, want the pinned identity", claim.Status)
	}
	if c := meta.FindStatusCondition(claim.Status.Conditions, sdnv1alpha1.PortClaimConditionBound); c == nil || c.Status != metav1.ConditionFalse || c.Reason != "Detached" {
		t.Errorf("Bound condition = %+v, want False/Detached", c)
	}
}

// A new pod for the claim on another node gets the same Port.
func TestPortClaimRebindsNewPod(t *testing.T) {
	r := newPCReconciler(t, newPortClaim("vm1", "u1"), claimedPortOn("vm1", "u1", "", "pod-a"),
		claimPod("launcher-b", "pod-b", "node-b", corev1.PodRunning))
	reconcileClaim(t, r, "vm1")

	p := getClaimPort(t, r)
	if p.Spec.Node != "node-b" || p.Spec.NodeIP != "192.0.2.2" || p.Labels[sdnv1alpha1.LabelPodUID] != "pod-b" {
		t.Errorf("port = node %q/%q pod %q, want node-b and pod-b", p.Spec.Node, p.Spec.NodeIP, p.Labels[sdnv1alpha1.LabelPodUID])
	}
	if p.Spec.IP != "10.10.0.4" || p.Spec.MAC != "02:00:00:00:00:04" {
		t.Errorf("identity changed: %s/%s", p.Spec.IP, p.Spec.MAC)
	}
	if c := meta.FindStatusCondition(getClaim(t, r, "vm1").Status.Conditions, sdnv1alpha1.PortClaimConditionBound); c == nil || c.Status != metav1.ConditionTrue {
		t.Errorf("Bound condition = %+v, want True", c)
	}
}

// Deleting the claim deletes the Port behind its sever finalizer, then releases the claim.
func TestPortClaimDeletionReleasesPortFirst(t *testing.T) {
	r := newPCReconciler(t, newPortClaim("vm1", "u1"), claimedPortOn("vm1", "u1", "node-a", "pod-a"))
	ctx := context.Background()
	if err := r.Delete(ctx, getClaim(t, r, "vm1")); err != nil {
		t.Fatal(err)
	}
	reconcileClaim(t, r, "vm1")

	p := getClaimPort(t, r)
	if p.DeletionTimestamp.IsZero() || !slices.Contains(p.Finalizers, sdnv1alpha1.FinalizerSever) {
		t.Fatalf("port not terminating behind its sever finalizer: %+v", p.ObjectMeta)
	}
	if !slices.Contains(getClaim(t, r, "vm1").Finalizers, sdnv1alpha1.FinalizerPortClaim) {
		t.Fatal("claim finalizer released while its Port still exists")
	}

	p.Finalizers = nil // the agent acknowledges the sever
	if err := r.Update(ctx, p); err != nil {
		t.Fatal(err)
	}
	reconcileClaim(t, r, "vm1")
	if err := r.Get(ctx, types.NamespacedName{Namespace: "tenant", Name: "vm1"}, &sdnv1alpha1.PortClaim{}); !apierrors.IsNotFound(err) {
		t.Fatalf("claim still present after its Port went: %v", err)
	}
}

func TestPortClaimCutover(t *testing.T) {
	cases := []struct {
		name     string
		portNode string
		pods     []*corev1.Pod
		wantNode string
	}{
		{"migration in flight keeps the source", "node-a", []*corev1.Pod{
			claimPod("src", "pod-a", "node-a", corev1.PodRunning), claimPod("tgt", "pod-b", "node-b", corev1.PodRunning)}, "node-a"},
		{"guest announcement on the target is kept", "node-b", []*corev1.Pod{
			claimPod("src", "pod-a", "node-a", corev1.PodRunning), claimPod("tgt", "pod-b", "node-b", corev1.PodRunning)}, "node-b"},
		{"source exits, target takes over", "node-a", []*corev1.Pod{
			claimPod("src", "pod-a", "node-a", corev1.PodSucceeded), claimPod("tgt", "pod-b", "node-b", corev1.PodRunning)}, "node-b"},
		{"failed target leaves the source", "node-a", []*corev1.Pod{
			claimPod("src", "pod-a", "node-a", corev1.PodRunning), claimPod("tgt", "pod-b", "node-b", corev1.PodFailed)}, "node-a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := []client.Object{newPortClaim("vm1", "u1"), claimedPortOn("vm1", "u1", tc.portNode, "pod-a")}
			for _, p := range tc.pods {
				objs = append(objs, p)
			}
			r := newPCReconciler(t, objs...)
			reconcileClaim(t, r, "vm1")
			if got := getClaimPort(t, r).Spec.Node; got != tc.wantNode {
				t.Errorf("node = %q, want %q", got, tc.wantNode)
			}
		})
	}
}

func TestPortClaimAdoptsLegacyVMPort(t *testing.T) {
	legacy := claimedPortOn("", "", "node-a", "pod-a")
	for _, k := range []string{sdnv1alpha1.LabelClaimNamespace, sdnv1alpha1.LabelClaimName, sdnv1alpha1.LabelClaimUID} {
		delete(legacy.Labels, k)
	}
	legacy.Labels[sdnv1alpha1.LabelVMName] = "vm1"
	claim := newPortClaim("vm1", "u1")
	claim.Spec.MAC = "02:00:00:00:00:99"
	r := newPCReconciler(t, claim, legacy, claimPod("launcher-a", "pod-a", "node-a", corev1.PodRunning))
	reconcileClaim(t, r, "vm1")

	p := getClaimPort(t, r)
	if p.Labels[sdnv1alpha1.LabelClaimUID] != "u1" || p.Labels[sdnv1alpha1.LabelVMName] != "" {
		t.Errorf("labels = %v, want the claim's and no vm-name", p.Labels)
	}
	if p.Spec.MAC != "02:00:00:00:00:99" {
		t.Errorf("mac = %q, want the claim's requested MAC", p.Spec.MAC)
	}
	if !p.DeletionTimestamp.IsZero() || p.Spec.Node != "node-a" {
		t.Errorf("adopted port disturbed: %+v", p.Spec)
	}
}

func TestPortClaimDeletesPortsOfAnEarlierClaim(t *testing.T) {
	r := newPCReconciler(t, newPortClaim("vm1", "new"), claimedPortOn("vm1", "old", "node-a", "pod-a"))
	reconcileClaim(t, r, "vm1")
	if p := getClaimPort(t, r); p.DeletionTimestamp.IsZero() {
		t.Error("port of the earlier claim kept")
	}
}

func TestPortClaimGoneDeletesPorts(t *testing.T) {
	r := newPCReconciler(t, claimedPortOn("vm1", "u1", "node-a", "pod-a"))
	reconcileClaim(t, r, "vm1")
	if p := getClaimPort(t, r); p.DeletionTimestamp.IsZero() {
		t.Error("port of a missing claim kept")
	}
}
