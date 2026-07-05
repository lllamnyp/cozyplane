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
	"testing"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func severPort(name, node string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Finalizers: []string{sdnv1alpha1.FinalizerSever},
		},
		Spec: sdnv1alpha1.PortSpec{Node: node, IP: "10.10.0.2"},
	}
}

// A terminating Port whose node is gone can never be acknowledged by an
// agent; the GC releases the finalizer so deletion completes. A Port whose
// node still exists is left to that node's agent.
func TestPortGCReleasesOrphanedSeverFinalizer(t *testing.T) {
	scheme := gatewayScheme(t)
	orphan := severPort("v100.10-10-0-2", "gone-node")
	held := severPort("v100.10-10-0-3", "live-node")
	liveNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "live-node"}}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orphan, held, liveNode).Build()
	r := &PortGCReconciler{Client: c}
	ctx := context.Background()

	// Delete both: the finalizer holds them terminating.
	for _, p := range []*sdnv1alpha1.Port{orphan, held} {
		if err := c.Delete(ctx, p); err != nil {
			t.Fatalf("delete %s: %v", p.Name, err)
		}
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: orphan.Name}}); err != nil {
		t.Fatalf("reconcile orphan: %v", err)
	}
	if err := c.Get(ctx, types.NamespacedName{Name: orphan.Name}, &sdnv1alpha1.Port{}); !apierrors.IsNotFound(err) {
		t.Errorf("orphaned port should be fully deleted after GC, got %v", err)
	}

	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: held.Name}}); err != nil {
		t.Fatalf("reconcile held: %v", err)
	}
	got := &sdnv1alpha1.Port{}
	if err := c.Get(ctx, types.NamespacedName{Name: held.Name}, got); err != nil {
		t.Fatalf("held port should still exist (its node's agent owns the ack), got %v", err)
	}
	if len(got.Finalizers) == 0 {
		t.Error("held port's sever finalizer should remain while its node exists")
	}
}

func claimedPort(name, podNS, podName, podUID string, gateway bool) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			Finalizers: []string{sdnv1alpha1.FinalizerSever},
			Labels: map[string]string{
				sdnv1alpha1.LabelPodNamespace: podNS,
				sdnv1alpha1.LabelPodName:      podName,
				sdnv1alpha1.LabelPodUID:       podUID,
			},
		},
		Spec: sdnv1alpha1.PortSpec{Node: "live-node", IP: "10.10.0.1", Gateway: gateway},
	}
}

// A live Port whose claimant pod is gone is abandoned (the pod died uncleanly,
// CNI DEL never ran) and gets deleted — for a gateway's fixed .1 that is what
// unwedges the AlreadyExists-looping replacement pod. A Port whose claimant is
// alive, or whose pod name was reused by a *different* pod (UID mismatch means
// the old claimant is gone), is judged by UID. VM persistent Ports are never
// touched here.
func TestPortGCReapsAbandonedClaims(t *testing.T) {
	scheme := gatewayScheme(t)
	alive := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "gw-alive", Namespace: "kube-system", UID: types.UID("uid-1")}}
	reuser := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "gw-reused", Namespace: "kube-system", UID: types.UID("uid-new")}}
	liveNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "live-node"}}

	abandoned := claimedPort("v100.10-10-0-1", "kube-system", "gw-dead", "uid-dead", true)
	held := claimedPort("v101.10-11-0-1", "kube-system", "gw-alive", "uid-1", true)
	reused := claimedPort("v102.10-12-0-1", "kube-system", "gw-reused", "uid-old", true)
	persistent := claimedPort("v103-vm-mig", "tenant-a", "launcher-dead", "uid-dead2", false)
	persistent.Labels[sdnv1alpha1.LabelVMName] = "mig"
	unclaimed := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v104.10-14-0-1"},
		Spec:       sdnv1alpha1.PortSpec{Node: "live-node", IP: "10.14.0.1"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(alive, reuser, liveNode, abandoned, held, reused, persistent, unclaimed).Build()
	r := &PortGCReconciler{Client: c}
	ctx := context.Background()

	for _, name := range []string{abandoned.Name, held.Name, reused.Name, persistent.Name, unclaimed.Name} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
			t.Fatalf("reconcile %s: %v", name, err)
		}
	}

	// Deleted (terminating: the fake client holds them via the finalizer, so
	// "reaped" shows as a set deletionTimestamp).
	for _, name := range []string{abandoned.Name, reused.Name} {
		got := &sdnv1alpha1.Port{}
		if err := c.Get(ctx, types.NamespacedName{Name: name}, got); err == nil {
			if got.DeletionTimestamp.IsZero() {
				t.Errorf("%s: abandoned port should be deleted (or terminating), still live", name)
			}
		} else if !apierrors.IsNotFound(err) {
			t.Errorf("%s: unexpected error %v", name, err)
		}
	}
	// Kept, fully live.
	for _, name := range []string{held.Name, persistent.Name, unclaimed.Name} {
		got := &sdnv1alpha1.Port{}
		if err := c.Get(ctx, types.NamespacedName{Name: name}, got); err != nil {
			t.Errorf("%s: should be kept, got %v", name, err)
		} else if !got.DeletionTimestamp.IsZero() {
			t.Errorf("%s: should be kept, but is terminating", name)
		}
	}
}
