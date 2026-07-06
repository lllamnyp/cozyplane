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
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func launcher(name, node, vm, fabricIP string, uid types.UID) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "tenant",
			Name:      name,
			UID:       uid,
			Labels: map[string]string{
				sdnv1alpha1.KubeVirtLabelVMName:   vm,
				sdnv1alpha1.KubeVirtLabelNodeName: node, // present only on the active pod
			},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fabricIP},
	}
}

func persistentPort(vm, ip, node string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "v100." + ip,
			Labels: map[string]string{sdnv1alpha1.LabelVMName: vm},
		},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef:       sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "vpc"},
			IP:           ip,
			MAC:          "02:00:00:00:00:01",
			Node:         node,
			PodNamespace: "tenant",
		},
	}
}

func vmi(vm, nodeName string) *unstructured.Unstructured {
	u := newVMI()
	u.SetNamespace("tenant")
	u.SetName(vm)
	_ = unstructured.SetNestedField(u.Object, nodeName, "status", "nodeName")
	return u
}

// vmiMigrating models the lag window: status.nodeName still names the source
// while an in-flight migration targets another node (targetNode set, not failed).
func vmiMigrating(vm, nodeName, targetNode string) *unstructured.Unstructured {
	u := vmi(vm, nodeName)
	_ = unstructured.SetNestedField(u.Object, targetNode, "status", "migrationState", "targetNode")
	return u
}

func ppScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(s)
	_ = sdnv1alpha1.AddToScheme(s)
	// Register the VMI GVK so the fake client can serve the unstructured object.
	s.AddKnownTypeWithName(vmiGVK, &unstructured.Unstructured{})
	return s
}

func node(name, ip string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: ip}}},
	}
}

func reconcilePP(t *testing.T, r *PersistentPortReconciler, name string) *sdnv1alpha1.Port {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.Port{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: name}, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	return got
}

// With KubeVirt, the cutover follows the VMI's status.nodeName: after the VMI
// flips to the target, the persistent Port re-points there (and binds to the
// target launcher's fabric IP) even though BOTH launchers are still running.
func TestCutoverFollowsVMINode(t *testing.T) {
	src := launcher("virt-launcher-vm-src", "node-a", "vm", "10.244.0.5", "uid-src")
	dst := launcher("virt-launcher-vm-dst", "node-b", "vm", "10.244.1.9", "uid-dst")
	// Mid-migration both pods carry the nodeName label; the VMI is the decider.
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).
		WithObjects(persistentPort("vm", "192.168.0.2", "node-a"), src, dst,
			node("node-a", "10.0.0.1"), node("node-b", "10.0.0.2"),
			vmi("vm", "node-b")).
		Build()
	r := &PersistentPortReconciler{Client: c, watchVMI: true}

	got := reconcilePP(t, r, "v100.192.168.0.2")
	if got.Spec.Node != "node-b" {
		t.Fatalf("port node = %q, want node-b (the VMI's current node)", got.Spec.Node)
	}
	if got.Spec.FabricIP != "10.244.1.9" {
		t.Errorf("fabric IP = %q, want the target launcher's %q", got.Spec.FabricIP, "10.244.1.9")
	}
	if got.Spec.NodeIP != "10.0.0.2" {
		t.Errorf("node IP = %q, want node-b's %q", got.Spec.NodeIP, "10.0.0.2")
	}
}

// Stage-3 anti-flap: when the target agent has already flipped spec.node to the
// migration target on the guest's announcement, the controller must NOT revert
// it to the (still-lagging) VMI status.nodeName source. It keeps the target.
func TestCutoverDefersToGuestAnnouncement(t *testing.T) {
	src := launcher("virt-launcher-vm-src", "node-a", "vm", "10.244.0.5", "uid-src")
	dst := launcher("virt-launcher-vm-dst", "node-b", "vm", "10.244.1.9", "uid-dst")
	// The agent already moved the Port to node-b (target). The VMI still reports
	// node-a as the active node, with an in-flight migration targeting node-b.
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).
		WithObjects(persistentPort("vm", "192.168.0.2", "node-b"), src, dst,
			node("node-a", "10.0.0.1"), node("node-b", "10.0.0.2"),
			vmiMigrating("vm", "node-a", "node-b")).
		Build()
	r := &PersistentPortReconciler{Client: c, watchVMI: true}

	got := reconcilePP(t, r, "v100.192.168.0.2")
	if got.Spec.Node != "node-b" {
		t.Fatalf("port node = %q, want node-b kept (no revert to the lagging source)", got.Spec.Node)
	}
	if got.Spec.NodeIP != "10.0.0.2" {
		t.Errorf("node IP = %q, want node-b's %q", got.Spec.NodeIP, "10.0.0.2")
	}
}

// Without KubeVirt (watchVMI false), the cutover falls back to the launcher
// pod's kubevirt.io/nodeName label — the pre-existing behavior is unchanged.
func TestCutoverFallsBackToPodLabel(t *testing.T) {
	// Only the target carries the nodeName label (KubeVirt moved it at cutover).
	src := launcher("virt-launcher-vm-src", "node-a", "vm", "10.244.0.5", "uid-src")
	src.Labels[sdnv1alpha1.KubeVirtLabelNodeName] = "" // source no longer active
	dst := launcher("virt-launcher-vm-dst", "node-b", "vm", "10.244.1.9", "uid-dst")
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).
		WithObjects(persistentPort("vm", "192.168.0.2", "node-a"), src, dst,
			node("node-a", "10.0.0.1"), node("node-b", "10.0.0.2")).
		Build()
	r := &PersistentPortReconciler{Client: c} // watchVMI false

	got := reconcilePP(t, r, "v100.192.168.0.2")
	if got.Spec.Node != "node-b" {
		t.Fatalf("port node = %q, want node-b (the active launcher's node)", got.Spec.Node)
	}
}

// No virt-launcher pods ⇒ the VM is gone ⇒ the persistent Port is GC'd.
func TestPersistentPortGCWhenNoPods(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(ppScheme(t)).
		WithObjects(persistentPort("vm", "192.168.0.2", "node-a")).
		Build()
	r := &PersistentPortReconciler{Client: c}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "v100.192.168.0.2"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	err := r.Get(context.Background(), types.NamespacedName{Name: "v100.192.168.0.2"}, &sdnv1alpha1.Port{})
	if !apierrors.IsNotFound(err) {
		t.Fatalf("port should have been GC'd (NotFound), got err=%v", err)
	}
}
