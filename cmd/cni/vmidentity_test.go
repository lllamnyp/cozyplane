package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestPersistentVMIdentityCannotComeFromLabels(t *testing.T) {
	vmi := &unstructured.Unstructured{}
	vmi.SetGroupVersionKind(schema.GroupVersionKind{Group: "kubevirt.io", Version: "v1", Kind: "VirtualMachineInstance"})
	vmi.SetName("vm")
	vmi.SetNamespace("tenant")
	vmi.SetUID("current-instance")
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), vmi)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "launcher", Namespace: "tenant", UID: "pod-uid", Labels: map[string]string{sdnv1alpha1.KubeVirtLabelVMName: "vm"}}}
	if _, err := verifiedVMName(t.Context(), pod, client); err == nil {
		t.Fatal("VM label alone accepted")
	}
	pod.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(vmi, vmi.GroupVersionKind())}
	if name, err := verifiedVMName(t.Context(), pod, client); err != nil || name != "vm" {
		t.Fatalf("current protected owner rejected: name=%s err=%v", name, err)
	}
	pod.OwnerReferences[0].UID = "old-instance"
	if _, err := verifiedVMName(t.Context(), pod, client); err == nil {
		t.Fatal("name-reused VMI accepted")
	}
	pod.OwnerReferences[0].UID = vmi.GetUID()
	pod.OwnerReferences[0].BlockOwnerDeletion = new(false)
	if _, err := verifiedVMName(t.Context(), pod, client); err == nil {
		t.Fatal("unprotected controller reference accepted")
	}
}
