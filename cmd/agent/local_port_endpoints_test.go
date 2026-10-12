package main

import (
	"testing"

	localv1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	"github.com/lllamnyp/cozyplane/internal/vmidentity"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corefake "k8s.io/client-go/kubernetes/fake"
)

func TestLegacyMigrationVethRequiresLiveSandboxAndProtectedOwner(t *testing.T) {
	port := &sdnv1.Port{ObjectMeta: metav1.ObjectMeta{UID: "port-owner", Labels: map[string]string{sdnv1.LabelVMName: "guest", vmidentity.InstanceUIDLabel: "instance-owner"}}, Spec: sdnv1.PortSpec{Node: "source", PodNamespace: "tenant"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "target-pod", Namespace: "tenant", UID: "pod-owner", OwnerReferences: []metav1.OwnerReference{{APIVersion: "kubevirt.io/v1", Kind: "VirtualMachineInstance", Name: "guest", UID: "instance-owner", Controller: new(true), BlockOwnerDeletion: new(true)}}}, Spec: corev1.PodSpec{NodeName: "target"}}
	claim := &localv1.FabricIP{Spec: localv1.FabricIPSpec{Node: "target", PodNamespace: "tenant", PodName: "target-pod", PodUID: "pod-owner", ContainerID: "sandbox", IfName: "eth0"}}
	v := datapath.LocalPortVeth{ContainerID: "sandbox", IfName: "eth0"}
	for _, kind := range []string{"valid", "reused-pod-name", "unprotected-owner", "wrong-instance", "other-node", "other-sandbox", "other-interface"} {
		t.Run(kind, func(t *testing.T) {
			p := pod.DeepCopy()
			c := claim.DeepCopy()
			switch kind {
			case "reused-pod-name":
				p.UID = "replacement"
			case "unprotected-owner":
				p.OwnerReferences[0].BlockOwnerDeletion = new(false)
			case "wrong-instance":
				p.OwnerReferences[0].UID = "other-instance"
			case "other-node":
				p.Spec.NodeName = "elsewhere"
			case "other-sandbox":
				c.Spec.ContainerID = "other"
			case "other-interface":
				c.Spec.IfName = "net1"
			}
			owned, err := legacyVethOwnsPort(t.Context(), corefake.NewSimpleClientset(p), []*localv1.FabricIP{c}, port, v, "target")
			if err != nil || owned != (kind == "valid") {
				t.Fatalf("ownership=%v err=%v", owned, err)
			}
		})
	}
	port.Annotations = map[string]string{sdnv1.AnnotationCNIIfName: "net1"}
	v.IfName = "net1"
	if owned, err := legacyVethOwnsPort(t.Context(), corefake.NewSimpleClientset(pod), []*localv1.FabricIP{claim}, port, v, "target"); err != nil || !owned {
		t.Fatal("secondary target did not join primary sandbox claim", owned, err)
	}
}
