package main

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corefake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
)

func TestHealFabricIPRequiresRebuiltLocalEndpointAndPreservesForeignClaim(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}, {IP: "fd00::10"}}}}
	core := corefake.NewClientset(pod)
	foreign := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: localv1alpha1.FabricIPName("fd00::10")}, Spec: localv1alpha1.FabricIPSpec{Address: "fd00::10", PodUID: "other-pod", Node: "node-b"}}
	local := localfake.NewSimpleClientset(foreign)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := healLocalFabricIPs(t.Context(), core, local, "node-a", nil, log); err != nil {
		t.Fatal(err)
	}
	if len(core.Actions()) != 0 {
		t.Fatal("repair without rebuilt endpoints listed historical Pods")
	}
	list, err := local.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 {
		t.Fatal("status address without local state repaired")
	}
	state := []datapath.LocalFabricIP{{Address: "10.244.0.10", ContainerID: "sandbox", IfName: "eth0"}, {Address: "fd00::10", ContainerID: "sandbox", IfName: "eth0"}}
	for i := 0; i < 2; i++ {
		if err := healLocalFabricIPs(t.Context(), core, local, "node-a", state, log); err != nil {
			t.Fatal(err)
		}
	}
	repaired, err := local.LocalV1alpha1().FabricIPs().Get(t.Context(), localv1alpha1.FabricIPName("10.244.0.10"), metav1.GetOptions{})
	if err != nil || repaired.Spec.PodUID != "pod-uid" || repaired.Spec.ContainerID != "sandbox" || repaired.Spec.IfName != "eth0" {
		t.Fatalf("missing or incorrect repair: %v %v", repaired, err)
	}
	kept, err := local.LocalV1alpha1().FabricIPs().Get(t.Context(), foreign.Name, metav1.GetOptions{})
	if err != nil || kept.Spec.PodUID != "other-pod" {
		t.Fatal("conflicting claim overwritten")
	}
	list, err = local.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 2 {
		t.Fatal("repair retry created extra claims")
	}
}

func TestHealFabricIPDoesNotRepairFromPartialPodSnapshot(t *testing.T) {
	core := corefake.NewClientset()
	local := localfake.NewSimpleClientset()
	calls := 0
	core.PrependReactor("list", "pods", func(ktesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			return true, &corev1.PodList{ListMeta: metav1.ListMeta{Continue: "next"}, Items: []corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.244.0.10"}}}}, nil
		}
		return true, nil, errors.New("snapshot expired")
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	state := []datapath.LocalFabricIP{{Address: "10.244.0.10", ContainerID: "sandbox", IfName: "eth0"}}
	if err := healLocalFabricIPs(t.Context(), core, local, "node-a", state, log); err == nil {
		t.Fatal("incomplete snapshot was accepted")
	}
	if calls != 2 || len(local.Actions()) != 0 {
		t.Fatalf("partial snapshot performed claim operations: calls=%d actions=%v", calls, local.Actions())
	}
}

func TestHealFabricIPDoesNotGuessBetweenRebuiltSandboxes(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		core := corefake.NewClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIPs: []corev1.PodIP{{IP: "10.244.0.10"}}}})
		local := localfake.NewSimpleClientset()
		state := []datapath.LocalFabricIP{{Address: "10.244.0.10", ContainerID: "old-sandbox", IfName: "eth0"}, {Address: "10.244.0.10", ContainerID: "current-sandbox", IfName: "eth0"}}
		if reverse {
			state[0], state[1] = state[1], state[0]
		}
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		if err := healLocalFabricIPs(t.Context(), core, local, "node-a", state, log); err != nil {
			t.Fatal(err)
		}
		if len(core.Actions()) != 0 {
			t.Fatal("ambiguous rebuilt endpoints still caused a Pod scan")
		}
		claims, err := local.LocalV1alpha1().FabricIPs().List(t.Context(), metav1.ListOptions{})
		if err != nil || len(claims.Items) != 0 {
			t.Fatalf("repair guessed sandbox ownership (reverse=%v): %v %v", reverse, claims, err)
		}
	}
}
