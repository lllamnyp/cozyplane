package sdn

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPortGCReapsCompletedPodClaimsWithoutDeletingVMIdentity(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodSucceeded, corev1.PodFailed, corev1.PodRunning, corev1.PodPending, corev1.PodUnknown} {
		t.Run(string(phase), func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "job", UID: "pod-uid"}, Status: corev1.PodStatus{Phase: phase}}
			port := claimedPort("v100.10-10-0-1", pod.Namespace, pod.Name, string(pod.UID), false)
			pinned := port.DeepCopy()
			pinned.Name = "v100.10-10-0-2"
			pinned.Spec.IP, pinned.Spec.MAC = "10.10.0.2", "02:00:00:00:00:02"
			pinned.Labels[sdn.LabelVMName] = "vm"
			c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithObjects(pod, port, pinned).Build()
			r := &PortGCReconciler{Client: c}
			for _, claim := range []*sdn.Port{port, pinned} {
				if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(claim)}); err != nil {
					t.Fatal(err)
				}
			}
			got := &sdn.Port{}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil && !apierrors.IsNotFound(err) {
				t.Fatal(err)
			}
			terminal := phase == corev1.PodSucceeded || phase == corev1.PodFailed
			if !got.DeletionTimestamp.IsZero() != terminal {
				t.Fatalf("phase=%s claim terminating=%v", phase, !got.DeletionTimestamp.IsZero())
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(pinned), got); err != nil || !got.DeletionTimestamp.IsZero() || got.Spec.IP != pinned.Spec.IP || got.Spec.MAC != pinned.Spec.MAC {
				t.Fatal("persistent VM identity changed", got, err)
			}
		})
	}
}

func TestPortGCTerminalDecisionIsConfirmedLive(t *testing.T) {
	for _, phase := range []corev1.PodPhase{corev1.PodRunning, corev1.PodUnknown, corev1.PodFailed} {
		t.Run(string(phase), func(t *testing.T) {
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "job", UID: "pod-uid"}, Status: corev1.PodStatus{Phase: corev1.PodSucceeded}}
			port := claimedPort("v100.10-10-0-1", pod.Namespace, pod.Name, string(pod.UID), false)
			scheme := gatewayScheme(t)
			cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(port, pod).Build()
			livePod := pod.DeepCopy()
			livePod.Status.Phase = phase
			live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(livePod).Build()
			r := &PortGCReconciler{Client: cached, Reader: live}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(port)}); err != nil {
				t.Fatal(err)
			}
			got := &sdn.Port{}
			if err := cached.Get(t.Context(), client.ObjectKeyFromObject(port), got); err != nil {
				t.Fatal(err)
			}
			if !got.DeletionTimestamp.IsZero() != (phase == corev1.PodFailed) {
				t.Fatal("GC ignored live phase", phase, got.DeletionTimestamp)
			}
		})
	}
}
