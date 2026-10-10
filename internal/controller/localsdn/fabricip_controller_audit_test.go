package localsdn

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
)

func TestFabricIPGCReapsOnlyStaleRunningSandboxAfterGrace(t *testing.T) {
	for _, tc := range []struct {
		name            string
		phase           corev1.PodPhase
		age             time.Duration
		ips             []corev1.PodIP
		remove, requeue bool
	}{
		{"old stale", corev1.PodRunning, 10 * time.Minute, []corev1.PodIP{{IP: "10.244.0.166"}}, true, false},
		{"new ADD", corev1.PodRunning, time.Second, []corev1.PodIP{{IP: "10.244.0.166"}}, false, true},
		{"live", corev1.PodRunning, 10 * time.Minute, []corev1.PodIP{{IP: "10.244.0.165"}}, false, false},
		{"not yet Running", corev1.PodPending, 10 * time.Minute, []corev1.PodIP{{IP: "10.244.0.166"}}, false, false},
		{"no reported IP", corev1.PodRunning, 10 * time.Minute, nil, false, false},
		{"completed success", corev1.PodSucceeded, time.Second, []corev1.PodIP{{IP: "10.244.0.165"}}, true, false},
		{"completed failure without IP", corev1.PodFailed, time.Second, nil, true, false},
		{"unknown preserved", corev1.PodUnknown, 10 * time.Minute, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			if err := localv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "f-10-244-0-165", UID: "claim-uid", CreationTimestamp: metav1.NewTime(time.Now().Add(-tc.age))}, Spec: localv1alpha1.FabricIPSpec{Address: "10.244.0.165", PodNamespace: "tenant", PodName: "pod", PodUID: "pod-uid"}}
			pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "pod-uid"}, Status: corev1.PodStatus{Phase: tc.phase, PodIPs: tc.ips}}
			c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claim, pod).Build()
			r := &FabricIPReconciler{Client: c}
			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(claim)})
			if err != nil {
				t.Fatal(err)
			}
			if (result.RequeueAfter > 0) != tc.requeue {
				t.Fatalf("unexpected retry: %v", result)
			}
			err = c.Get(t.Context(), client.ObjectKeyFromObject(claim), &localv1alpha1.FabricIP{})
			if apierrors.IsNotFound(err) != tc.remove || err != nil && !apierrors.IsNotFound(err) {
				t.Fatalf("wrong GC decision: %v", err)
			}
		})
	}
}

func TestFabricIPGCUsesLivePodReader(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := localv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "claim", UID: "claim-uid"}, Spec: localv1alpha1.FabricIPSpec{Address: "10.244.0.2", PodNamespace: "tenant", PodName: "pod", PodUID: "uid"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "tenant", UID: "uid"}}
	// A stale terminal informer view cannot overrule the live nonterminal Pod.
	stalePod := pod.DeepCopy()
	stalePod.Status.Phase = corev1.PodSucceeded
	cached := fake.NewClientBuilder().WithScheme(scheme).WithObjects(claim, stalePod).Build()
	live := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pod).Build()
	r := &FabricIPReconciler{Client: cached, Reader: live}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(claim)}); err != nil {
		t.Fatal(err)
	}
	if err := cached.Get(t.Context(), client.ObjectKeyFromObject(claim), &localv1alpha1.FabricIP{}); err != nil {
		t.Fatal("claim lost due to delayed informer", err)
	}
}
