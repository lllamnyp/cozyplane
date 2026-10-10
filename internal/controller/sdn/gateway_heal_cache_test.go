package sdn

import (
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func gatewayHealCacheFixture(tb testing.TB, ready bool) (*GatewayReconciler, *sdnv1alpha1.VPC, *vpnCachedPortClient, *corev1.Pod) {
	tb.Helper()
	vpn, _, vpc, c := vpnApplianceIndexFixture(tb, 4000, ready)
	vpc.UID = "vpc-current"
	r := &GatewayReconciler{Client: c, Scheme: vpn.Scheme, Config: GatewayConfig{Namespace: "system-a"}}
	dep := r.deployment(vpc)
	dep.UID = "deployment-current"
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: r.Config.Namespace, Name: "gateway-rs", UID: "replicaset-current", OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(dep, appsv1.SchemeGroupVersion.WithKind("Deployment"))}}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: r.Config.Namespace, Name: "appliance", UID: "pod-current", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: vpc.Namespace, sdnv1alpha1.LabelVPC: vpc.Name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(rs, appsv1.SchemeGroupVersion.WithKind("ReplicaSet"))}}, Status: corev1.PodStatus{Phase: corev1.PodRunning}}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	c.Client = fake.NewClientBuilder().WithScheme(vpn.Scheme).WithObjects(vpc, dep, rs, pod).Build()
	port := &sdnv1alpha1.Port{}
	if err := c.cache.Get(tb.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, port); err != nil {
		tb.Fatal(err)
	}
	if err := c.index.Delete(port); err != nil {
		tb.Fatal(err)
	}
	port.Name, port.Spec.IP = "v101.10-0-0-1", "10.0.0.1"
	port.Spec.PodNamespace, port.Spec.Gateway = pod.Namespace, true
	if err := c.index.Add(port); err != nil {
		tb.Fatal(err)
	}
	c.calls, c.copied = 0, 0
	return r, vpc, c, pod
}

func TestGatewayHealingCopiesOnlyRelatedClaims(t *testing.T) {
	r, vpc, c, pod := gatewayHealCacheFixture(t, true)
	if err := r.healSeveredGateway(t.Context(), vpc); err != nil {
		t.Fatal(err)
	}
	if c.calls != 1 || c.copied != 1 {
		t.Fatalf("one Ready gateway copied=%d Ports in %d lists; want one related claim", c.copied, c.calls)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatalf("healthy gateway was removed: %v", err)
	}
}

func TestGatewayHealingSkipsClaimsWithoutReadyPod(t *testing.T) {
	r, vpc, c, _ := gatewayHealCacheFixture(t, false)
	if err := r.healSeveredGateway(t.Context(), vpc); err != nil {
		t.Fatal(err)
	}
	if c.calls != 0 || c.copied != 0 {
		t.Fatalf("no Ready gateway copied=%d Ports in %d lists", c.copied, c.calls)
	}
}

func TestGatewayHealingMissingIndexNeverDeletesAndRecovers(t *testing.T) {
	r, vpc, c, pod := gatewayHealCacheFixture(t, true)
	var current sdnv1alpha1.PortList
	if err := c.cache.List(t.Context(), &current); err != nil {
		t.Fatal(err)
	}
	if err := c.cache.RemoveInformer(t.Context(), &sdnv1alpha1.Port{}); err != nil {
		t.Fatal(err)
	}
	if err := r.healSeveredGateway(t.Context(), vpc); err == nil {
		t.Fatal("missing index did not fail")
	}
	if c.calls != 1 || c.copied != 0 {
		t.Fatalf("missing index triggered broad scan: lists=%d copied=%d", c.calls, c.copied)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatalf("missing index caused deletion: %v", err)
	}
	// Restart from the current upstream snapshot, rather than the fixture's
	// initial list which predates its simulated gateway claim update.
	current.ListMeta = metav1.ListMeta{ResourceVersion: "2"} // No cache-only continuation marker.
	c.cache, c.index = vpnObjectCache(t, &sdnv1alpha1.Port{}, &current, vpnAppliancePodIndex, vpnAppliancePodKeys)
	if err := r.healSeveredGateway(t.Context(), vpc); err != nil {
		t.Fatalf("restored index did not recover: %v", err)
	}
	if c.copied != 1 {
		t.Fatal("restored index did not select only related claim")
	}
}

func TestGatewayHealingForeignReadyPodDoesNotReadClaims(t *testing.T) {
	r, vpc, c, pod := gatewayHealCacheFixture(t, true)
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), pod); err != nil {
		t.Fatal(err)
	}
	pod.OwnerReferences = nil
	if err := c.Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	if err := r.healSeveredGateway(t.Context(), vpc); err != nil {
		t.Fatal(err)
	}
	if c.calls != 0 || c.copied != 0 {
		t.Fatal("foreign Ready pod drove Port lookup")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); err != nil {
		t.Fatalf("foreign Ready pod was deleted: %v", err)
	}
}

func TestGatewayHealingDeletedOrRetargetedClaimRecreatesOnlyOwnedPod(t *testing.T) {
	for _, retarget := range []bool{false, true} {
		r, vpc, c, pod := gatewayHealCacheFixture(t, true)
		port := &sdnv1alpha1.Port{}
		if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-1"}, port); err != nil {
			t.Fatal(err)
		}
		if retarget {
			port.Spec.PodName = "other-pod"
			if err := c.index.Update(port.DeepCopy()); err != nil {
				t.Fatal(err)
			}
		} else if err := c.index.Delete(port); err != nil {
			t.Fatal(err)
		}
		if err := r.healSeveredGateway(t.Context(), vpc); err != nil {
			t.Fatal(err)
		}
		if c.calls != 1 || c.copied != 0 {
			t.Fatal("stale claim retained in exact pod lookup")
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(pod), &corev1.Pod{}); !apierrors.IsNotFound(err) {
			t.Fatalf("owned severed pod not reaped: %v", err)
		}
	}
}

func BenchmarkGatewayHealingActualCache(b *testing.B) {
	r, vpc, _, _ := gatewayHealCacheFixture(b, true)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if err := r.healSeveredGateway(b.Context(), vpc); err != nil {
			b.Fatal(err)
		}
	}
}
