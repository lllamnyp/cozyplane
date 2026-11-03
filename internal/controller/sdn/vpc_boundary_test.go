package sdn

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/pkg/boundaryidentity"
)

type boundaryFixture struct {
	namespace string
	ds        *appsv1.DaemonSet
	pods      []*corev1.Pod
	vpc       *sdnv1alpha1.VPC
}

func newBoundaryFixture() *boundaryFixture {
	controller := true
	f := &boundaryFixture{
		namespace: "network-operator",
		ds: &appsv1.DaemonSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "network-operator", Name: "cozyplane-agent", UID: "operator-agent-ds"},
			Spec:       appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "cozyplane-agent"}}},
			Status:     appsv1.DaemonSetStatus{DesiredNumberScheduled: 2},
		},
		vpc: &sdnv1alpha1.VPC{Spec: sdnv1alpha1.VPCSpec{Boundary: &sdnv1alpha1.VPCBoundary{Revision: 7}}},
	}
	for _, node := range []string{"node-a", "node-b"} {
		uid := types.UID("agent-" + node)
		f.pods = append(f.pods, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: f.namespace, Name: "agent-" + node, UID: uid,
				Labels:          map[string]string{"app": "cozyplane-agent"},
				OwnerReferences: []metav1.OwnerReference{{APIVersion: "apps/v1", Kind: "DaemonSet", Name: f.ds.Name, UID: f.ds.UID, Controller: &controller}},
			},
			Spec:   corev1.PodSpec{NodeName: node},
			Status: corev1.PodStatus{Phase: corev1.PodRunning, Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}},
		})
		f.vpc.Status.BoundaryNodes = append(f.vpc.Status.BoundaryNodes, sdnv1alpha1.VPCBoundaryNode{Node: node, AgentUID: string(uid), Revision: 7, PrimaryPortsDigest: boundaryidentity.Digest(nil)})
	}
	return f
}

func (f *boundaryFixture) reconciler(t *testing.T) *VPCReconciler {
	t.Helper()
	scheme := testScheme(t)
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{}
	if f.ds != nil {
		objects = append(objects, f.ds)
	}
	for _, pod := range f.pods {
		objects = append(objects, pod)
	}
	return &VPCReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build(), AgentNamespace: f.namespace}
}

func TestVPCBoundaryAppliedRequiresEveryCurrentAgent(t *testing.T) {
	for _, tc := range []struct {
		name              string
		change            func(*boundaryFixture)
		policy, transport bool
	}{
		{"policy staged before transport", func(f *boundaryFixture) {}, true, false},
		{"all transport acknowledged", func(f *boundaryFixture) {
			for i := range f.vpc.Status.BoundaryNodes {
				f.vpc.Status.BoundaryNodes[i].TransportReady = true
			}
		}, true, true},
		{"one transport pending", func(f *boundaryFixture) { f.vpc.Status.BoundaryNodes[0].TransportReady = true }, true, false},
		{"missing agent", func(f *boundaryFixture) { f.pods = f.pods[:1] }, false, false},
		{"missing acknowledgement", func(f *boundaryFixture) { f.vpc.Status.BoundaryNodes = f.vpc.Status.BoundaryNodes[:1] }, false, false},
		{"stale agent UID", func(f *boundaryFixture) { f.vpc.Status.BoundaryNodes[1].AgentUID = "old-agent-instance" }, false, false},
		{"stale revision", func(f *boundaryFixture) { f.vpc.Status.BoundaryNodes[1].Revision-- }, false, false},
		{"changed VPC generation", func(f *boundaryFixture) { f.vpc.Generation++ }, false, false},
		{"missing primary digest", func(f *boundaryFixture) { f.vpc.Status.BoundaryNodes[1].PrimaryPortsDigest = "" }, false, false},
		{"not ready", func(f *boundaryFixture) { f.pods[1].Status.Conditions[0].Status = corev1.ConditionFalse }, false, false},
		{"missing readiness", func(f *boundaryFixture) { f.pods[1].Status.Conditions = nil }, false, false},
		{"not running", func(f *boundaryFixture) { f.pods[1].Status.Phase = corev1.PodPending }, false, false},
		{"missing node", func(f *boundaryFixture) { f.pods[1].Spec.NodeName = "" }, false, false},
		{"terminating agent", func(f *boundaryFixture) {
			stamp := metav1.Now()
			f.pods[1].DeletionTimestamp = &stamp
			f.pods[1].Finalizers = []string{"test.example/hold"}
		}, false, false},
		{"desired count greater than actual", func(f *boundaryFixture) { f.ds.Status.DesiredNumberScheduled = 3 }, false, false},
		{"desired count less than actual", func(f *boundaryFixture) { f.ds.Status.DesiredNumberScheduled = 1 }, false, false},
		{"zero desired agents", func(f *boundaryFixture) { f.ds.Status.DesiredNumberScheduled = 0 }, false, false},
		{"no pods", func(f *boundaryFixture) { f.pods = nil }, false, false},
		{"missing daemonset", func(f *boundaryFixture) { f.ds = nil }, false, false},
		{"missing operator namespace", func(f *boundaryFixture) { f.namespace = "" }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newBoundaryFixture()
			tc.change(f)
			policy, transport, err := f.reconciler(t).boundaryApplied(context.Background(), f.vpc)
			if err != nil {
				t.Fatal(err)
			}
			if policy != tc.policy || transport != tc.transport {
				t.Fatalf("policy=%v transport=%v, want policy=%v transport=%v", policy, transport, tc.policy, tc.transport)
			}
		})
	}
}

func TestVPCBoundaryAppliedPrunesRetiredAgentAcknowledgements(t *testing.T) {
	f := newBoundaryFixture()
	f.vpc.Status.BoundaryNodes = append(f.vpc.Status.BoundaryNodes, sdnv1alpha1.VPCBoundaryNode{Node: "retired-node", AgentUID: "retired-agent", Revision: 6, PrimaryPortsDigest: "old-map"})
	policy, _, err := f.reconciler(t).boundaryApplied(context.Background(), f.vpc)
	if err != nil || !policy || len(f.vpc.Status.BoundaryNodes) != 2 {
		t.Fatalf("retired agent prevents future primary verification: policy=%v nodes=%+v err=%v", policy, f.vpc.Status.BoundaryNodes, err)
	}
}

func TestVPCBoundaryAppliedIgnoresForgedAgentPods(t *testing.T) {
	for _, tc := range []struct {
		name  string
		forge func(*corev1.Pod)
	}{
		{"outside operator namespace", func(p *corev1.Pod) { p.Namespace = "tenant-a" }},
		{"wrong owner UID", func(p *corev1.Pod) { p.OwnerReferences[0].UID = "tenant-daemonset" }},
		{"wrong owner kind", func(p *corev1.Pod) { p.OwnerReferences[0].Kind = "ReplicaSet" }},
		{"no controller owner", func(p *corev1.Pod) { p.OwnerReferences[0].Controller = nil }},
		{"non-controller owner", func(p *corev1.Pod) { controller := false; p.OwnerReferences[0].Controller = &controller }},
		{"labels alone", func(p *corev1.Pod) { p.OwnerReferences = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, replace := range []bool{false, true} {
				f := newBoundaryFixture()
				for i := range f.vpc.Status.BoundaryNodes {
					f.vpc.Status.BoundaryNodes[i].TransportReady = true
				}
				forged := f.pods[1].DeepCopy()
				forged.Name = "forged-agent"
				tc.forge(forged)
				if replace {
					f.pods = f.pods[:1]
				} else {
					// Even a matching label plus unrelated unacknowledged node must not
					// poison the legitimate operator's complete acknowledgement set.
					forged.Spec.NodeName = "unrelated-node"
					forged.UID = "unrelated-pod"
				}
				f.pods = append(f.pods, forged)
				policy, transport, err := f.reconciler(t).boundaryApplied(context.Background(), f.vpc)
				if err != nil {
					t.Fatal(err)
				}
				if policy != !replace || transport != !replace {
					t.Fatalf("replace=%v policy=%v transport=%v", replace, policy, transport)
				}
			}
		})
	}
}
