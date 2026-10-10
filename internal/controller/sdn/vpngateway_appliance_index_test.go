package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

type vpnCachedPortClient struct {
	client.Client
	cache         cache.Cache
	index         toolscache.Indexer
	copied, calls int
}

func (c *vpnCachedPortClient) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	if rows, ok := out.(*sdnv1alpha1.PortList); ok {
		c.calls++
		if err := c.cache.List(ctx, out, opts...); err != nil {
			return err
		}
		c.copied += len(rows.Items)
		return nil
	}
	return c.Client.List(ctx, out, opts...)
}

func vpnApplianceIndexFixture(tb testing.TB, unrelated int, ready bool) (*VPNGatewayReconciler, *sdnv1alpha1.VPNGateway, *sdnv1alpha1.VPC, *vpnCachedPortClient) {
	tb.Helper()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{clientgoscheme.AddToScheme, sdnv1alpha1.AddToScheme} {
		if err := add(scheme); err != nil {
			tb.Fatal(err)
		}
	}
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "tenant-a", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Name: "net", Namespace: gw.Namespace}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/16"}}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: "gateway-vpn", Namespace: gw.Namespace, UID: "deployment-current"}}
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Name: "appliance-rs", Namespace: gw.Namespace, UID: "replicaset-current"}}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "appliance", Namespace: gw.Namespace, UID: "pod-current", Labels: map[string]string{vpnGatewayLabel: gw.Name}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "192.0.2.10"}}
	if ready {
		pod.Status.Conditions = []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}
	}
	for _, pair := range [][2]client.Object{{gw, dep}, {dep, rs}, {rs, pod}} {
		if err := controllerutil.SetControllerReference(pair[0], pair[1], scheme); err != nil {
			tb.Fatal(err)
		}
	}
	port := sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: gw.Namespace, sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelPodUID: string(pod.UID)}}, Spec: sdnv1alpha1.PortSpec{IP: "10.0.0.2", VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}, PodNamespace: pod.Namespace, PodName: pod.Name}}
	ports := []sdnv1alpha1.Port{port}
	for i := range unrelated {
		other := port.DeepCopy()
		other.Spec.IP = fmt.Sprintf("10.0.%d.%d", (i+16)/256, (i+16)%256)
		other.Name = sdn.PortName(vpc.Status.VNI, other.Spec.IP)
		other.Spec.PodName = fmt.Sprintf("workload-%d", i)
		other.Labels[sdnv1alpha1.LabelPodUID] = fmt.Sprintf("workload-uid-%d", i)
		ports = append(ports, *other)
	}
	cached, index := vpnObjectCache(tb, &sdnv1alpha1.Port{}, &sdnv1alpha1.PortList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: ports}, vpnAppliancePodIndex, vpnAppliancePodKeys)
	c := &vpnCachedPortClient{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw, dep, rs, pod).Build(), cache: cached, index: index}
	return &VPNGatewayReconciler{Client: c, Scheme: scheme}, gw, vpc, c
}

func TestVPNApplianceIndexTracksClaimRetargetAndRemoval(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 100, true)
	port := &sdnv1alpha1.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, port); err != nil {
		t.Fatal(err)
	}
	port.Spec.PodName = "other-pod"
	if err := c.index.Update(port); err != nil {
		t.Fatal(err)
	}
	if got := r.resolveAppliancePorts(t.Context(), gw, vpc, 2); len(got) != 0 {
		t.Fatalf("retargeted claim remained a next hop: %+v", got)
	}
	port = port.DeepCopy() // Informer updates replace immutable stored objects.
	port.Spec.PodName = "appliance"
	if err := c.index.Update(port); err != nil {
		t.Fatal(err)
	}
	if got := r.resolveAppliancePorts(t.Context(), gw, vpc, 2); len(got) != 1 {
		t.Fatalf("claim retarget recovery failed: %+v", got)
	}
	if err := c.index.Delete(port); err != nil {
		t.Fatal(err)
	}
	if got := r.resolveAppliancePorts(t.Context(), gw, vpc, 2); len(got) != 0 {
		t.Fatalf("deleted claim remained a next hop: %+v", got)
	}
}

func TestVPNApplianceResolutionMissingIndexHasNoBroadFallback(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 100, true)
	if err := c.cache.RemoveInformer(t.Context(), &sdnv1alpha1.Port{}); err != nil {
		t.Fatal(err)
	}
	c.calls, c.copied = 0, 0
	if got := r.resolveAppliancePorts(t.Context(), gw, vpc, 2); len(got) != 0 || c.calls != 1 || c.copied != 0 {
		t.Fatalf("missing index fell back to a VPC scan: choices=%v calls=%d copied=%d", got, c.calls, c.copied)
	}
}

func TestVPNApplianceResolutionKeepsBothOwnedReplicas(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 100, true)
	gw.Spec.HA = &sdnv1alpha1.VPNGatewayHA{Mode: sdnv1alpha1.VPNGatewayHAModeActiveActive}
	ss := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "statefulset-current"}}
	if err := controllerutil.SetControllerReference(gw, ss, r.Scheme); err != nil {
		t.Fatal(err)
	}
	if err := c.Create(t.Context(), ss); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		name := fmt.Sprintf("gateway-vpn-%d", i)
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: gw.Namespace, UID: types.UID(name), Labels: map[string]string{vpnGatewayLabel: gw.Name}}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: fmt.Sprintf("192.0.2.%d", i+11), Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}}}}
		if err := controllerutil.SetControllerReference(ss, pod, r.Scheme); err != nil {
			t.Fatal(err)
		}
		if err := c.Create(t.Context(), pod); err != nil {
			t.Fatal(err)
		}
		ip := fmt.Sprintf("10.0.0.%d", i+3)
		port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(vpc.Status.VNI, ip), CreationTimestamp: metav1.NewTime(time.Unix(200-int64(i), 0)), Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: gw.Namespace, sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelPodUID: string(pod.UID)}}, Spec: sdnv1alpha1.PortSpec{IP: ip, VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}, PodNamespace: pod.Namespace, PodName: pod.Name}}
		if err := c.index.Add(port); err != nil {
			t.Fatal(err)
		}
	}
	c.calls, c.copied = 0, 0
	got := r.resolveAppliancePorts(t.Context(), gw, vpc, 2)
	if len(got) != 2 || c.calls != 2 || c.copied != 2 || got[0].PodName != "gateway-vpn-0" || got[1].PodName != "gateway-vpn-1" {
		t.Fatalf("owned ordinal endpoints lost or reordered: choices=%v calls=%d copied=%d", got, c.calls, c.copied)
	}
}

func TestVPNApplianceIndexRejectsUnusableOversizedPodReferences(t *testing.T) {
	p := &sdnv1alpha1.Port{Spec: sdnv1alpha1.PortSpec{PodNamespace: "tenant-a", PodName: strings.Repeat("x", 1<<20)}}
	if keys := vpnAppliancePodKeys(p); len(keys) != 0 {
		t.Fatal("oversized reference allocated an unusable pod index key")
	}
	p.Spec.PodNamespace, p.Spec.PodName = strings.Repeat("x", 64), "pod"
	if keys := vpnAppliancePodKeys(p); len(keys) != 0 {
		t.Fatal("oversized namespace allocated an unusable pod index key")
	}
}

func TestVPNApplianceResolutionCopiesOnlyCandidateClaims(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 4000, true)
	choices := r.resolveAppliancePorts(t.Context(), gw, vpc, 2)
	if len(choices) != 1 || choices[0].Port != "v101.10-0-0-2" {
		t.Fatalf("owned current appliance disappeared: %+v", choices)
	}
	if c.copied != 1 {
		t.Fatalf("one appliance copied %d whole-VPC Ports; want only its one current candidate", c.copied)
	}
}

func TestVPNApplianceResolutionSkipsPortsWithoutReadyPod(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 4000, false)
	if choices := r.resolveAppliancePorts(t.Context(), gw, vpc, 2); len(choices) != 0 || c.calls != 0 {
		t.Fatalf("no Ready appliance still read Ports: choices=%v calls=%d copied=%d", choices, c.calls, c.copied)
	}
}

func BenchmarkVPNApplianceResolutionActualCache(b *testing.B) {
	r, gw, vpc, _ := vpnApplianceIndexFixture(b, 4000, true)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if choices := r.resolveAppliancePorts(b.Context(), gw, vpc, 2); len(choices) != 1 {
			b.Fatal("appliance disappeared")
		}
	}
}
