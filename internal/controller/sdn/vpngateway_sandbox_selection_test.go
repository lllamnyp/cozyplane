package sdn

import (
	"context"
	"strings"
	"testing"
	"time"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpnFabricReadCounter struct {
	client.Client
	fabricGets int
}

func (c *vpnFabricReadCounter) Get(ctx context.Context, key client.ObjectKey, out client.Object, opts ...client.GetOption) error {
	if _, ok := out.(*local.FabricIP); ok {
		c.fabricGets++
	}
	return c.Client.Get(ctx, key, out, opts...)
}

func TestVPNCurrentSandboxWinsBeforeOldPortGC(t *testing.T) {
	r, gw, vpc, c := vpnApplianceIndexFixture(t, 0, true)
	if err := local.AddToScheme(r.Scheme); err != nil {
		t.Fatal(err)
	}
	pod := &corev1.Pod{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: "appliance"}, pod); err != nil {
		t.Fatal(err)
	}
	pod.Spec.NodeName = "node-a"
	if err := c.Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	pod.Status.PodIPs = []corev1.PodIP{{IP: pod.Status.PodIP}}
	if err := c.Status().Update(t.Context(), pod); err != nil {
		t.Fatal(err)
	}
	old := &sdnv1alpha1.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, old); err != nil {
		t.Fatal(err)
	}
	old.CreationTimestamp = metav1.NewTime(time.Unix(100, 0))
	old.Annotations = map[string]string{sdnv1alpha1.AnnotationContainerID: strings.Repeat("a", 64), sdnv1alpha1.AnnotationCNIIfName: "eth0"}
	if err := c.index.Update(old); err != nil {
		t.Fatal(err)
	}
	current := old.DeepCopy()
	current.Spec.IP = "10.0.0.3"
	current.Name = sdn.PortName(vpc.Status.VNI, current.Spec.IP)
	current.CreationTimestamp = metav1.NewTime(time.Unix(200, 0))
	current.Annotations[sdnv1alpha1.AnnotationContainerID] = strings.Repeat("b", 64)
	if err := c.index.Add(current); err != nil {
		t.Fatal(err)
	}
	claim := &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: local.FabricIPName(pod.Status.PodIP)}, Spec: local.FabricIPSpec{Address: pod.Status.PodIP, Node: pod.Spec.NodeName, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), ContainerID: current.Annotations[sdnv1alpha1.AnnotationContainerID], IfName: "eth0"}}
	if err := c.Create(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	witness, err := currentPodSandbox(t.Context(), c.Client, pod, "eth0")
	if err != nil || witness != current.Annotations[sdnv1alpha1.AnnotationContainerID] {
		t.Fatalf("fixture lacks current sandbox proof: witness=%q err=%v", witness, err)
	}
	counter := &vpnFabricReadCounter{Client: c.Client}
	c.Client = counter
	t.Run("managed VPN", func(t *testing.T) {
		got := r.resolveAppliancePorts(t.Context(), gw, vpc, 1)
		if len(got) != 1 || got[0].Port != current.Name {
			t.Fatalf("same pod UID selected stale sandbox before GC: choices=%+v want=%s", got, current.Name)
		}
	})
	t.Run("explicit VPC gateway", func(t *testing.T) {
		counter.fabricGets = 0
		gateway := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "route-gateway"}}
		gateway.Spec.VPCRef.Name = vpc.Name
		gateway.Spec.Routes = make([]sdnv1alpha1.VPCGatewayRoute, 16)
		for i := range gateway.Spec.Routes {
			gateway.Spec.Routes[i].CIDRs = []string{"203.0.113.0/24"}
			gateway.Spec.Routes[i].Via.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{vpnGatewayLabel: gw.Name}}
		}
		vr := &VPCGatewayReconciler{Client: r.Client}
		got, problem, err := vr.reconcileRoutes(t.Context(), gateway, vpc)
		if err != nil || problem != "" || len(got) != 16 || got[0].Port != current.Name {
			t.Fatalf("explicit next hop selected stale sandbox: routes=%+v problem=%q err=%v want=%s", got, problem, err, current.Name)
		}
		for _, route := range got {
			if route.Port != current.Name {
				t.Fatalf("another route selected the obsolete sandbox: %+v", route)
			}
		}
		if counter.fabricGets != 1 {
			t.Fatalf("repeated selectors repeated sandbox reads: gets=%d want1", counter.fabricGets)
		}
	})
	t.Run("default VPC door", func(t *testing.T) {
		for _, source := range []*sdnv1alpha1.Port{old, current} {
			stored := source.DeepCopy()
			if err := c.Create(t.Context(), stored); err != nil {
				t.Fatal(err)
			}
			if err := c.index.Update(stored); err != nil {
				t.Fatal(err)
			}
		}
		gateway := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "default-gateway"}}
		gateway.Spec.VPCRef.Name = vpc.Name
		gateway.Spec.Appliance = &sdnv1alpha1.VPCGatewayAppliance{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{vpnGatewayLabel: gw.Name}}}
		counter.fabricGets = 0
		vr := &VPCGatewayReconciler{Client: r.Client}
		chosen, problem, err := vr.reconcileAppliance(t.Context(), gateway, vpc)
		if err != nil || problem != "" || chosen != current.Name || counter.fabricGets != 1 {
			t.Fatalf("default door selected obsolete sandbox: chosen=%s problem=%q err=%v gets=%d", chosen, problem, err, counter.fabricGets)
		}
	})
}

func TestRouteSandboxSnapshotUsesCurrentPodVersionAndCancellation(t *testing.T) {
	_, gw, _, c := vpnApplianceIndexFixture(t, 0, true)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "appliance", UID: "pod-current", ResourceVersion: "1"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "192.0.2.10"}}}}
	if err := local.AddToScheme(c.Scheme()); err != nil {
		t.Fatal(err)
	}
	claim := &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: local.FabricIPName("192.0.2.10")}, Spec: local.FabricIPSpec{Address: "192.0.2.10", Node: pod.Spec.NodeName, PodNamespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), ContainerID: strings.Repeat("a", 64), IfName: "eth0"}}
	if err := c.Create(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	counter := &vpnFabricReadCounter{Client: c.Client}
	snapshot := podSandboxSnapshot{}
	for range 100 {
		if sid, err := snapshot.forPod(t.Context(), counter, pod); err != nil || sid != claim.Spec.ContainerID {
			t.Fatalf("current witness unavailable: %q %v", sid, err)
		}
	}
	if counter.fabricGets != 1 {
		t.Fatalf("same-version witness not reused: gets=%d", counter.fabricGets)
	}
	claim.Spec.ContainerID = strings.Repeat("b", 64)
	if err := c.Update(t.Context(), claim); err != nil {
		t.Fatal(err)
	}
	pod.ResourceVersion = "2"
	if sid, err := snapshot.forPod(t.Context(), counter, pod); err != nil || sid != claim.Spec.ContainerID || counter.fabricGets != 2 {
		t.Fatalf("new pod version reused an obsolete witness: %q %v gets=%d", sid, err, counter.fabricGets)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := snapshot.forPod(ctx, counter, pod); err != context.Canceled || counter.fabricGets != 2 {
		t.Fatalf("cancelled lookup used cached authority: err=%v gets=%d", err, counter.fabricGets)
	}
}
