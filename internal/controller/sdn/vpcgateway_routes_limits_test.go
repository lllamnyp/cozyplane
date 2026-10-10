package sdn

import (
	"context"
	"fmt"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type routePodListCounter struct {
	client.Client
	podLists int
}

func (c *routePodListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if _, ok := list.(*corev1.PodList); ok {
		c.podLists++
	}
	return c.Client.List(ctx, list, opts...)
}

func TestVPCRouteLimitsRejectBeforeSelectorExpansion(t *testing.T) {
	for _, manyRoutes := range []bool{false, true} {
		t.Run(map[bool]string{false: "prefixes", true: "routes"}[manyRoutes], func(t *testing.T) {
			r, gw, vpc := routeSecurityFixture(t, "203.0.113.0/24")
			counter := &routePodListCounter{Client: r.Client}
			r.Client = counter
			if manyRoutes {
				route := gw.Spec.Routes[0]
				gw.Spec.Routes = make([]sdnv1alpha1.VPCGatewayRoute, 4097)
				for i := range gw.Spec.Routes {
					gw.Spec.Routes[i] = route
				}
			} else {
				gw.Spec.Routes[0].CIDRs = make([]string, 4097)
				for i := range gw.Spec.Routes[0].CIDRs {
					gw.Spec.Routes[0].CIDRs[i] = "203.0.113.0/24"
				}
			}
			out, problem, err := r.reconcileRoutes(t.Context(), gw, vpc)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != 0 || problem == "" || counter.podLists != 0 {
				t.Fatalf("oversized route input expanded: rows=%d podLists=%d problem=%q", len(out), counter.podLists, problem)
			}
			gw.Spec.Routes = gw.Spec.Routes[:1]
			gw.Spec.Routes[0].CIDRs = []string{"203.0.113.0/24"}
			out, problem, err = r.reconcileRoutes(t.Context(), gw, vpc)
			if err != nil || problem != "" || len(out) != 1 || out[0].Port == "" {
				t.Fatalf("valid input did not recover: %+v %q %v", out, problem, err)
			}
		})
	}
}

func TestVPCRouteDiagnosticsAreBounded(t *testing.T) {
	r, gw, vpc := routeSecurityFixture(t)
	gw.Spec.Routes[0].CIDRs = make([]string, 4096)
	for i := range gw.Spec.Routes[0].CIDRs {
		gw.Spec.Routes[0].CIDRs[i] = "127.0.0.0/8"
	}
	out, problem, err := r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Port != "" || len(problem) > 4096 {
		t.Fatalf("unbounded diagnostics: rows=%d messageBytes=%d", len(out), len(problem))
	}
}

func largeRouteFixture(t testing.TB, allPortsSelected bool) (*VPCGatewayReconciler, *sdnv1alpha1.VPCGateway, *sdnv1alpha1.VPC) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := sdnv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/16")
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "router", UID: "current-pod", Labels: map[string]string{"app": "router"}}}
	objects := []client.Object{vpc, pod}
	for i := 0; i < 1500; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/250, i%250+1)
		podName := "unrelated"
		if i == 0 || allPortsSelected {
			podName = pod.Name
		}
		objects = append(objects, &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("v101.10-0-%d-%d", i/250, i%250+1), Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: vpc.Namespace, sdnv1alpha1.LabelVPC: vpc.Name, sdnv1alpha1.LabelPodUID: string(pod.UID)}}, Spec: sdnv1alpha1.PortSpec{IP: ip, PodNamespace: pod.Namespace, PodName: podName, VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}}})
	}
	r := &VPCGatewayReconciler{Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()}
	gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: vpc.Namespace, Name: "door"}}
	gw.Spec.Routes = make([]sdnv1alpha1.VPCGatewayRoute, 1024)
	for i := range gw.Spec.Routes {
		gw.Spec.Routes[i] = sdnv1alpha1.VPCGatewayRoute{CIDRs: []string{"203.0.113.0/24"}, Via: sdnv1alpha1.VPCGatewayVia{PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "router"}}}}
	}
	return r, gw, vpc
}

func TestVPCRouteWorkBudgetRejectsWithoutPartialStatusAndRecovers(t *testing.T) {
	r, gw, vpc := largeRouteFixture(t, true)
	counter := &routePodListCounter{Client: r.Client}
	r.Client = counter
	out, problem, err := r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || len(out) != 0 || problem == "" || counter.podLists == 0 || counter.podLists >= len(gw.Spec.Routes) {
		t.Fatalf("candidate expansion not stopped: rows=%d lists=%d problem=%q err=%v", len(out), counter.podLists, problem, err)
	}
	gw.Spec.Routes = gw.Spec.Routes[:1]
	out, problem, err = r.reconcileRoutes(t.Context(), gw, vpc)
	if err != nil || problem != "" || len(out) != 1 || out[0].Port == "" {
		t.Fatalf("budget recovery failed: %+v %q %v", out, problem, err)
	}
}

func TestVPCRouteResolutionCancellation(t *testing.T) {
	r, gw, vpc := routeSecurityFixture(t, "203.0.113.0/24")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out, _, err := r.reconcileRoutes(ctx, gw, vpc)
	if err != context.Canceled || len(out) != 0 {
		t.Fatalf("cancelled resolution continued: %+v %v", out, err)
	}
}

func BenchmarkVPCGatewayRouteResolution(b *testing.B) {
	r, gw, vpc := largeRouteFixture(b, false)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		out, problem, err := r.reconcileRoutes(b.Context(), gw, vpc)
		if err != nil || problem != "" || len(out) != 1024 {
			b.Fatalf("incomplete resolution rows=%d problem=%q err=%v", len(out), problem, err)
		}
	}
}
