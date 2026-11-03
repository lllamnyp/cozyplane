package sdn

import (
	"fmt"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func serviceVIPCandidateCache(tb testing.TB, unrelated int) (*ServiceVIPReconciler, *corev1.Service, *sdnv1alpha1.VPC, *vpnCachedPortClient) {
	tb.Helper()
	vpn, _, vpc, c := vpnApplianceIndexFixture(tb, unrelated, true)
	vpc.UID = "vpc-current"
	if err := c.cache.IndexField(tb.Context(), &sdnv1alpha1.Port{}, serviceVIPPodIndex, vpnAppliancePodKeys); err != nil {
		tb.Fatal(err)
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: vpc.Namespace, Name: "service", UID: "service-current"}, Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{{Name: "http", Port: 80, Protocol: corev1.ProtocolTCP}}}}
	name, target := "http", int32(8080)
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: svc.Namespace, Name: "slice", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(svc, corev1.SchemeGroupVersion.WithKind("Service"))}}, Ports: []discoveryv1.EndpointPort{{Name: &name, Port: &target}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: svc.Namespace, Name: "appliance", UID: "pod-current"}}}}
	c.Client = fake.NewClientBuilder().WithScheme(vpn.Scheme).WithObjects(svc, slice).Build()
	return &ServiceVIPReconciler{Client: c}, svc, vpc, c
}

func TestServiceVIPCandidateLookupCopiesOnlyReferencedClaims(t *testing.T) {
	r, svc, vpc, c := serviceVIPCandidateCache(t, 4000)
	backends, err := r.resolveBackends(t.Context(), svc, vpc)
	if err != nil || len(backends) != 1 || backends[0].IP != "10.0.0.2" {
		t.Fatal(backends, err)
	}
	if c.copied != 1 || c.calls != 1 {
		t.Fatalf("one backend copied %d Ports in %d lists; want its one candidate", c.copied, c.calls)
	}
}

func TestServiceVIPNoEndpointsDoesNotCopyPorts(t *testing.T) {
	r, svc, vpc, c := serviceVIPCandidateCache(t, 4000)
	var slices discoveryv1.EndpointSliceList
	if err := c.Client.List(t.Context(), &slices); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(t.Context(), &slices.Items[0]); err != nil {
		t.Fatal(err)
	}
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err != nil || len(backends) != 0 {
		t.Fatal(backends, err)
	}
	if c.copied != 0 || c.calls != 0 {
		t.Fatalf("no endpoint copied %d Ports in %d lists", c.copied, c.calls)
	}
}

func TestServiceVIPCandidateIndexRetargetDeleteAndFailure(t *testing.T) {
	r, svc, vpc, c := serviceVIPCandidateCache(t, 100)
	port := &sdnv1alpha1.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, port); err != nil {
		t.Fatal(err)
	}
	check := func(want int) {
		t.Helper()
		c.calls, c.copied = 0, 0
		backends, err := r.resolveBackends(t.Context(), svc, vpc)
		if err != nil || len(backends) != want || c.copied != want {
			t.Fatalf("backends=%v copied=%d err=%v", backends, c.copied, err)
		}
	}
	for _, change := range []func(*sdnv1alpha1.Port){
		func(p *sdnv1alpha1.Port) { p.Spec.PodName = "other-pod" },
		func(p *sdnv1alpha1.Port) { p.Spec.PodNamespace = "other-tenant" },
		func(p *sdnv1alpha1.Port) { p.Labels[sdnv1alpha1.LabelPodUID] = "old-pod" },
	} {
		other := port.DeepCopy()
		change(other)
		if err := c.index.Update(other); err != nil {
			t.Fatal(err)
		}
		check(0)
		if err := c.index.Update(port.DeepCopy()); err != nil {
			t.Fatal(err)
		}
		check(1)
	}
	if err := c.index.Delete(port); err != nil {
		t.Fatal(err)
	}
	check(0)
	if err := c.index.Add(port); err != nil {
		t.Fatal(err)
	}
	check(1)
	if err := c.cache.RemoveInformer(t.Context(), &sdnv1alpha1.Port{}); err != nil {
		t.Fatal(err)
	}
	c.calls, c.copied = 0, 0
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err == nil || len(backends) != 0 || c.copied != 0 {
		t.Fatal("missing index admitted a partial view or scanned unrelated claims", backends, err)
	}
}

func TestServiceVIPRepeatedEndpointsReuseCandidates(t *testing.T) {
	r, svc, vpc, c := serviceVIPCandidateCache(t, 100)
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: svc.Namespace, Name: "slice"}, slice); err != nil {
		t.Fatal(err)
	}
	endpoint := slice.Endpoints[0]
	for range 999 {
		slice.Endpoints = append(slice.Endpoints, endpoint)
	}
	if err := c.Update(t.Context(), slice); err != nil {
		t.Fatal(err)
	}
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err != nil || len(backends) != 1 || c.calls != 1 || c.copied != 1 {
		t.Fatal("duplicate endpoints repeated cache work", backends, c.calls, c.copied, err)
	}
}

func TestServiceVIPCandidateOverflowRejectsPartialView(t *testing.T) {
	r, svc, vpc, c := serviceVIPCandidateCache(t, 0)
	port := &sdnv1alpha1.Port{}
	if err := c.cache.Get(t.Context(), client.ObjectKey{Name: "v101.10-0-0-2"}, port); err != nil {
		t.Fatal(err)
	}
	for i := range 600 {
		other := port.DeepCopy()
		other.Spec.IP = fmt.Sprintf("10.0.%d.%d", 240+i/256, i%256)
		other.Name = fmt.Sprintf("v101.10-0-%d-%d", 240+i/256, i%256)
		if err := c.index.Add(other); err != nil {
			t.Fatal(err)
		}
	}
	slice := &discoveryv1.EndpointSlice{}
	if err := c.Get(t.Context(), client.ObjectKey{Namespace: svc.Namespace, Name: "slice"}, slice); err != nil {
		t.Fatal(err)
	}
	endpoint := slice.Endpoints[0]
	for range 999 {
		slice.Endpoints = append(slice.Endpoints, endpoint)
	}
	for i := range 65 {
		other := slice.DeepCopy()
		other.Name, other.ResourceVersion = fmt.Sprintf("large-slice-%d", i), ""
		if err := c.Create(t.Context(), other); err != nil {
			t.Fatal(err)
		}
	}
	if backends, err := r.resolveBackends(t.Context(), svc, vpc); err == nil || len(backends) != 0 {
		t.Fatal("candidate overflow admitted partial view", backends, err)
	}
	if c.calls != 1 || c.copied == 0 || c.copied >= 601 {
		t.Fatal("query did not limit copies before rejecting overflow", c.calls, c.copied)
	}
}

// Each unrelated claim carries a valid 64 KiB annotation. Setup is excluded
// from the benchmark: 4,000 such objects represent over 250 MiB of API data.
func BenchmarkServiceVIPCandidateCacheLargeData(b *testing.B) {
	r, svc, vpc, c := serviceVIPCandidateCache(b, 4000)
	for _, obj := range c.index.List() {
		port := obj.(*sdnv1alpha1.Port).DeepCopy()
		if port.Spec.PodName != "appliance" {
			port.Annotations = map[string]string{"example.invalid/payload": fmt.Sprintf("%s:%s", port.Name, strings.Repeat("x", 64<<10))}
			if err := c.index.Update(port); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if backends, err := r.resolveBackends(b.Context(), svc, vpc); err != nil || len(backends) != 1 {
			b.Fatal(backends, err)
		}
	}
}
