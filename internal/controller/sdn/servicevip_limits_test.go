package sdn

import (
	"fmt"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestServiceVIPEndpointBudgetClearsStaleSetAndRecovers(t *testing.T) {
	svc := clusterIPService("tenant", "service", "net")
	vpc := readyVPC("tenant", "net", "10.0.0.0/24", 100)
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPC: "net", sdnv1alpha1.LabelVPCNamespace: "tenant", sdnv1alpha1.LabelPodUID: "pod-uid"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}, IP: "10.0.0.2", PodNamespace: "tenant", PodName: "backend"}}
	controller := true
	name, target := "http", int32(8080)
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "slice-0", Labels: map[string]string{discoveryv1.LabelServiceName: "service"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller}}}, Ports: []discoveryv1.EndpointPort{{Name: &name, Port: &target}}}
	for i := 0; i < 1000; i++ {
		slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant", Name: "backend", UID: "pod-uid"}})
	}
	c := svcClient(t, svc, vpc, port, slice, binding("tenant", "tenant", "net"))
	r := &ServiceVIPReconciler{Client: c}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(svc)}
	check := func(want int) {
		t.Helper()
		claims := vipsInVPC(t, c, "tenant", "net")
		if len(claims) != 1 || len(claims[0].Status.Backends) != want {
			t.Fatal("backend state", claims)
		}
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	check(1)
	var extra []*discoveryv1.EndpointSlice
	for i := 1; i < 66; i++ {
		copy := slice.DeepCopy()
		copy.Name = fmt.Sprintf("slice-%d", i)
		copy.ResourceVersion = ""
		if err := c.Create(t.Context(), copy); err != nil {
			t.Fatal(err)
		}
		extra = append(extra, copy)
	}
	if _, err := r.Reconcile(t.Context(), req); err == nil {
		t.Fatal("duplicate endpoint work exceeded budget without rejection")
	}
	check(0)
	for _, copy := range extra {
		if err := c.Delete(t.Context(), copy); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	check(1)
}
