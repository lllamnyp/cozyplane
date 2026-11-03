package sdn

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestServiceVIPRejectsEndpointSliceFromPredecessor(t *testing.T) {
	svc := clusterIPService("tenant", "service", "net")
	svc.UID = "current-service"
	vpc := readyVPC("tenant", "net", "10.0.0.0/24", 100)
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPC: "net", sdnv1alpha1.LabelVPCNamespace: "tenant", sdnv1alpha1.LabelPodUID: "pod-uid"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}, IP: "10.0.0.2", PodNamespace: "tenant", PodName: "backend"}}
	controller := true
	for _, owner := range []types.UID{"old-service", "current-service", ""} {
		slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "slice", Labels: map[string]string{discoveryv1.LabelServiceName: "service"}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant", Name: "backend", UID: "pod-uid"}}}}
		if owner != "" {
			slice.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: owner, Controller: &controller}}
		}
		c := svcClient(t, []client.Object{svc, vpc, port, slice}...)
		r := &ServiceVIPReconciler{Client: c}
		backends, err := r.resolveBackends(t.Context(), svc, vpc)
		if err != nil {
			t.Fatal(err)
		}
		if (len(backends) == 1) != (owner == svc.UID) {
			t.Errorf("EndpointSlice owner %q resolved %d backends for current Service %q", owner, len(backends), svc.UID)
		}
	}
}

func TestServiceVIPBackendRequiresNetworkAndPodGeneration(t *testing.T) {
	svc := clusterIPService("tenant", "service", "net")
	vpc := readyVPC("tenant", "net", "10.0.0.0/24", 100)
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPC: "net", sdnv1alpha1.LabelVPCNamespace: "tenant", sdnv1alpha1.LabelPodUID: "pod-uid"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}, IP: "10.0.0.2", PodNamespace: "tenant", PodName: "backend"}}
	controller := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "slice", Labels: map[string]string{discoveryv1.LabelServiceName: "service"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller}}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant", Name: "backend", UID: "pod-uid"}}}}
	for _, mode := range []string{"current", "network recreated", "Pod UID absent"} {
		t.Run(mode, func(t *testing.T) {
			current, ep := vpc.DeepCopy(), slice.DeepCopy()
			if mode == "network recreated" {
				current.Status.VNI = 101
			}
			if mode == "Pod UID absent" {
				ep.Endpoints[0].TargetRef.UID = ""
			}
			c := svcClient(t, svc, current, port, ep)
			r := &ServiceVIPReconciler{Client: c}
			backends, err := r.resolveBackends(t.Context(), svc, current)
			if err != nil {
				t.Fatal(err)
			}
			if (len(backends) == 1) != (mode == "current") {
				t.Fatalf("mode %s admitted %d backends", mode, len(backends))
			}
		})
	}
}
