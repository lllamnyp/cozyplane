package main

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestDNSPortRequiresCurrentNetworkGeneration(t *testing.T) {
	ref := sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}
	state := &informerState{
		vpcs: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil), svcs: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil), bindings: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}),
		ports: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podUIDIndex: func(any) ([]string, error) { return []string{"pod-uid"}, nil }, podIndex: func(any) ([]string, error) { return []string{"tenant/backend"}, nil }}),
		fips:  cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{fabricIPIndex: func(any) ([]string, error) { return []string{"192.0.2.10"}, nil }}),
		eps:   cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{svcIndex: func(any) ([]string, error) { return []string{"tenant/service"}, nil }}),
	}
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net", UID: "vpc-uid"}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}, Status: sdnv1alpha1.VPCStatus{VNI: 100}}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "service", UID: "service-uid"}}
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelPodUID: "pod-uid"}, Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: "sandbox", sdnv1alpha1.AnnotationCNIIfName: "eth0", sdnv1alpha1.AnnotationCNIPrimary: "true"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: ref, IP: "10.0.0.2", PodNamespace: "tenant", PodName: "backend"}}
	claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "fabric"}, Spec: localv1alpha1.FabricIPSpec{Address: "192.0.2.10", PodUID: "pod-uid", ContainerID: "sandbox", IfName: "eth0"}}
	binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "grant"}, Spec: sdnv1alpha1.VPCBindingSpec{VPCRef: ref}}
	controller := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "slice", Labels: map[string]string{discoveryv1.LabelServiceName: "service"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller}}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant", Name: "backend", UID: "pod-uid"}}}}
	for _, entry := range []struct {
		store  cache.Indexer
		object any
	}{{state.vpcs, vpc}, {state.svcs, svc}, {state.ports, port}, {state.fips, claim}, {state.bindings, binding}, {state.eps, slice}} {
		if err := entry.store.Add(entry.object); err != nil {
			t.Fatal(err)
		}
	}
	if state.PortByFabricIP(claim.Spec.Address) == nil {
		t.Fatal("current query source rejected")
	}
	if got, err := state.Endpoints("tenant", "service", ref); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	vpc = vpc.DeepCopy()
	vpc.UID = "replacement-vpc"
	vpc.Status.VNI = 101
	_ = state.vpcs.Update(vpc)
	if state.PortByFabricIP(claim.Spec.Address) != nil {
		t.Error("old query-source Port adopted into recreated VPC")
	}
	if got, err := state.Endpoints("tenant", "service", ref); err != nil || len(got) != 0 {
		t.Error("old backend Port adopted into recreated VPC", got, err)
	}
	vpc.Status.VNI = 100
	vpc.UID = "vpc-uid"
	_ = state.vpcs.Update(vpc)
	slice = slice.DeepCopy()
	slice.Endpoints[0].TargetRef.UID = ""
	_ = state.eps.Update(slice)
	if got, err := state.Endpoints("tenant", "service", ref); err != nil || len(got) != 0 {
		t.Error("Pod name without UID selected a backend", got, err)
	}
}
