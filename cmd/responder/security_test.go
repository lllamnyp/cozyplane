package main

import (
	"fmt"
	"net"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/responder"
)

func addDNSVPC(t *testing.T, state *informerState, ref sdnv1alpha1.VPCRef, vni int32) {
	t.Helper()
	if state.vpcs == nil {
		state.vpcs = cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	}
	vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name, UID: types.UID("vpc-" + ref.Namespace + "-" + ref.Name)}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/8"}}, Status: sdnv1alpha1.VPCStatus{VNI: vni}}
	if err := state.vpcs.Add(vpc); err != nil {
		t.Fatal(err)
	}
}

func TestDNSRequiresLiveBinding(t *testing.T) {
	vpc := sdnv1alpha1.VPCRef{Namespace: "owner", Name: "network"}
	bindings := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	svcs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	fips := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{fabricIPIndex: func(any) ([]string, error) { return []string{"192.0.2.10"}, nil }})
	ports := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podUIDIndex: func(any) ([]string, error) { return []string{"pod-uid"}, nil }})
	state := &informerState{bindings: bindings, svcs: svcs, fips: fips, ports: ports}
	addDNSVPC(t, state, vpc, 100)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "headless", Annotations: map[string]string{sdnv1alpha1.AnnotationVPC: "owner/network"}}, Spec: corev1.ServiceSpec{ClusterIP: corev1.ClusterIPNone}}
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, "10.10.0.10")}, Spec: sdnv1alpha1.PortSpec{IP: "10.10.0.10", PodNamespace: "consumer", VPCRef: vpc}}
	fip := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "fabric"}, Spec: localv1alpha1.FabricIPSpec{Address: "192.0.2.10", PodUID: "pod-uid"}}
	for _, entry := range []struct {
		index cache.Indexer
		obj   any
	}{{svcs, svc}, {ports, port}, {fips, fip}} {
		if err := entry.index.Add(entry.obj); err != nil {
			t.Fatal(err)
		}
	}
	check := func(allowed bool) {
		t.Helper()
		if (state.Service("consumer", "headless") != nil) != allowed {
			t.Fatalf("headless service authorization: want allowed=%v", allowed)
		}
		if (state.PortByFabricIP("192.0.2.10") != nil) != allowed {
			t.Fatalf("query source authorization: want allowed=%v", allowed)
		}
	}
	check(false)
	binding := &sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "grant"}, Spec: sdnv1alpha1.VPCBindingSpec{VPCRef: vpc}}
	if err := bindings.Add(binding); err != nil {
		t.Fatal(err)
	}
	check(true)
	binding.DeletionTimestamp = new(metav1.Now())
	if err := bindings.Update(binding); err != nil {
		t.Fatal(err)
	}
	check(false)
}

func TestDNSEndpointViewBudgets(t *testing.T) {
	for _, mode := range []string{"retention", "duplicate scan"} {
		t.Run(mode, func(t *testing.T) {
			vpc := sdnv1alpha1.VPCRef{Namespace: "tenant", Name: "net"}
			eps := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{svcIndex: func(any) ([]string, error) { return []string{"tenant/service"}, nil }})
			ports := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podIndex: func(obj any) ([]string, error) {
				port := obj.(*sdnv1alpha1.Port)
				return []string{port.Spec.PodNamespace + "/" + port.Spec.PodName}, nil
			}})
			state := &informerState{eps: eps, ports: ports}
			addDNSVPC(t, state, vpc, 100)
			svcs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "service", UID: "service-uid"}}
			if err := svcs.Add(svc); err != nil {
				t.Fatal(err)
			}
			state.svcs = svcs
			controller := true
			total := responder.MaxEndpoints + 1
			if mode == "duplicate scan" {
				total = responder.MaxEndpointWork + 1
			}
			for i := 0; i < total; {
				slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: fmt.Sprintf("slice-%d", i), Labels: map[string]string{discoveryv1.LabelServiceName: "service"}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller}}}}
				for count := 0; count < 1000 && i < total; count++ {
					name := fmt.Sprintf("pod-%d", i)
					if mode == "duplicate scan" {
						name = "pod"
					}
					if mode == "retention" || i == 0 {
						address := net.IPv4(10, 0, byte((i+2)>>8), byte(i+2)).String()
						port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, address), Labels: map[string]string{sdnv1alpha1.LabelPodUID: name}}, Spec: sdnv1alpha1.PortSpec{VPCRef: vpc, PodNamespace: "tenant", PodName: name, IP: address}}
						if err := ports.Add(port); err != nil {
							t.Fatal(err)
						}
					}
					slice.Endpoints = append(slice.Endpoints, discoveryv1.Endpoint{TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "tenant", Name: name, UID: types.UID(name)}})
					i++
				}
				if err := eps.Add(slice); err != nil {
					t.Fatal(err)
				}
			}
			if endpoints, err := state.Endpoints("tenant", "service", vpc); err == nil || len(endpoints) != 0 {
				t.Fatalf("partial or oversized view returned: endpoints=%d err=%v", len(endpoints), err)
			}
		})
	}
}

func TestDNSEndpointRejectsReusedPodNameAndWrongVPC(t *testing.T) {
	vpc := sdnv1alpha1.VPCRef{Namespace: "owner", Name: "network"}
	eps := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{svcIndex: func(any) ([]string, error) { return []string{"consumer/service"}, nil }})
	ports := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podIndex: func(any) ([]string, error) { return []string{"consumer/backend"}, nil }})
	state := &informerState{eps: eps, ports: ports}
	addDNSVPC(t, state, vpc, 100)
	svcs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "service", UID: "service-uid"}}
	if err := svcs.Add(svc); err != nil {
		t.Fatal(err)
	}
	state.svcs = svcs
	controller := true
	slice := &discoveryv1.EndpointSlice{ObjectMeta: metav1.ObjectMeta{Namespace: "consumer", Name: "slice", Labels: map[string]string{discoveryv1.LabelServiceName: svc.Name}, OwnerReferences: []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: svc.Name, UID: svc.UID, Controller: &controller}}}, Endpoints: []discoveryv1.Endpoint{{TargetRef: &corev1.ObjectReference{Namespace: "consumer", Name: "backend", Kind: "Pod", UID: "old-pod"}}}}
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(100, "10.10.0.10"), Labels: map[string]string{sdnv1alpha1.LabelPodUID: "new-pod"}}, Spec: sdnv1alpha1.PortSpec{VPCRef: vpc, IP: "10.10.0.10", PodNamespace: "consumer", PodName: "backend"}}
	if err := eps.Add(slice); err != nil {
		t.Fatal(err)
	}
	if err := ports.Add(port); err != nil {
		t.Fatal(err)
	}
	if got, err := state.Endpoints("consumer", "service", vpc); err != nil || len(got) != 0 {
		t.Fatal("stale endpoint resolved to recreated pod")
	}
	port.Labels[sdnv1alpha1.LabelPodUID] = "old-pod"
	if err := ports.Update(port); err != nil {
		t.Fatal(err)
	}
	if got, err := state.Endpoints("consumer", "service", vpc); err != nil || len(got) != 1 {
		t.Fatal("valid endpoint rejected")
	}
	svc.UID = "replacement-service"
	if err := svcs.Update(svc); err != nil {
		t.Fatal(err)
	}
	if got, err := state.Endpoints("consumer", "service", vpc); err != nil || len(got) != 0 {
		t.Fatal("EndpointSlice of predecessor Service admitted", err)
	}
	slice.OwnerReferences[0].UID = svc.UID
	if err := eps.Update(slice); err != nil {
		t.Fatal(err)
	}
	if got, err := state.Endpoints("consumer", "service", vpc); err != nil || len(got) != 1 {
		t.Fatal("current Service slice did not recover", err)
	}
	port.Spec.VPCRef.Name = "other-network"
	if err := ports.Update(port); err != nil {
		t.Fatal(err)
	}
	if got, err := state.Endpoints("consumer", "service", vpc); err != nil || len(got) != 0 {
		t.Fatal("foreign VPC endpoint admitted")
	}
}

func TestDNSUsesSandboxPrimaryAttachment(t *testing.T) {
	bindings := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc})
	fips := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{fabricIPIndex: func(obj any) ([]string, error) { return []string{obj.(*localv1alpha1.FabricIP).Spec.Address}, nil }})
	ports := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{podUIDIndex: func(obj any) ([]string, error) {
		return []string{obj.(*sdnv1alpha1.Port).Labels[sdnv1alpha1.LabelPodUID]}, nil
	}})
	state := &informerState{bindings: bindings, fips: fips, ports: ports}
	for i, network := range []string{"primary", "secondary"} {
		addDNSVPC(t, state, sdnv1alpha1.VPCRef{Namespace: "tenant", Name: network}, int32(100+i))
		if err := bindings.Add(&sdnv1alpha1.VPCBinding{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: network}, Spec: sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: network}}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"old", "current"} {
		for _, network := range []string{"primary", "secondary"} {
			primary := "false"
			if network == "primary" {
				primary = "true"
			}
			vni, address := int32(100), "10.0.0.10"
			if network == "secondary" {
				vni = 101
			}
			if id == "current" {
				address = "10.0.0.11"
			}
			port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: sdn.PortName(vni, address), Labels: map[string]string{sdnv1alpha1.LabelPodUID: "uid"}, Annotations: map[string]string{sdnv1alpha1.AnnotationContainerID: id, sdnv1alpha1.AnnotationCNIIfName: "eth0", sdnv1alpha1.AnnotationCNIPrimary: primary}}, Spec: sdnv1alpha1.PortSpec{IP: address, PodNamespace: "tenant", VPCRef: sdnv1alpha1.VPCRef{Namespace: "tenant", Name: network}}}
			if err := ports.Add(port); err != nil {
				t.Fatal(err)
			}
		}
	}
	claim := &localv1alpha1.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: "fabric"}, Spec: localv1alpha1.FabricIPSpec{Address: "192.0.2.10", PodUID: "uid", ContainerID: "current", IfName: "eth0"}}
	if err := fips.Add(claim); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		port := state.PortByFabricIP(claim.Spec.Address)
		if port == nil || port.Name != sdn.PortName(100, "10.0.0.11") {
			t.Fatal("DNS selected another sandbox or secondary VPC", port)
		}
	}
	claim.Spec.ContainerID = ""
	if err := fips.Update(claim); err != nil {
		t.Fatal(err)
	}
	if state.PortByFabricIP(claim.Spec.Address) != nil {
		t.Fatal("ambiguous legacy claim was assigned a tenant view")
	}
}

func TestDNSPeeringRevocationIgnoresStaleReadyStatus(t *testing.T) {
	vpcs := cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)
	peerings := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{localVPCIndex: func(obj any) ([]string, error) {
		p := obj.(*sdnv1alpha1.VPCPeering)
		return []string{p.Namespace + "/" + p.Spec.VPCRef.Name}, nil
	}, peeringPairIndex: peeringPairIndexFunc})
	state := &informerState{vpcs: vpcs, peerings: peerings}
	local := sdnv1alpha1.VPCRef{Namespace: "tenant-a", Name: "net"}
	remote := sdnv1alpha1.VPCRef{Namespace: "tenant-b", Name: "net"}
	for i, ref := range []sdnv1alpha1.VPCRef{local, remote} {
		cidr := "10.1.0.0/24"
		if i == 1 {
			cidr = "10.2.0.0/24"
		}
		if err := vpcs.Add(&sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name}, Spec: sdnv1alpha1.VPCSpec{CIDRs: []string{cidr}}, Status: sdnv1alpha1.VPCStatus{VNI: int32(100 + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	first := &sdnv1alpha1.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: local.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPCPeeringSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: local.Name}, PeerRef: remote}, Status: sdnv1alpha1.VPCPeeringStatus{Phase: sdnv1alpha1.VPCPeeringPhaseReady}}
	second := &sdnv1alpha1.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: remote.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPCPeeringSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: remote.Name}, PeerRef: local}}
	if err := peerings.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := peerings.Add(second); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers(local)) != 1 {
		t.Fatal("live peering rejected")
	}
	second.DeletionTimestamp = new(metav1.Now())
	if err := peerings.Update(second); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers(local)) != 0 {
		t.Fatal("terminating reciprocal still permits DNS")
	}
	if err := peerings.Delete(second); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers(local)) != 0 {
		t.Fatal("missing reciprocal still permits DNS")
	}
}
