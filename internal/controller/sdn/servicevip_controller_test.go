/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sdn

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// svcScheme registers the sdn types plus core/v1 (Service) and discovery/v1
// (EndpointSlice), which the ServiceVIP controller reads.
func svcScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("client-go scheme: %v", err)
	}
	if err := sdnv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("sdn scheme: %v", err)
	}
	_ = discoveryv1.AddToScheme(s)
	return s
}

func readyVPC(ns, name, cidr string, vni int32) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{cidr}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni, Phase: sdnv1alpha1.VPCPhaseReady},
	}
}

func binding(ns, vpcNS, vpc string) *sdnv1alpha1.VPCBinding {
	return &sdnv1alpha1.VPCBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "b-" + vpc},
		Spec:       sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpc}},
	}
}

func clusterIPService(ns, name, vpcAnno string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Annotations: map[string]string{sdnv1alpha1.AnnotationVPC: vpcAnno},
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "10.96.0.5",
			Ports:     []corev1.ServicePort{{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80}},
		},
	}
}

func svcClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(svcScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.ServiceVIP{}).
		Build()
}

func reconcileSVC(t *testing.T, c client.Client, ns, name string) {
	t.Helper()
	r := &ServiceVIPReconciler{Client: c}
	key := types.NamespacedName{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func vipsInVPC(t *testing.T, c client.Client, vpcNS, vpc string) []sdnv1alpha1.ServiceVIP {
	t.Helper()
	list := &sdnv1alpha1.ServiceVIPList{}
	if err := c.List(context.Background(), list); err != nil {
		t.Fatalf("list: %v", err)
	}
	var out []sdnv1alpha1.ServiceVIP
	for _, v := range list.Items {
		if v.Spec.VPCRef.Namespace == vpcNS && v.Spec.VPCRef.Name == vpc {
			out = append(out, v)
		}
	}
	return out
}

// An attached ClusterIP Service materializes a ServiceVIP with an address from
// the VPC's own space (allocated from the top of the CIDR down), carrying the
// service's ports.
func TestServiceVIPMaterializes(t *testing.T) {
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		binding("team-a", "team-a", "vpc-a"),
		clusterIPService("team-a", "db", "vpc-a"),
	)
	reconcileSVC(t, c, "team-a", "db")

	vips := vipsInVPC(t, c, "team-a", "vpc-a")
	if len(vips) != 1 {
		t.Fatalf("want 1 ServiceVIP, got %d", len(vips))
	}
	v := vips[0]
	if v.Spec.IP != "10.0.0.254" {
		t.Errorf("VIP = %q, want 10.0.0.254 (top-down allocation)", v.Spec.IP)
	}
	if len(v.Spec.Ports) != 1 || v.Spec.Ports[0].Port != 80 {
		t.Errorf("ports = %+v", v.Spec.Ports)
	}
}

// Without a VPCBinding in the Service's namespace the Service is not attached,
// so no VIP is materialized (the same default-deny gate pods pass).
func TestServiceVIPNeedsBinding(t *testing.T) {
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		clusterIPService("team-a", "db", "vpc-a"), // no binding
	)
	reconcileSVC(t, c, "team-a", "db")
	if vips := vipsInVPC(t, c, "team-a", "vpc-a"); len(vips) != 0 {
		t.Fatalf("want no VIP without a binding, got %d", len(vips))
	}
}

// The Port-always-wins repair: if a Port comes to hold a VIP's address, the
// VIP yields (is deleted) on its next reconcile and re-allocates a fresh one —
// a Port's IP is pinned workload identity, the VIP is the movable kind.
func TestServiceVIPYieldsToPort(t *testing.T) {
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		binding("team-a", "team-a", "vpc-a"),
		clusterIPService("team-a", "db", "vpc-a"),
	)
	reconcileSVC(t, c, "team-a", "db")
	first := vipsInVPC(t, c, "team-a", "vpc-a")
	if len(first) != 1 {
		t.Fatalf("want 1 VIP, got %d", len(first))
	}
	vip := first[0].Spec.IP

	// A Port now claims that exact address (the collision the repair guards).
	port := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name: "v101." + "conflict",
			Labels: map[string]string{
				sdnv1alpha1.LabelVPC:          "vpc-a",
				sdnv1alpha1.LabelVPCNamespace: "team-a",
			},
		},
		Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"}, IP: vip},
	}
	if err := c.Create(context.Background(), port); err != nil {
		t.Fatalf("create port: %v", err)
	}

	// Reconcile twice: once yields (deletes) the colliding VIP, the next
	// re-allocates a different address that the Port does not hold.
	reconcileSVC(t, c, "team-a", "db")
	reconcileSVC(t, c, "team-a", "db")

	after := vipsInVPC(t, c, "team-a", "vpc-a")
	if len(after) != 1 {
		t.Fatalf("want exactly 1 VIP after repair, got %d", len(after))
	}
	if after[0].Spec.IP == vip {
		t.Errorf("VIP still holds the Port's address %q; it must have yielded", vip)
	}
	if err := c.Get(context.Background(), types.NamespacedName{Name: port.Name}, &sdnv1alpha1.Port{}); apierrors.IsNotFound(err) {
		t.Errorf("the Port must survive — it wins the conflict")
	}
}

// SessionAffinity flows from the Service onto the ServiceVIP spec (the agent
// reads it to set the datapath affinity flag).
func TestServiceVIPCarriesAffinity(t *testing.T) {
	svc := clusterIPService("team-a", "db", "vpc-a")
	svc.Spec.SessionAffinity = corev1.ServiceAffinityClientIP
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		binding("team-a", "team-a", "vpc-a"),
		svc,
	)
	reconcileSVC(t, c, "team-a", "db")
	vips := vipsInVPC(t, c, "team-a", "vpc-a")
	if len(vips) != 1 || vips[0].Spec.SessionAffinity != "ClientIP" {
		t.Fatalf("affinity not propagated: %+v", vips)
	}
}
