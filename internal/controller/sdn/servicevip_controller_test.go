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

func reportedVIP(t *testing.T, c client.Client, ns, name string) (string, bool) {
	t.Helper()
	svc := &corev1.Service{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, svc); err != nil {
		t.Fatalf("get service: %v", err)
	}
	ip, ok := svc.Annotations[sdnv1alpha1.AnnotationVPCIP]
	return ip, ok
}

func editService(t *testing.T, c client.Client, ns, name string, edit func(*corev1.Service)) {
	t.Helper()
	svc := &corev1.Service{}
	if err := c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, svc); err != nil {
		t.Fatalf("get service: %v", err)
	}
	edit(svc)
	if err := c.Update(context.Background(), svc); err != nil {
		t.Fatalf("update service: %v", err)
	}
}

// The VIP is reported on the Service, and a forged value is overwritten.
func TestServiceVIPReportedOnService(t *testing.T) {
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		binding("team-a", "team-a", "vpc-a"),
		clusterIPService("team-a", "db", "vpc-a"),
	)
	reconcileSVC(t, c, "team-a", "db")
	if ip, _ := reportedVIP(t, c, "team-a", "db"); ip != "10.0.0.254" {
		t.Fatalf("reported %q, want the VIP 10.0.0.254", ip)
	}
	for _, forged := range []string{"10.0.0.9", ""} {
		editService(t, c, "team-a", "db", func(s *corev1.Service) { s.Annotations[sdnv1alpha1.AnnotationVPCIP] = forged })
		reconcileSVC(t, c, "team-a", "db")
		if ip, _ := reportedVIP(t, c, "team-a", "db"); ip != "10.0.0.254" {
			t.Errorf("after forging %q: reported %q, want 10.0.0.254", forged, ip)
		}
	}
}

// The report follows the VIP across a yield and a retarget.
func TestServiceVIPReportFollowsVIP(t *testing.T) {
	c := svcClient(t,
		readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
		readyVPC("team-a", "vpc-b", "10.1.0.0/24", 102),
		binding("team-a", "team-a", "vpc-a"),
		binding("team-a", "team-a", "vpc-b"),
		clusterIPService("team-a", "db", "vpc-a"),
	)
	reconcileSVC(t, c, "team-a", "db")
	port := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v101.conflict"},
		Spec:       sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"}, IP: "10.0.0.254"},
	}
	if err := c.Create(context.Background(), port); err != nil {
		t.Fatal(err)
	}
	reconcileSVC(t, c, "team-a", "db") // yields
	if ip, ok := reportedVIP(t, c, "team-a", "db"); ok {
		t.Errorf("reported %q while the Service has no VIP, want none", ip)
	}
	reconcileSVC(t, c, "team-a", "db") // reallocates
	if ip, _ := reportedVIP(t, c, "team-a", "db"); ip != "10.0.0.253" {
		t.Errorf("reported %q after the yield, want the new VIP 10.0.0.253", ip)
	}

	editService(t, c, "team-a", "db", func(s *corev1.Service) { s.Annotations[sdnv1alpha1.AnnotationVPC] = "vpc-b" })
	reconcileSVC(t, c, "team-a", "db")
	if ip, _ := reportedVIP(t, c, "team-a", "db"); ip != "10.1.0.254" {
		t.Errorf("reported %q after the retarget, want vpc-b's VIP 10.1.0.254", ip)
	}
}

// Detaching the Service reaps its VIP and removes the report.
func TestServiceVIPReportWithdrawnOnDetach(t *testing.T) {
	for name, detach := range map[string]func(c client.Client){
		"annotation removed": func(c client.Client) {
			editService(t, c, "team-a", "db", func(s *corev1.Service) { delete(s.Annotations, sdnv1alpha1.AnnotationVPC) })
		},
		"binding deleted": func(c client.Client) {
			if err := c.Delete(context.Background(), binding("team-a", "team-a", "vpc-a")); err != nil {
				t.Fatal(err)
			}
		},
		"made headless": func(c client.Client) {
			// clusterIP is immutable, so recreate the Service headless.
			svc := &corev1.Service{}
			if err := c.Get(context.Background(), types.NamespacedName{Namespace: "team-a", Name: "db"}, svc); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(context.Background(), svc); err != nil {
				t.Fatal(err)
			}
			headless := clusterIPService("team-a", "db", "vpc-a")
			headless.Spec.ClusterIP = corev1.ClusterIPNone
			headless.Annotations[sdnv1alpha1.AnnotationVPCIP] = svc.Annotations[sdnv1alpha1.AnnotationVPCIP]
			if err := c.Create(context.Background(), headless); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := svcClient(t,
				readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101),
				binding("team-a", "team-a", "vpc-a"),
				clusterIPService("team-a", "db", "vpc-a"),
			)
			reconcileSVC(t, c, "team-a", "db")
			if _, ok := reportedVIP(t, c, "team-a", "db"); !ok {
				t.Fatal("no report before the detach")
			}
			detach(c)
			reconcileSVC(t, c, "team-a", "db")
			if ip, ok := reportedVIP(t, c, "team-a", "db"); ok {
				t.Errorf("reported %q after the detach, want none", ip)
			}
			if vips := vipsInVPC(t, c, "team-a", "vpc-a"); len(vips) != 0 {
				t.Errorf("%d VIPs after the detach, want none", len(vips))
			}
		})
	}
}

// VPCBinding and VPC events enqueue the Services that name the VPC.
func TestServiceVIPWatchesBindingAndVPC(t *testing.T) {
	other := clusterIPService("team-b", "db", "team-a/vpc-a") // consumer namespace
	c := svcClient(t,
		clusterIPService("team-a", "db", "vpc-a"),
		clusterIPService("team-a", "web", "vpc-b"),
		other,
	)
	r := &ServiceVIPReconciler{Client: c}
	names := func(reqs []ctrl.Request) map[string]bool {
		out := map[string]bool{}
		for _, q := range reqs {
			out[q.String()] = true
		}
		return out
	}
	got := names(r.mapBinding(context.Background(), binding("team-b", "team-a", "vpc-a")))
	if len(got) != 1 || !got["team-b/db"] {
		t.Errorf("binding in team-b enqueued %v, want only team-b/db", got)
	}
	got = names(r.mapVPC(context.Background(), readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101)))
	if len(got) != 2 || !got["team-a/db"] || !got["team-b/db"] {
		t.Errorf("VPC team-a/vpc-a enqueued %v, want team-a/db and team-b/db", got)
	}

	// A binding created after its Service attaches it.
	c = svcClient(t, readyVPC("team-a", "vpc-a", "10.0.0.0/24", 101), clusterIPService("team-a", "db", "vpc-a"))
	reconcileSVC(t, c, "team-a", "db")
	if _, ok := reportedVIP(t, c, "team-a", "db"); ok {
		t.Fatal("reported a VIP without a binding")
	}
	b := binding("team-a", "team-a", "vpc-a")
	if err := c.Create(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	r = &ServiceVIPReconciler{Client: c}
	for _, q := range r.mapBinding(context.Background(), b) {
		if _, err := r.Reconcile(context.Background(), q); err != nil {
			t.Fatal(err)
		}
	}
	if ip, _ := reportedVIP(t, c, "team-a", "db"); ip != "10.0.0.254" {
		t.Errorf("after the binding arrived: reported %q, want 10.0.0.254", ip)
	}
}
