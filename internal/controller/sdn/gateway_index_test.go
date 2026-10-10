package sdn

import (
	"fmt"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestGatewayReconcileCopiesOnlyCurrentVPCBoundaries(t *testing.T) {
	vpc := egressVPC("tenant-a", "net", 101, true)
	a := natGateway(vpc.Namespace, "a-door", vpc.Name)
	b := natGateway(vpc.Namespace, "b-door", vpc.Name)
	b.Spec.NAT.Enabled = false
	objects := []client.Object{vpc, a, b, natGateway("tenant-b", "foreign", vpc.Name)}
	for i := range 1400 {
		objects = append(objects, natGateway(vpc.Namespace, fmt.Sprintf("unrelated-%d", i), fmt.Sprintf("other-%d", i)))
	}
	c := &routeGatewayListCounter{Client: gwClient(t, objects...)}
	r := gatewayReconciler(c)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpc)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if c.read != 2 {
		t.Errorf("gateway reconciliation copied %d boundaries, want 2", c.read)
	}
	dep := &appsv1.Deployment{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(r.deployment(vpc)), dep); err != nil {
		t.Fatalf("oldest enabled boundary did not create deployment: %v", err)
	}
	if dep.Annotations[gatewayVPCUIDAnnotation] != string(vpc.UID) {
		t.Fatal("deployment lost current VPC ownership")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(a), a); err != nil {
		t.Fatal(err)
	}
	a.Spec.VPCRef.Name = "next"
	if err := c.Update(t.Context(), a); err != nil {
		t.Fatal(err)
	}
	c.read = 0
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if c.read != 1 {
		t.Fatalf("retarget retained old boundary: copied=%d", c.read)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(dep), &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("disabled successor did not withdraw deployment: %v", err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(b), b); err != nil {
		t.Fatal(err)
	}
	b.Spec.NAT.Enabled = true
	if err := c.Update(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(dep), &appsv1.Deployment{}); err != nil {
		t.Fatalf("enabled successor did not recover: %v", err)
	}
	if err := c.Delete(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	c.read = 0
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if c.read != 0 {
		t.Fatal("deleted boundary retained in index", c.read)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(dep), &appsv1.Deployment{}); !apierrors.IsNotFound(err) {
		t.Fatalf("deleted boundary did not withdraw deployment: %v", err)
	}
}
