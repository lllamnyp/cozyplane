package sdn

import (
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"testing"
)

func TestTerminatingVPCDoesNotRecreateGateway(t *testing.T) {
	vpc := egressVPC("tenant-a", "net", 101, true)
	now := metav1.Now()
	vpc.DeletionTimestamp = &now
	vpc.Finalizers = []string{"example.invalid/cleanup"}
	c := gatewayClientBuilder(gatewayScheme(t)).WithObjects(vpc, natGateway(vpc.Namespace, "door", vpc.Name)).Build()
	r := gatewayReconciler(c)
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpc)}); err != nil {
		t.Fatal(err)
	}
	var deps appsv1.DeploymentList
	if err := c.List(t.Context(), &deps); err != nil {
		t.Fatal(err)
	}
	if len(deps.Items) != 0 {
		t.Fatal("gateway deployment created while VPC is deleting")
	}
}

func TestTerminatingVPCDoesNotRetainNATService(t *testing.T) {
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
	now := metav1.Now()
	vpc.DeletionTimestamp = &now
	vpc.Finalizers = []string{"example.invalid/cleanup"}
	c := gwClient(t, vpc, natGateway(vpc.Namespace, "door", vpc.Name))
	got := reconcileGateway(t, c, vpc.Namespace, "door")
	if len(allNATServices(t, c, vpc.Namespace, got.Name)) != 0 {
		t.Fatal("NAT service created for terminating VPC")
	}
}

func TestTerminatingVPCRetiresExistingGateway(t *testing.T) {
	vpc := egressVPC("tenant-a", "net", 101, true)
	vpc.Finalizers = []string{"example.invalid/cleanup"}
	c := gatewayClientBuilder(gatewayScheme(t)).WithObjects(vpc, natGateway(vpc.Namespace, "door", vpc.Name)).Build()
	r := gatewayReconciler(c)
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpc)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	var before appsv1.DeploymentList
	if err := c.List(t.Context(), &before); err != nil {
		t.Fatal(err)
	}
	if len(before.Items) != 1 {
		t.Fatalf("live VPC deployment count: %d", len(before.Items))
	}
	if err := c.Delete(t.Context(), vpc); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := r.Reconcile(t.Context(), req); err != nil {
			t.Fatal(err)
		}
		var after appsv1.DeploymentList
		if err := c.List(t.Context(), &after); err != nil {
			t.Fatal(err)
		}
		if len(after.Items) != 0 {
			t.Fatal("terminating VPC retains or recreates deployment")
		}
	}
}

func TestTerminatingVPCRetiresExistingNATService(t *testing.T) {
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
	vpc.Finalizers = []string{"example.invalid/cleanup"}
	c := gwClient(t, vpc, natGateway(vpc.Namespace, "door", vpc.Name))
	got := reconcileGateway(t, c, vpc.Namespace, "door")
	if len(allNATServices(t, c, vpc.Namespace, got.Name)) != 1 {
		t.Fatal("live VPC NAT Service missing")
	}
	if err := c.Delete(t.Context(), vpc); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		got = reconcileGateway(t, c, vpc.Namespace, "door")
		if len(allNATServices(t, c, vpc.Namespace, got.Name)) != 0 {
			t.Fatal("terminating VPC retains or recreates NAT Service")
		}
		if got.Status.NATAddress != "" || got.Status.NATAddress6 != "" || got.Status.AppliancePort != "" || len(got.Status.Routes) != 0 {
			t.Fatalf("terminating VPC retains gateway projection: %+v", got.Status)
		}
	}
}
