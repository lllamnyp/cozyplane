package sdn

import (
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVPCGatewayLegacyReferenceCleanupAndRecovery(t *testing.T) {
	gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	gw.Spec.NAT.Enabled = true
	vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	c := &vpnReferenceReader{Client: gwClient(t, gw, vpc)}
	r := &VPCGatewayReconciler{Client: c, Scheme: gatewayScheme(t)}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
	run := func() {
		t.Helper()
		if _, err := r.Reconcile(t.Context(), req); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(t.Context(), req.NamespacedName, gw); err != nil {
			t.Fatal(err)
		}
	}
	run()
	if len(allNATServices(t, c, gw.Namespace, gw.Name)) != 1 {
		t.Fatal("valid gateway did not create NAT identity service")
	}
	// A foreign Service with matching labels must survive cleanup.
	foreign := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "foreign", Labels: map[string]string{vpcGatewayLabel: gw.Name, addressFamilyLabel: "IPv4"}}}
	if err := c.Create(t.Context(), foreign); err != nil {
		t.Fatal(err)
	}
	gw.Spec.VPCRef.Name = strings.Repeat("a", 128<<10)
	if err := c.Update(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	run()
	condition := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPCGatewayConditionVPCResolved)
	if c.invalidGets != 0 || gw.Status.Phase != sdnv1alpha1.VPCGatewayPhasePending || condition == nil || condition.Status != metav1.ConditionFalse || len(condition.Message) > 1024 {
		t.Fatalf("invalid reference lookup/status: invalidGets=%d status=%+v", c.invalidGets, gw.Status)
	}
	services := allNATServices(t, c, gw.Namespace, gw.Name)
	if len(services) != 1 || services[0].Name != foreign.Name {
		t.Fatal("cleanup retained owned NAT service or deleted foreign service")
	}
	gw.Spec.VPCRef.Name = vpc.Name
	if err := c.Update(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	run()
	if gw.Status.Phase != sdnv1alpha1.VPCGatewayPhaseReady || len(allNATServices(t, c, gw.Namespace, gw.Name)) != 2 {
		t.Fatal("valid reference did not recover")
	}
}

func TestVPCGatewayReferenceCacheRemovalAndRecovery(t *testing.T) {
	large := strings.Repeat("a", 128<<10)
	gw := &sdnv1alpha1.VPCGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", ResourceVersion: "1"}}
	gw.Spec.VPCRef.Name = large
	list := &sdnv1alpha1.VPCGatewayList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.VPCGateway{*gw}}
	cached, index := vpnObjectCache(t, gw, list, gatewayVPCIndex, gatewayVPCKeys)
	lookup := func(name string, want int) {
		t.Helper()
		if err := cached.List(t.Context(), list, client.InNamespace(gw.Namespace), client.MatchingFields{gatewayVPCIndex: name}); err != nil {
			t.Fatal(err)
		}
		if len(list.Items) != want {
			t.Fatalf("index rows=%d want=%d", len(list.Items), want)
		}
	}
	lookup(large, 0)
	gw.Spec.VPCRef.Name = "net"
	if err := index.Update(gw.DeepCopyObject()); err != nil {
		t.Fatal(err)
	}
	lookup("net", 1)
	gw.Spec.VPCRef.Name = "bad/name"
	if err := index.Update(gw.DeepCopyObject()); err != nil {
		t.Fatal(err)
	}
	lookup("net", 0)
	lookup("bad/name", 0)
	gw.Spec.VPCRef.Name = "other-net"
	if err := index.Update(gw.DeepCopyObject()); err != nil {
		t.Fatal(err)
	}
	lookup("other-net", 1)
}
