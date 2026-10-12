package sdn

import (
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"
)

func TestHubProtectsEveryServedVPCWithoutStatusChurn(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "gateway", UID: "gateway-uid"}}
	gw.Spec.VPCRef.Name = "net-a"
	gw.Spec.AdditionalVPCRefs = []sdn.LocalVPCRef{{Name: "net-b"}}
	c := &vpnIntentClient{Client: vpnIndexClient(t, gw)}
	r := &VPNGatewayReconciler{Client: c}
	peers := []sdn.VPNConnection{{Spec: sdn.VPNConnectionSpec{RemoteCIDRs: []string{"203.0.113.0/24"}}}}
	if err := r.protectRouteIntent(t.Context(), gw, peers); err != nil {
		t.Fatal(err)
	}
	if len(gw.Status.Routes) != 2 {
		t.Fatalf("missing protected hub leg: %+v", gw.Status.Routes)
	}
	for i, name := range []string{"net-a", "net-b"} {
		route := gw.Status.Routes[i]
		if route.VPCRef.Name != name || route.Port != "" || len(route.CIDRs) != 1 {
			t.Fatalf("unsafe protected route: %+v", route)
		}
		gw.Status.Routes[i].Port = "active-leg"
	}
	for range 20 {
		if err := r.protectRouteIntent(t.Context(), gw, peers); err != nil {
			t.Fatal(err)
		}
	}
	if c.statusWrites != 1 || gw.Status.Routes[1].Port != "active-leg" {
		t.Fatal("unchanged hub intent erased active authority")
	}
	blocked, err := blackholeVPNRoutes(gw.Status.Routes)
	if err != nil || blocked[1].VPCRef.Name != "net-b" || blocked[1].Port != "" {
		t.Fatalf("revocation lost route ownership: %+v %v", blocked, err)
	}
	gw.Spec.AdditionalVPCRefs[0].Name = "net-c"
	if err := r.protectRouteIntent(t.Context(), gw, peers); err != nil {
		t.Fatal(err)
	}
	if c.statusWrites != 2 || gw.Status.Routes[1].VPCRef.Name != "net-c" || gw.Status.Routes[1].Port != "" {
		t.Fatal("retarget retained predecessor authority")
	}
}

func TestHubMissingLegProducesBlackholeInsteadOfPanic(t *testing.T) {
	peers := []sdn.VPNConnection{{Spec: sdn.VPNConnectionSpec{RemoteCIDRs: []string{"203.0.113.0/24"}}}}
	routes := connectionRoutes(peers, nil)
	if len(routes) != 1 || routes[0].Port != "" || len(routes[0].Ports) != 0 || len(routes[0].CIDRs) != 1 {
		t.Fatalf("missing leg erased intent: %+v", routes)
	}
}

func TestHubRejectsLegacyReferenceInputBeforeLookup(t *testing.T) {
	gw := &sdn.VPNGateway{}
	gw.Spec.VPCRef.Name = "net-a"
	gw.Spec.AdditionalVPCRefs = make([]sdn.LocalVPCRef, 10000)
	if vpnGatewayInputProblem(gw) == "" {
		t.Fatal("unbounded references accepted")
	}
	gw.Spec.AdditionalVPCRefs = []sdn.LocalVPCRef{{Name: "net-a"}}
	if vpnGatewayInputProblem(gw) == "" {
		t.Fatal("duplicate primary accepted")
	}
	gw.Spec.AdditionalVPCRefs[0].Name = "net-b"
	if problem := vpnGatewayInputProblem(gw); problem != "" {
		t.Fatal(problem)
	}
}
