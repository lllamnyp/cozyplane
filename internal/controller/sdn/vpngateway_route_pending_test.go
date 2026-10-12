package sdn

import (
	"fmt"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestVPNPendingApplianceRetainsProtectedPrefixes(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"203.0.113.0/24", "2001:db8:20::/64"},
		WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PeerPublicKey: key.PublicKey().String()},
	}}
	c := vpnIndexClient(t, gw, vpc, peer)
	r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	if gw.Status.Phase != sdnv1alpha1.VPNGatewayPhasePending || gw.Status.AppliancePort != "" ||
		len(gw.Status.Routes) != 1 || len(gw.Status.Routes[0].CIDRs) != 2 ||
		gw.Status.Routes[0].Port != "" || len(gw.Status.Routes[0].Ports) != 0 {
		t.Fatalf("pending appliance erased protected prefixes or authorized a leg: %+v", gw.Status)
	}
	// Intent withdrawal deliberately removes the blackhole on reconciliation.
	if err := c.Delete(t.Context(), peer); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	if len(gw.Status.Routes) != 0 {
		t.Fatal("withdrawn peer retained its protected prefixes")
	}
}

func TestVPNRejectedPrefixRetentionIsBoundedAndIndependent(t *testing.T) {
	for _, routes := range [][]sdnv1alpha1.VPCGatewayRouteStatus{
		make([]sdnv1alpha1.VPCGatewayRouteStatus, 4097),
		{{CIDRs: make([]string, 4097)}},
		{{CIDRs: []string{strings.Repeat("x", 65)}}},
	} {
		if got, err := blackholeVPNRoutes(routes); err == nil || got != nil {
			t.Fatal("oversized retained state copied or accepted")
		}
	}
	old := []sdnv1alpha1.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}, Port: "old-port", Ports: []string{"old-port"}}}
	got, err := blackholeVPNRoutes(old)
	if err != nil || len(got) != 1 || got[0].Port != "" || len(got[0].Ports) != 0 {
		t.Fatalf("old authorization retained: %+v err=%v", got, err)
	}
	got[0].CIDRs[0] = "192.0.2.0/24"
	if old[0].CIDRs[0] != "203.0.113.0/24" || old[0].Port != "old-port" {
		t.Fatal("retention mutated source status")
	}
}

func TestVPNQuotaRejectionRetainsPreviouslyProtectedPrefixes(t *testing.T) {
	gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{
		GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"203.0.113.0/24"},
		WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PeerPublicKey: key.PublicKey().String()},
	}}
	c := vpnIndexClient(t, gw, vpc, peer)
	r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	if len(gw.Status.Routes) != 1 {
		t.Fatal("initial protected prefix missing")
	}
	for i := 1; i < 17; i++ {
		extra := peer.DeepCopy()
		extra.Name = fmt.Sprintf("peer-%d", i)
		extra.ResourceVersion = ""
		if err := c.Create(t.Context(), extra); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	if len(gw.Status.Routes) != 1 || len(gw.Status.Routes[0].CIDRs) != 1 || gw.Status.Routes[0].CIDRs[0] != "203.0.113.0/24" || gw.Status.Routes[0].Port != "" || len(gw.Status.Routes[0].Ports) != 0 {
		t.Fatalf("quota rejection erased protected prefix: %+v", gw.Status)
	}
}
