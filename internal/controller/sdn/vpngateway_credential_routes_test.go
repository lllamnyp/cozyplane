package sdn

import (
	"context"
	"errors"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpnIntentClient struct {
	client.Client
	statusError           error
	statusWrites, creates int
}

func (c *vpnIntentClient) Status() client.SubResourceWriter {
	return &vpnIntentWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

func (c *vpnIntentClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	c.creates++
	return c.Client.Create(ctx, obj, opts...)
}

type vpnIntentWriter struct {
	client.SubResourceWriter
	parent *vpnIntentClient
}

func (w *vpnIntentWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	w.parent.statusWrites++
	if w.parent.statusError != nil {
		return w.parent.statusError
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestVPNIntentPublicationConflictStopsRealization(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	peer := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"203.0.113.0/24"}}}
	vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	want := apierrors.NewConflict(schema.GroupResource{Group: sdn.GroupName, Resource: "vpngateways"}, gw.Name, errors.New("snapshot changed"))
	c := &vpnIntentClient{Client: vpnIndexClient(t, gw, vpc, peer), statusError: want}
	r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); !apierrors.IsConflict(err) {
		t.Fatalf("publication conflict ignored: %v", err)
	}
	if c.creates != 0 || c.statusWrites != 1 {
		t.Fatalf("failed prefix publication realized resources: creates=%d status=%d", c.creates, c.statusWrites)
	}
}

func TestVPNUnchangedIntentDoesNotCycleStatusOrAuthority(t *testing.T) {
	gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
	gw.Spec.VPCRef.Name = "net"
	gw.Status = sdn.VPNGatewayStatus{Phase: sdn.VPNGatewayPhaseReady, Address: "198.51.100.20", AppliancePort: "current-leg", Routes: []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"203.0.113.0/24"}, Port: "current-leg", Ports: []string{"current-leg"}}}}
	c := &vpnIntentClient{Client: vpnIndexClient(t, gw)}
	r := &VPNGatewayReconciler{Client: c}
	peers := []sdn.VPNConnection{{Spec: sdn.VPNConnectionSpec{RemoteCIDRs: []string{"203.0.113.0/24"}}}}
	for i := 0; i < 100; i++ {
		if err := r.protectRouteIntent(t.Context(), gw, peers); err != nil {
			t.Fatal(err)
		}
	}
	if c.statusWrites != 0 || gw.Status.Phase != sdn.VPNGatewayPhaseReady || gw.Status.AppliancePort != "current-leg" || gw.Status.Routes[0].Port != "current-leg" {
		t.Fatal("unchanged intent cycled readiness or next-hop authority")
	}
}

func TestVPNCredentialFailureProtectsNewAcceptedPrefixes(t *testing.T) {
	for _, backend := range []string{backendWireGuard, backendIPsec} {
		for _, previous := range []bool{false, true} {
			t.Run(backend+"/previous="+map[bool]string{true: "true", false: "false"}[previous], func(t *testing.T) {
				gw := &sdn.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
				gw.Spec.VPCRef.Name = "net"
				if previous {
					gw.Status.Routes = []sdn.VPCGatewayRouteStatus{{CIDRs: []string{"192.0.2.0/24"}, Port: "old-leg", Ports: []string{"old-leg"}}}
				}
				vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
				key, err := wgtypes.GeneratePrivateKey()
				if err != nil {
					t.Fatal(err)
				}
				peer := &sdn.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: gw.Name}, RemoteCIDRs: []string{"203.0.113.0/24", "2001:db8:20::/64"}}}
				if backend == backendWireGuard {
					peer.Spec.WireGuard = &sdn.VPNConnectionWireGuard{PeerPublicKey: key.PublicKey().String(), PresharedKeySecretRef: "missing-credential"}
				} else {
					gw.Spec.IPsec = &sdn.VPNGatewayIPsec{}
					peer.Spec.IPsec = &sdn.VPNConnectionIPsec{PeerAddress: "198.51.100.10", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "missing-credential"}}
				}
				c := vpnIndexClient(t, gw, vpc, peer)
				r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
				req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
				if _, err := r.Reconcile(t.Context(), req); err == nil {
					t.Fatal("missing credential did not preserve retry error")
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
					t.Fatal(err)
				}
				assertProtected := func() {
					t.Helper()
					if len(gw.Status.Routes) != 1 || len(gw.Status.Routes[0].CIDRs) != 2 || gw.Status.Routes[0].CIDRs[0] != "203.0.113.0/24" || gw.Status.Routes[0].CIDRs[1] != "2001:db8:20::/64" || gw.Status.Routes[0].Port != "" || len(gw.Status.Routes[0].Ports) != 0 {
						t.Fatalf("credential failure erased new intent or retained authority: %+v", gw.Status.Routes)
					}
				}
				assertProtected()
				secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "missing-credential"}, Data: map[string][]byte{"psk": []byte(key.String())}}
				if err := c.Create(t.Context(), secret); err != nil {
					t.Fatal(err)
				}
				if _, err := r.Reconcile(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
					t.Fatal(err)
				}
				assertProtected()
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
					t.Fatal("withdrawn peer intent remained blocked")
				}
			})
		}
	}
}
