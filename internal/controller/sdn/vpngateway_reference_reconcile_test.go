package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type vpnReferenceReader struct {
	client.Client
	invalidGets int
}

func (c *vpnReferenceReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if !vpnlimits.ObjectName(key.Name) {
		c.invalidGets++
		return fmt.Errorf("unusable reference reached client")
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestVPNLegacyReferenceRejectionDrainsAndRecovers(t *testing.T) {
	for _, kind := range []string{"VPC", "TLS", "WG-PSK", "claim"} {
		t.Run(kind, func(t *testing.T) {
			gw := &sdnv1alpha1.VPNGateway{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "gateway", UID: "gateway-current"}}
			gw.Spec.VPCRef.Name = "net"
			vpc := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
			key, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: gw.Namespace, Name: "peer"}, Spec: sdnv1alpha1.VPNConnectionSpec{GatewayRef: sdnv1alpha1.LocalVPNGatewayRef{Name: gw.Name}, WireGuard: &sdnv1alpha1.VPNConnectionWireGuard{PeerPublicKey: key.PublicKey().String()}, RemoteCIDRs: []string{"203.0.113.0/24"}}}
			c := &vpnReferenceReader{Client: vpnIndexClient(t, gw, vpc, peer)}
			r := &VPNGatewayReconciler{Client: c, Scheme: svcScheme(t), Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
			req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
				t.Fatal(err)
			}
			set := func(name string) client.Object {
				switch kind {
				case "VPC":
					gw.Spec.VPCRef.Name = name
				case "TLS":
					gw.Spec.IPsec = &sdnv1alpha1.VPNGatewayIPsec{CredentialSecretRef: name}
					if name == "" {
						gw.Spec.IPsec = nil
					}
				case "WG-PSK":
					peer.Spec.WireGuard.PresharedKeySecretRef = name
					return peer
				case "claim":
					gw.Spec.ExternalAddress.AddressClaimName = name
				}
				return gw
			}
			if err := c.Update(t.Context(), set(strings.Repeat("a", 128<<10))); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if c.invalidGets != 0 {
				t.Fatalf("invalid API lookups=%d", c.invalidGets)
			}
			if err := c.Get(t.Context(), req.NamespacedName, gw); err != nil {
				t.Fatal(err)
			}
			condition := meta.FindStatusCondition(gw.Status.Conditions, sdnv1alpha1.VPNGatewayConditionApplianceReady)
			if condition == nil || condition.Reason != "InputLimitExceeded" || len(condition.Message) > 1024 {
				t.Fatalf("rejection status not bounded: %+v", condition)
			}
			for _, obj := range []client.Object{&appsv1.Deployment{}, &sdnv1alpha1.VPCBinding{}} {
				if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name + "-vpn"}, obj); !apierrors.IsNotFound(err) {
					t.Fatalf("rejected input retains active %T: %v", obj, err)
				}
			}
			if kind == "WG-PSK" {
				if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
					t.Fatal(err)
				}
			}
			name := ""
			if kind == "VPC" {
				name = vpc.Name
			}
			if err := c.Update(t.Context(), set(name)); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKey{Namespace: gw.Namespace, Name: gw.Name + "-vpn"}, &appsv1.Deployment{}); err != nil {
				t.Fatalf("valid reference did not recover appliance: %v", err)
			}
		})
	}
}

func TestVPNSecretReadersRejectInvalidNamesBeforeClient(t *testing.T) {
	r := &VPNGatewayReconciler{} // A lookup would panic: no client is installed.
	for _, name := range []string{"", "bad/name", strings.Repeat("a", 128<<10)} {
		if _, err := r.readSecretValue(t.Context(), "tenant-a", name, "psk"); err == nil || len(err.Error()) > 1024 {
			t.Fatal("invalid Secret reference accepted or echoed")
		}
		if _, _, _, err := r.readTLSCredential(t.Context(), "tenant-a", name); err == nil || len(err.Error()) > 1024 {
			t.Fatal("invalid TLS Secret reference accepted or echoed")
		}
	}
}
