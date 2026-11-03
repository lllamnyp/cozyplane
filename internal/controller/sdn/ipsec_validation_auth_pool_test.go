package sdn

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestIPsecLegacyAuthPoolMismatchRejectedBeforeSecretReads(t *testing.T) {
	for _, mode := range []string{"PSK with pool", "EAP without pool"} {
		t.Run(mode, func(t *testing.T) {
			r, gw, peers := ipsecProposalBudgetFixture(t)
			gw.Spec.IPsec.Proposals = nil
			last := peers[len(peers)-1].Spec.IPsec
			if mode == "PSK with pool" {
				last.AddressPool = "clients"
			} else {
				last.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "account", SecretRef: "credential"}}
			}
			raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}}}, peers, 1280)
			if err == nil || raw != nil || r.Client.(*wgBudgetClient).secretReads != 0 {
				t.Fatal("late invalid legacy auth/pool combination reached credential loading or configuration serialization")
			}
		})
	}
}

func TestIPsecLegacyAuthPoolMismatchDrainsAuthorizationAndStatus(t *testing.T) {
	for _, mode := range []string{"PSK with pool", "EAP without pool"} {
		t.Run(mode, func(t *testing.T) {
			gw, connection, vpc := wgSecurityFixture()
			gw.Spec.WireGuard, gw.Spec.IPsec = nil, &sdn.VPNGatewayIPsec{AddressPools: []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "198.18.0.0/24"}}}
			connection.Spec.WireGuard = nil
			connection.Spec.RemoteCIDRs = []string{"198.19.0.0/24"}
			connection.Spec.IPsec = &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", AddressPool: "clients", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "missing-credential"}}
			if mode == "EAP without pool" {
				connection.Spec.IPsec.AddressPool = ""
				connection.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "account", SecretRef: "missing-credential"}}
			}
			connection.Status.ClientConfig, connection.Status.Conditions = nil, nil
			setConnCondition(&connection.Status, sdn.VPNConnectionConditionEstablished, true, "TunnelEstablished", "tunnel established")
			scheme := gatewayScheme(t)
			binding := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "binding-current"}, Spec: sdn.VPCBindingSpec{AllowForwarding: true, ForwardingCIDRs: []string{"198.18.0.0/24"}}}
			if err := controllerutil.SetControllerReference(gw, binding, scheme); err != nil {
				t.Fatal(err)
			}
			c := &wgBudgetClient{Client: vpnIndexClient(t, gw, connection, vpc, binding)}
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err == nil {
				t.Fatal("legacy auth/pool mismatch did not reject configuration")
			}
			if c.secretReads != 0 {
				t.Fatal("invalid auth/pool combination reached referenced Secrets")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); !apierrors.IsNotFound(err) {
				t.Fatal("legacy rejection retained previous forwarding grant", err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
				t.Fatal(err)
			}
			if connection.Status.Phase == sdn.VPNConnectionPhaseEstablished || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionEstablished) {
				t.Fatal("legacy auth/pool rejection retained established status")
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
				t.Fatal(err)
			}
			if len(gw.Status.Routes) == 0 {
				t.Fatal("legacy rejection lost protected accepted prefix intent")
			}
			for _, route := range gw.Status.Routes {
				if route.Port != "" || len(route.Ports) != 0 {
					t.Fatal("legacy rejection retained a usable return route")
				}
			}
		})
	}
}
