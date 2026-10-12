package sdn

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestIPsecRejectedModeAndBackendEditsDrainPreviousAuthorization(t *testing.T) {
	for _, mode := range []string{"active-active pools", "gateway backend changed"} {
		t.Run(mode, func(t *testing.T) {
			gw, connection, _ := wgSecurityFixture()
			connection.Spec.WireGuard, connection.Spec.IPsec = nil, &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}}
			connection.Status.ClientConfig, connection.Status.Conditions = nil, nil
			setConnCondition(&connection.Status, sdn.VPNConnectionConditionEstablished, true, "TunnelEstablished", "tunnel established")
			gw.Spec.WireGuard, gw.Spec.IPsec = nil, &sdn.VPNGatewayIPsec{CredentialSecretRef: "tls", AddressPools: []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "198.18.0.0/24"}}}
			gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{"192.0.2.1"}}}
			if mode == "gateway backend changed" {
				gw.Spec.IPsec, gw.Spec.WireGuard, gw.Spec.HA = nil, &sdn.VPNGatewayWireGuard{}, nil
				gw.Spec.ExternalAddress.AddressClaimName = "invalid/reference"
			}
			scheme := gatewayScheme(t)
			binding := &sdn.VPCBinding{ObjectMeta: metav1.ObjectMeta{Name: gw.Name + "-vpn", Namespace: gw.Namespace, UID: "binding-current"}, Spec: sdn.VPCBindingSpec{AllowForwarding: true, ForwardingCIDRs: []string{"198.18.0.0/24"}}}
			if err := controllerutil.SetControllerReference(gw, binding, scheme); err != nil {
				t.Fatal(err)
			}
			c := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPNGateway{}, &sdn.VPNConnection{}).WithObjects(gw, connection, binding).Build()
			r := &VPNGatewayReconciler{Client: c, Scheme: scheme, Config: VPNGatewayConfig{Image: "example.invalid/appliance:test"}}
			if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)}); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(binding), binding); !apierrors.IsNotFound(err) {
				t.Fatal("rejected mode retains previous forwarding authorization", err)
			}
			if err := c.Get(t.Context(), client.ObjectKeyFromObject(connection), connection); err != nil {
				t.Fatal(err)
			}
			if connection.Status.Phase == sdn.VPNConnectionPhaseEstablished || !meta.IsStatusConditionFalse(connection.Status.Conditions, sdn.VPNConnectionConditionEstablished) {
				t.Fatal("mode rejection retained predecessor IPSec success")
			}
		})
	}
}
