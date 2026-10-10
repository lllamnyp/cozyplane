package vpnconnection

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestIPsecScalarBudgetAtPublicAdmission(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	for _, field := range []string{"identity", "address", "certificate", "eap"} {
		t.Run(field, func(t *testing.T) {
			conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "credential"}}}}
			large := "input-canary-" + strings.Repeat("a", 128<<10)
			switch field {
			case "identity":
				conn.Spec.IPsec.RemoteIdentity = large
			case "address":
				conn.Spec.IPsec.PeerAddress = large
			case "certificate":
				conn.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{Certificate: &sdn.VPNIPsecCertificateAuth{RemoteIdentity: large}}
			case "eap":
				conn.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: large, SecretRef: "credential"}}
				conn.Spec.IPsec.AddressPool = "clients"
			}
			if errs := strategy.Validate(t.Context(), conn); len(errs) == 0 {
				t.Error("128KiB IPsec scalar admitted on create")
			} else if len(errs.ToAggregate().Error()) > 256 || strings.Contains(errs.ToAggregate().Error(), "input-canary") {
				t.Error("unbounded diagnostic")
			}
			if errs := strategy.ValidateUpdate(t.Context(), conn, conn.DeepCopy()); len(errs) == 0 {
				t.Error("128KiB IPsec scalar admitted on update")
			}
		})
	}
}
