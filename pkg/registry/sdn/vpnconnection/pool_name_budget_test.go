package vpnconnection

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIPsecPoolReferenceBudgetAndRecovery(t *testing.T) {
	strategy := NewStrategy(nil)
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, IPsec: &sdn.VPNConnectionIPsec{Auth: sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "peer@example.invalid", SecretRef: "credential"}}, AddressPool: "clients"}}}
	old := conn.DeepCopy()
	conn.Spec.IPsec.AddressPool = "input-canary-" + strings.Repeat("a", 128<<10)
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, old)} {
		raw := invalidCIDRStatus(t, errs)
		if len(errs) != 1 || len(raw) > 1024 || strings.Contains(string(raw), "input-canary") {
			t.Fatal("unbounded or absent pool reference rejection")
		}
	}
	conn.Spec.IPsec.AddressPool = strings.Repeat("a", 255)
	if errs := strategy.ValidateUpdate(t.Context(), conn, old); len(errs) != 0 {
		t.Fatal("valid pool reference recovery rejected", errs)
	}
	conn.Spec.IPsec = &sdn.VPNConnectionIPsec{PeerAddress: "192.0.2.1", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "credential"}}
	if errs := strategy.Validate(t.Context(), conn); len(errs) != 0 {
		t.Fatal("empty optional pool reference rejected", errs)
	}
}
