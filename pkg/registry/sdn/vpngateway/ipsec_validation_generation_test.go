package vpngateway

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func ipsecGenerationGateway() *sdn.VPNGateway {
	return &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "app"}, IPsec: &sdn.VPNGatewayIPsec{LocalIdentity: "vpn.example.invalid"}}}
}

func TestIPsecGatewayGenerationTracksCredentialsPoolsAndVPCs(t *testing.T) {
	strategy := NewStrategy(nil)
	created := ipsecGenerationGateway()
	created.Generation = 99
	strategy.PrepareForCreate(t.Context(), created)
	if created.Generation != 1 {
		t.Fatal("IPsec gateway create generation not initialized")
	}
	for _, mutate := range []func(*sdn.VPNGateway){
		func(g *sdn.VPNGateway) { g.Spec.IPsec.CredentialSecretRef = "tls" },
		func(g *sdn.VPNGateway) { g.Spec.IPsec.LocalIdentity = "replacement.example.invalid" },
		func(g *sdn.VPNGateway) {
			g.Spec.IPsec.AddressPools = []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "198.18.0.0/24"}}
		},
		func(g *sdn.VPNGateway) { g.Spec.AdditionalVPCRefs = []sdn.LocalVPCRef{{Name: "db"}} },
	} {
		old, current := ipsecGenerationGateway(), ipsecGenerationGateway()
		old.Generation, current.Generation = 7, 99
		mutate(current)
		strategy.PrepareForUpdate(t.Context(), current, old)
		if current.Generation != 8 {
			t.Fatal("IPsec gateway specification did not advance generation", current.Generation)
		}
	}
	old, current := ipsecGenerationGateway(), ipsecGenerationGateway()
	old.Generation, current.Generation = 7, 99
	current.Labels = map[string]string{"example.invalid/label": "value"}
	strategy.PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("IPsec gateway metadata changed generation")
	}
	current.Generation = 99
	NewStatusStrategy(strategy).PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("IPsec gateway status changed generation")
	}
}
