package vpnconnection

import (
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func ipsecGenerationConnection() *sdn.VPNConnection {
	return &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{
		GatewayRef: sdn.LocalVPNGatewayRef{Name: "ike-gateway"}, RemoteCIDRs: []string{"198.18.0.0/24"},
		IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}},
	}}
}

func TestIPsecGenerationTracksCredentialAndPermissionChanges(t *testing.T) {
	strategy := NewStrategy(nil)
	created := ipsecGenerationConnection()
	created.Generation = 99
	strategy.PrepareForCreate(t.Context(), created)
	if created.Generation != 1 {
		t.Fatal("IPsec create generation not initialized")
	}
	for _, mutate := range []func(*sdn.VPNConnection){
		func(c *sdn.VPNConnection) { c.Spec.IPsec.Auth.PSKSecretRef = "rotated-psk" },
		func(c *sdn.VPNConnection) { c.Spec.IPsec.RemoteIdentity = "replacement.example.invalid" },
		func(c *sdn.VPNConnection) { c.Spec.RemoteCIDRs = []string{"198.19.0.0/24"} },
	} {
		old, current := ipsecGenerationConnection(), ipsecGenerationConnection()
		old.Generation, current.Generation = 7, 99
		mutate(current)
		strategy.PrepareForUpdate(t.Context(), current, old)
		if current.Generation != 8 {
			t.Fatal("IPsec specification change did not advance generation", current.Generation)
		}
	}
	old, current := ipsecGenerationConnection(), ipsecGenerationConnection()
	old.Generation, current.Generation = 7, 99
	current.Labels = map[string]string{"example.invalid/label": "value"}
	strategy.PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("IPsec metadata update changed generation")
	}
	current.Generation = 99
	NewStatusStrategy(strategy).PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("IPsec status update changed generation")
	}
}
