package vpnconnection

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestVPNConnectionReferenceAdmissionBounds(t *testing.T) {
	setters := map[string]func(*sdn.VPNConnection, string){
		"gateway":   func(c *sdn.VPNConnection, name string) { c.Spec.GatewayRef.Name = name },
		"WG secret": func(c *sdn.VPNConnection, name string) { c.Spec.WireGuard.PresharedKeySecretRef = name },
		"IPsec secret": func(c *sdn.VPNConnection, name string) {
			c.Spec.WireGuard = nil
			c.Spec.IPsec = &sdn.VPNConnectionIPsec{PeerAddress: "192.0.2.10", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: name}}
		},
		"EAP secret": func(c *sdn.VPNConnection, name string) {
			c.Spec.WireGuard = nil
			c.Spec.IPsec = &sdn.VPNConnectionIPsec{AddressPool: "clients", Auth: sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: "device", SecretRef: name}}}
		},
	}
	strategy := NewStrategy(runtime.NewScheme())
	for kind, set := range setters {
		t.Run(kind, func(t *testing.T) {
			for _, name := range []string{strings.Repeat("a", 128<<10), strings.Repeat("a", 254), "bad/name", "BadName", "bad_name", "a\x00b"} {
				c := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}
				old := c.DeepCopy()
				set(c, name)
				for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), c), strategy.ValidateUpdate(t.Context(), c, old)} {
					if len(errs) == 0 {
						t.Fatal("invalid reference admitted")
					}
					if size := len(errs.ToAggregate().Error()); size > 1024 {
						t.Fatalf("reference diagnostic retains %d bytes", size)
					}
				}
				set(c, strings.Repeat("a", 253))
				if errs := strategy.Validate(t.Context(), c); len(errs) != 0 {
					t.Fatalf("valid 253-byte reference refused: %v", errs)
				}
			}
		})
	}
}
