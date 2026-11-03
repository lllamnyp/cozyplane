package vpngateway

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestVPNGatewayReferenceAdmissionBounds(t *testing.T) {
	setters := map[string]func(*sdn.VPNGateway, string){
		"VPC":   func(g *sdn.VPNGateway, name string) { g.Spec.VPCRef.Name = name },
		"claim": func(g *sdn.VPNGateway, name string) { g.Spec.ExternalAddress.AddressClaimName = name },
		"claims": func(g *sdn.VPNGateway, name string) {
			g.Spec.ExternalAddress.AddressClaimNames = []string{name, "other-claim"}
		},
		"TLS": func(g *sdn.VPNGateway, name string) { g.Spec.IPsec = &sdn.VPNGatewayIPsec{CredentialSecretRef: name} },
		"CA":  func(g *sdn.VPNGateway, name string) { g.Spec.IPsec = &sdn.VPNGatewayIPsec{TrustedCASecretRef: name} },
		"state": func(g *sdn.VPNGateway, name string) {
			g.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdn.VPNGatewayVirtualMachine{Image: "example.invalid/appliance:test", StateClaimName: name}}
		},
		"cloud-init": func(g *sdn.VPNGateway, name string) {
			g.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration, VirtualMachine: &sdn.VPNGatewayVirtualMachine{Image: "example.invalid/appliance:test", StateClaimName: "state", CloudInitSecretRef: name}}
		},
	}
	strategy := NewStrategy(runtime.NewScheme())
	for kind, set := range setters {
		t.Run(kind, func(t *testing.T) {
			for _, name := range []string{strings.Repeat("a", 128<<10), strings.Repeat("a", 254), "bad/name", "BadName", "bad_name", "a\x00b"} {
				g := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}}}
				old := g.DeepCopy()
				set(g, name)
				for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), g), strategy.ValidateUpdate(t.Context(), g, old)} {
					if len(errs) == 0 {
						t.Fatal("invalid reference admitted")
					}
					if size := len(errs.ToAggregate().Error()); size > 1024 {
						t.Fatalf("reference diagnostic retains %d bytes", size)
					}
				}
				set(g, strings.Repeat("a", 253))
				if errs := strategy.Validate(t.Context(), g); len(errs) != 0 {
					t.Fatalf("valid 253-byte reference refused: %v", errs)
				}
			}
		})
	}
	g := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, ExternalAddress: sdn.VPNExternalAddress{AddressClaimNames: make([]string, 10000)}}}
	if errs := strategy.Validate(t.Context(), g); len(errs) != 1 || len(errs.ToAggregate().Error()) > 1024 {
		t.Fatal("unbounded claim list accepted or echoed")
	}
}
