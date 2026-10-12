package vpngateway

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func wireGuardClientGateway() *sdn.VPNGateway {
	return &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{
		VPCRef: sdn.LocalVPCRef{Name: "app"},
		WireGuard: &sdn.VPNGatewayWireGuard{AddressPools: []sdn.VPNWireGuardAddressPool{
			{Name: "v4", CIDR: "198.18.0.0/24", DNS: []string{"198.18.2.53"}},
			{Name: "v6", CIDR: "2001:db8:100::/64"},
		}},
	}}
}

func TestWireGuardClientGatewayAdmission(t *testing.T) {
	strategy := NewStrategy(nil)
	for _, mode := range []sdn.VPNGatewayHAMode{"", sdn.VPNGatewayHAModeWarmStandby} {
		gw := wireGuardClientGateway()
		if mode != "" {
			gw.Spec.HA = &sdn.VPNGatewayHA{Mode: mode}
		}
		if errs := strategy.Validate(t.Context(), gw); len(errs) != 0 {
			t.Fatal("valid client gateway rejected", errs)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNGateway)
	}{
		{"ActiveActive", func(gw *sdn.VPNGateway) { gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive} }},
		{"LiveMigration", func(gw *sdn.VPNGateway) { gw.Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeLiveMigration} }},
		{"bad port", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.ListenPort = 65536 }},
		{"overlap", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.AddressPools[1].CIDR = "198.18.0.128/25" }},
		{"duplicate name", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.AddressPools[1].Name = "v4" }},
		{"too many pools", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.AddressPools = make([]sdn.VPNWireGuardAddressPool, 129) }},
		{"too many DNS", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.AddressPools[0].DNS = make([]string, 17) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			gw := wireGuardClientGateway()
			test.mutate(gw)
			if errs := strategy.Validate(t.Context(), gw); len(errs) == 0 {
				t.Fatal("invalid client gateway admitted")
			}
		})
	}
}

func TestWireGuardClientGatewayBoundedDiagnostics(t *testing.T) {
	gw := wireGuardClientGateway()
	gw.Spec.WireGuard.AddressPools[0].CIDR = "input-canary-" + strings.Repeat("x", 1<<20)
	errs := NewStrategy(nil).Validate(t.Context(), gw)
	raw := diagnosticStatus(t, errs)
	if len(errs) != 1 || len(raw) > 2048 || strings.Contains(string(raw), "input-canary") {
		t.Fatal("invalid pool input amplified APIStatus")
	}
}

func TestWireGuardGatewayClientModeImmutable(t *testing.T) {
	strategy := NewStrategy(nil)
	old, current := wireGuardClientGateway(), wireGuardClientGateway()
	current.Spec.WireGuard.AddressPools = nil
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) == 0 {
		t.Fatal("client gateway converted to site-to-site")
	}
	if errs := strategy.ValidateUpdate(t.Context(), old, current); len(errs) == 0 {
		t.Fatal("site-to-site gateway converted to client")
	}
	current = wireGuardClientGateway()
	current.Spec.AdditionalVPCRefs = []sdn.LocalVPCRef{{Name: "db"}}
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) != 0 {
		t.Fatal("valid gateway VPC update rejected", errs)
	}
}

func TestWireGuardClientGatewayGeneration(t *testing.T) {
	strategy := NewStrategy(nil)
	created := wireGuardClientGateway()
	created.Generation = 99
	strategy.PrepareForCreate(t.Context(), created)
	if created.Generation != 1 {
		t.Fatal("new client gateway generation was not initialized")
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNGateway)
		want   int64
	}{
		{"metadata", func(gw *sdn.VPNGateway) { gw.Finalizers = []string{"example.invalid/revoke"} }, 7},
		{"pool", func(gw *sdn.VPNGateway) { gw.Spec.WireGuard.AddressPools[0].CIDR = "198.19.0.0/24" }, 8},
		{"permissions", func(gw *sdn.VPNGateway) { gw.Spec.AdditionalVPCRefs = []sdn.LocalVPCRef{{Name: "db"}} }, 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			old, current := wireGuardClientGateway(), wireGuardClientGateway()
			old.Generation, current.Generation = 7, 99
			test.mutate(current)
			strategy.PrepareForUpdate(t.Context(), current, old)
			if current.Generation != test.want {
				t.Fatal("unexpected generation", current.Generation)
			}
		})
	}
	old, current := wireGuardClientGateway(), wireGuardClientGateway()
	old.Generation, current.Generation = 7, 99
	NewStatusStrategy(strategy).PrepareForUpdate(t.Context(), current, old)
	if current.Generation != 7 {
		t.Fatal("status update changed generation")
	}
	legacy := wireGuardClientGateway()
	legacy.Spec.WireGuard.AddressPools = nil
	legacy.Generation = 99
	strategy.PrepareForCreate(t.Context(), legacy)
	if legacy.Generation != 99 {
		t.Fatal("legacy site-to-site generation behavior changed")
	}
}

func TestWireGuardClientGatewayMalformedLegacyCleanup(t *testing.T) {
	old, current := wireGuardClientGateway(), wireGuardClientGateway()
	old.Spec.WireGuard.AddressPools[0].CIDR = "invalid"
	current.Spec.WireGuard.AddressPools[0].CIDR = "invalid"
	current.Finalizers = nil
	strategy := NewStrategy(nil)
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) != 0 {
		t.Fatal("unchanged malformed gateway blocks metadata cleanup", errs)
	}
	current.Spec.WireGuard.ListenPort = 51821
	if errs := strategy.ValidateUpdate(t.Context(), current, old); len(errs) == 0 {
		t.Fatal("changed malformed gateway bypasses validation")
	}
}
