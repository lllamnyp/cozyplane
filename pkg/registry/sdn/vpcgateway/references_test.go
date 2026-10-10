package vpcgateway

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestVPCGatewayReferenceAdmissionBounds(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme(), nil)
	old := &sdn.VPCGateway{Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}}
	for _, name := range []string{"", strings.Repeat("a", 128<<10), strings.Repeat("a", 254), "bad/name", "BadName", "bad_name", "a\x00b"} {
		current := old.DeepCopy()
		current.Spec.VPCRef.Name = name
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), current), strategy.ValidateUpdate(t.Context(), current, old)} {
			if len(errs) == 0 {
				t.Fatal("invalid VPC reference admitted")
			}
			if len(errs.ToAggregate().Error()) > 1024 {
				t.Fatal("invalid reference retained in diagnostic")
			}
		}
	}
	for _, name := range []string{"net", "net.example", strings.Repeat("a", 253)} {
		current := old.DeepCopy()
		current.Spec.VPCRef.Name = name
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), current), strategy.ValidateUpdate(t.Context(), current, old)} {
			if len(errs) != 0 {
				t.Fatalf("valid VPC reference refused: %v", errs)
			}
		}
	}
}

func TestVPCGatewayNamespaceAndRouteAdmissionBounds(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme(), nil)
	old := &sdn.VPCGateway{Spec: sdn.VPCGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "net"}}}
	for _, appliance := range []bool{false, true} {
		set := func(gw *sdn.VPCGateway, ns string) {
			if appliance {
				gw.Spec.Appliance = &sdn.VPCGatewayAppliance{Namespace: ns}
			} else {
				gw.Spec.Routes = []sdn.VPCGatewayRoute{{Via: sdn.VPCGatewayVia{Namespace: ns}}}
			}
		}
		for _, ns := range []string{strings.Repeat("a", 128<<10), strings.Repeat("a", 64), "tenant.a", "BadName", "bad/name", "a\x00b"} {
			current := old.DeepCopy()
			set(current, ns)
			for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), current), strategy.ValidateUpdate(t.Context(), current, old)} {
				if len(errs) != 1 || len(errs.ToAggregate().Error()) > 1024 {
					t.Fatal("invalid namespace admitted or diagnostic unbounded")
				}
			}
		}
		for _, ns := range []string{"", "tenant-a", strings.Repeat("a", 63)} {
			current := old.DeepCopy()
			set(current, ns)
			for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), current), strategy.ValidateUpdate(t.Context(), current, old)} {
				if len(errs) != 0 {
					t.Fatalf("valid optional namespace refused: %v", errs)
				}
			}
		}
	}
	for _, manyRoutes := range []bool{false, true} {
		current := old.DeepCopy()
		if manyRoutes {
			current.Spec.Routes = make([]sdn.VPCGatewayRoute, 4097)
		} else {
			current.Spec.Routes = []sdn.VPCGatewayRoute{{CIDRs: make([]string, 2048)}, {CIDRs: make([]string, 2049)}}
		}
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), current), strategy.ValidateUpdate(t.Context(), current, old)} {
			if len(errs) != 1 || len(errs.ToAggregate().Error()) > 1024 {
				t.Fatal("oversized route input admitted or diagnostic unbounded")
			}
		}
		if manyRoutes {
			current.Spec.Routes = current.Spec.Routes[:4096]
		} else {
			current.Spec.Routes[1].CIDRs = current.Spec.Routes[1].CIDRs[:2048]
		}
		if errs := strategy.Validate(t.Context(), current); len(errs) != 0 {
			t.Fatalf("route boundary input refused: %v", errs)
		}
	}
	current := old.DeepCopy()
	current.Spec.Routes = make([]sdn.VPCGatewayRoute, 4096)
	large := strings.Repeat("a", 128<<10)
	for i := range current.Spec.Routes {
		current.Spec.Routes[i].Via.Namespace = large
	}
	if errs := strategy.Validate(t.Context(), current); len(errs) != 1 || len(errs.ToAggregate().Error()) > 1024 {
		t.Fatal("legacy many invalid references produce unbounded diagnostics")
	}
}
