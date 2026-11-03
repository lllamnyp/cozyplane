package vpngateway

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIPsecLocalIdentityBudgetAtAdmission(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	gw := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, IPsec: &sdn.VPNGatewayIPsec{LocalIdentity: "input-canary-" + strings.Repeat("a", 128<<10)}}}
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), gw), strategy.ValidateUpdate(t.Context(), gw, gw.DeepCopy())} {
		if len(errs) != 1 || len(errs.ToAggregate().Error()) > 256 || strings.Contains(errs.ToAggregate().Error(), "input-canary") {
			t.Fatal("unbounded or absent local identity rejection")
		}
	}
	for _, identity := range []string{"", "gateway.example.invalid", strings.Repeat("a", 4096)} {
		gw.Spec.IPsec.LocalIdentity = identity
		if errs := strategy.Validate(t.Context(), gw); len(errs) != 0 {
			t.Fatal(errs)
		}
	}
}
