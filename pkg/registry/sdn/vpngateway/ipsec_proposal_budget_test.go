package vpngateway

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIPsecDefaultProposalBudgetAtAdmission(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	gw := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, IPsec: &sdn.VPNGatewayIPsec{Proposals: []string{strings.Repeat("a", 128<<10)}}}}
	if errs := strategy.Validate(t.Context(), gw); len(errs) == 0 {
		t.Fatal("128KiB gateway default proposal admitted")
	}
	if errs := strategy.ValidateUpdate(t.Context(), gw, gw.DeepCopy()); len(errs) == 0 {
		t.Fatal("128KiB gateway default proposal admitted on update")
	}
}

func TestIPsecDefaultProposalBudgetDiagnosticsAndRecovery(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	gw := &sdn.VPNGateway{Spec: sdn.VPNGatewaySpec{VPCRef: sdn.LocalVPCRef{Name: "vpc"}, IPsec: &sdn.VPNGatewayIPsec{}}}
	for _, proposals := range [][]string{make([]string, 17), {"input-canary-" + strings.Repeat("a", 128<<10)}} {
		gw.Spec.IPsec.Proposals = proposals
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), gw), strategy.ValidateUpdate(t.Context(), gw, gw.DeepCopy())} {
			if len(errs) != 1 || len(errs.ToAggregate().Error()) > 256 || strings.Contains(errs.ToAggregate().Error(), "input-canary") {
				t.Fatal("unbounded admission rejection")
			}
		}
	}
	gw.Spec.IPsec.Proposals = make([]string, vpnlimits.IPsecProposals)
	for i := range gw.Spec.IPsec.Proposals {
		gw.Spec.IPsec.Proposals[i] = strings.Repeat("a", vpnlimits.IPsecProposalBytes)
	}
	if errs := strategy.Validate(t.Context(), gw); len(errs) != 0 {
		t.Fatal(errs)
	}
}
