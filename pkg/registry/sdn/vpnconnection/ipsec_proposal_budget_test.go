package vpnconnection

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIPsecOverrideProposalBudgetAtAdmission(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, IPsec: &sdn.VPNConnectionIPsec{RemoteIdentity: "peer.example.invalid", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "credential"}}}}
	for _, proposals := range [][]string{make([]string, 17), {"input-canary-" + strings.Repeat("a", 128<<10)}} {
		conn.Spec.IPsec.Proposals = proposals
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, conn.DeepCopy())} {
			if len(errs) != 1 || len(errs.ToAggregate().Error()) > 256 || strings.Contains(errs.ToAggregate().Error(), "input-canary") {
				t.Fatal("unbounded proposal admission rejection")
			}
		}
	}
	conn.Spec.IPsec.Proposals = []string{"aes256-sha256-modp2048"}
	if errs := strategy.Validate(t.Context(), conn); len(errs) != 0 {
		t.Fatal(errs)
	}
}
