package vpngateway

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestIPsecPoolNameBudgetAtPublicAdmission(t *testing.T) {
	strategy := NewStrategy(nil)
	gw := poolBudgetFixture(1)
	gw.Spec.IPsec.AddressPools[0].Name = "input-canary-" + strings.Repeat("a", 128<<10)
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), gw), strategy.ValidateUpdate(t.Context(), gw, gw.DeepCopy())} {
		if len(errs) == 0 {
			t.Error("128KiB pool name admitted although VICI section keys have a one-byte length")
		}
		if len(diagnosticStatus(t, errs)) > 1024 {
			t.Fatal("oversized pool name echoed")
		}
	}
	gw.Spec.IPsec.AddressPools[0].Name = strings.Repeat("a", 255)
	if errs := strategy.Validate(t.Context(), gw); len(errs) != 0 {
		t.Fatal("255-byte pool name rejected", errs)
	}
}
