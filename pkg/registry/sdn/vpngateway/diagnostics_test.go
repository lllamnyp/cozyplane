package vpngateway

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func diagnosticStatus(t testing.TB, errs field.ErrorList) []byte {
	t.Helper()
	if len(errs) == 0 {
		t.Fatal("invalid gateway admitted")
	}
	status := apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "VPNGateway"}, "gateway", errs).Status()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func overlapDiagnosticGateway() *sdn.VPNGateway {
	gw := poolBudgetFixture(128)
	for i := range gw.Spec.IPsec.AddressPools {
		gw.Spec.IPsec.AddressPools[i].CIDR = "192.0.2.0/24"
	}
	return gw
}

func TestVPNGatewayDiagnosticsBoundActualAPIStatus(t *testing.T) {
	strategy := NewStrategy(nil)
	canary := "input-canary-" + strings.Repeat("a", 1<<20)
	objects := []*sdn.VPNGateway{overlapDiagnosticGateway(), poolBudgetFixture(1), poolBudgetFixture(1), poolBudgetFixture(0), poolBudgetFixture(0), poolBudgetFixture(2)}
	objects[1].Spec.IPsec.AddressPools[0].CIDR = canary
	objects[2].Spec.IPsec.AddressPools[0].DNS = []string{canary}
	objects[3].Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAMode(canary)}
	objects[4].Spec.HA = &sdn.VPNGatewayHA{Mode: sdn.VPNGatewayHAModeActiveActive, ActiveActive: &sdn.VPNGatewayActiveActive{LocalASN: 64520, PeerASN: 64521, PeerAddresses: []string{canary}}}
	objects[5].Spec.IPsec.AddressPools[0].Name = canary
	objects[5].Spec.IPsec.AddressPools[1].Name = canary
	for i, obj := range objects {
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), obj), strategy.ValidateUpdate(t.Context(), obj, obj.DeepCopy())} {
			raw := diagnosticStatus(t, errs)
			if len(errs) > 8 || len(raw) > 2048 || strings.Contains(string(raw), "input-canary") {
				t.Errorf("case %d: %d causes/%d-byte APIStatus", i, len(errs), len(raw))
			}
		}
	}
}

func BenchmarkVPNPoolOverlapDiagnostics(b *testing.B) {
	strategy := NewStrategy(nil)
	gw := overlapDiagnosticGateway()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = diagnosticStatus(b, strategy.Validate(b.Context(), gw))
	}
}

func TestVPNGatewayPoolDiagnosticRecovery(t *testing.T) {
	strategy := NewStrategy(nil)
	valid := poolBudgetFixture(128)
	valid.Spec.IPsec.AddressPools[127].CIDR = "2001:db8::7/64"
	valid.Spec.IPsec.AddressPools[127].DNS = []string{"192.0.2.53", "2001:db8::53"}
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), valid), strategy.ValidateUpdate(t.Context(), valid, valid.DeepCopy())} {
		if len(errs) != 0 {
			t.Fatal("valid full pool capacity rejected", errs)
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNGateway)
		field  string
	}{
		{"late overlap", func(gw *sdn.VPNGateway) { gw.Spec.IPsec.AddressPools[127].CIDR = gw.Spec.IPsec.AddressPools[0].CIDR }, "spec.ipsec.addressPools[127].cidr"},
		{"late duplicate", func(gw *sdn.VPNGateway) { gw.Spec.IPsec.AddressPools[127].Name = gw.Spec.IPsec.AddressPools[0].Name }, "spec.ipsec.addressPools[127].name"},
		{"late DNS", func(gw *sdn.VPNGateway) { gw.Spec.IPsec.AddressPools[127].DNS[1] = "invalid-address" }, "spec.ipsec.addressPools[127].dns[1]"},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := valid.DeepCopy()
			test.mutate(bad)
			for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), bad), strategy.ValidateUpdate(t.Context(), bad, valid)} {
				if len(errs) != 1 || errs[0].Field != test.field || len(diagnosticStatus(t, errs)) > 2048 {
					t.Fatal("invalid late field admitted or mislocated diagnostic", errs)
				}
			}
			if errs := strategy.ValidateUpdate(t.Context(), valid.DeepCopy(), bad); len(errs) != 0 {
				t.Fatal("pool recovery rejected", errs)
			}
		})
	}
}
