package vpnconnection

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func invalidCIDRStatus(t testing.TB, errors field.ErrorList) []byte {
	t.Helper()
	if len(errors) == 0 {
		t.Fatal("invalid prefix admitted")
	}
	status := apierrors.NewInvalid(schema.GroupKind{Group: sdn.GroupName, Kind: "VPNConnection"}, "peer", errors).Status()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVPNCIDRDiagnosticsBoundActualAPIStatus(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}}
	for _, large := range []bool{false, true} {
		if large {
			conn.Spec.RemoteCIDRs = []string{"input-canary-" + strings.Repeat("a", 1<<20)}
		} else {
			conn.Spec.RemoteCIDRs = make([]string, 4096)
			for i := range conn.Spec.RemoteCIDRs {
				conn.Spec.RemoteCIDRs[i] = "invalid-prefix"
			}
		}
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, conn.DeepCopy())} {
			raw := invalidCIDRStatus(t, errs)
			if len(errs) != 1 || len(raw) > 1024 || strings.Contains(string(raw), "input-canary") {
				t.Errorf("invalid prefix input produced %d causes/%d-byte API Status", len(errs), len(raw))
			}
		}
	}
}

func TestVPNCIDRAdmissionValidPrefixesAndLateFailure(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, RemoteCIDRs: make([]string, vpnlimits.RoutePrefixes)}}
	valid := []string{"192.0.2.7/24", "2001:db8::7/64", "::ffff:192.0.2.7/120", "0.0.0.0/0", "::/0"}
	for i := range conn.Spec.RemoteCIDRs {
		conn.Spec.RemoteCIDRs[i] = valid[i%len(valid)]
	}
	old := conn.DeepCopy()
	for _, value := range []string{"invalid-prefix", strings.Repeat("a", vpnlimits.RoutePrefixBytes), strings.Repeat("a", vpnlimits.RoutePrefixBytes+1)} {
		conn.Spec.RemoteCIDRs[len(conn.Spec.RemoteCIDRs)-1] = value
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, old)} {
			raw := invalidCIDRStatus(t, errs)
			if len(errs) != 1 || errs[0].Field != "spec.remoteCIDRs[4095]" || len(raw) > 1024 || strings.Contains(string(raw), value) {
				t.Errorf("late invalid prefix produced unbounded or mislocated diagnostic: %s", raw)
			}
		}
	}
	conn.Spec.RemoteCIDRs = old.Spec.RemoteCIDRs
	for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, old)} {
		if len(errs) != 0 {
			t.Errorf("valid prefix recovery rejected: %v", errs)
		}
	}
}

func BenchmarkVPNCIDRDiagnosticsBudget(b *testing.B) {
	strategy := NewStrategy(runtime.NewScheme())
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, RemoteCIDRs: make([]string, 4096)}}
	for i := range conn.Spec.RemoteCIDRs {
		conn.Spec.RemoteCIDRs[i] = "invalid-prefix"
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invalidCIDRStatus(b, strategy.Validate(b.Context(), conn))
	}
}

func TestVPNConnectionInvalidModesDoNotEchoSpec(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	canary := "input-canary-" + strings.Repeat("a", 1<<20)
	base := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, IPsec: &sdn.VPNConnectionIPsec{PeerAddress: "192.0.2.1", Auth: sdn.VPNConnectionIPsecAuth{PSKSecretRef: "psk"}}}}
	for _, test := range []struct {
		name   string
		mutate func(*sdn.VPNConnection)
	}{
		{"start action", func(conn *sdn.VPNConnection) { conn.Spec.IPsec.StartAction = sdn.VPNIPsecStartAction(canary) }},
		{"pool error", func(conn *sdn.VPNConnection) { conn.Spec.IPsec.AddressPool = canary }},
		{"backend conflict", func(conn *sdn.VPNConnection) {
			conn.Spec.IPsec.AddressPool = canary
			conn.Spec.WireGuard = &sdn.VPNConnectionWireGuard{PeerPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := base.DeepCopy()
			test.mutate(bad)
			for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), bad), strategy.ValidateUpdate(t.Context(), bad, base)} {
				raw := invalidCIDRStatus(t, errs)
				if len(raw) > 2048 || strings.Contains(string(raw), "input-canary") {
					t.Fatal("diagnostic echoed unbounded input", len(raw))
				}
			}
			if errs := strategy.ValidateUpdate(t.Context(), base.DeepCopy(), bad); len(errs) != 0 {
				t.Fatal("valid mode recovery rejected", errs)
			}
		})
	}
}
