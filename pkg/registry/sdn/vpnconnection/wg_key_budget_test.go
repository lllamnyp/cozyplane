package vpnconnection

import (
	"strings"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestWireGuardRejectsOversizedKeyAtPublicAdmission(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: strings.Repeat("A", 128<<10)}}}
	if errs := strategy.Validate(t.Context(), conn); len(errs) == 0 {
		t.Fatal("128KiB invalid WireGuard public key admitted")
	}
	if errs := strategy.ValidateUpdate(t.Context(), conn, conn.DeepCopy()); len(errs) == 0 {
		t.Fatal("128KiB invalid WireGuard public key admitted on update")
	}
}

func TestWireGuardAdmissionBudgetShapesAndDiagnostics(t *testing.T) {
	strategy := NewStrategy(runtime.NewScheme())
	const key = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, mutate := range []func(*sdn.VPNConnectionWireGuard){
		func(w *sdn.VPNConnectionWireGuard) { w.PeerPublicKey = "secret-canary-" + strings.Repeat("A", 128<<10) },
		func(w *sdn.VPNConnectionWireGuard) { w.PeerPublicKey = ""; w.PeerPublicKeys = make([]string, 4097) },
		func(w *sdn.VPNConnectionWireGuard) { w.PeerEndpoints = make([]string, 4097) },
		func(w *sdn.VPNConnectionWireGuard) { w.PeerPublicKeys = []string{key, key} },
		func(w *sdn.VPNConnectionWireGuard) {
			w.PeerEndpoint = "secret-canary-" + strings.Repeat("a", 128<<10) + ":51820"
		},
		func(w *sdn.VPNConnectionWireGuard) { w.PeerEndpoint = "192.0.2.10:65536" },
		func(w *sdn.VPNConnectionWireGuard) { w.PersistentKeepalive = 65536 },
	} {
		conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKey: key}}}
		mutate(conn.Spec.WireGuard)
		for _, errs := range []field.ErrorList{strategy.Validate(t.Context(), conn), strategy.ValidateUpdate(t.Context(), conn, conn.DeepCopy())} {
			if len(errs) != 1 {
				t.Fatalf("expected bounded one-error rejection, got %d", len(errs))
			}
			message := errs.ToAggregate().Error()
			if len(message) > 1024 || strings.Contains(message, "secret-canary") {
				t.Fatal("invalid input retained in diagnostic")
			}
		}
	}
	conn := &sdn.VPNConnection{Spec: sdn.VPNConnectionSpec{GatewayRef: sdn.LocalVPNGatewayRef{Name: "gateway"}, WireGuard: &sdn.VPNConnectionWireGuard{PeerPublicKeys: []string{key, key}, PeerEndpoints: []string{"192.0.2.10:1", "[2001:db8::1]:65535"}, PersistentKeepalive: 65535}}}
	if errs := strategy.Validate(t.Context(), conn); len(errs) != 0 {
		t.Fatalf("valid paired boundary refused: %v", errs)
	}
}
