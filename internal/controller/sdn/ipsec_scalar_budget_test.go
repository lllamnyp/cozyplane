package sdn

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func ipsecScalarBudgetFixture(tb testing.TB, field string) (*VPNGatewayReconciler, *sdn.VPNGateway, []sdn.VPNConnection) {
	tb.Helper()
	r, gw, conns := ipsecProposalBudgetFixture(tb)
	gw.Spec.IPsec.Proposals = nil
	large := strings.Repeat("a", 128<<10)
	for i := range conns {
		if field == "address" {
			conns[i].Spec.IPsec.PeerAddress = large
		} else {
			conns[i].Spec.IPsec.RemoteIdentity = large + fmt.Sprintf("-%d", i)
		}
	}
	return r, gw, conns
}

func TestIPsecScalarBudgetBeforeCredentialsAndSerialization(t *testing.T) {
	for _, field := range []string{"identity", "address"} {
		t.Run(field, func(t *testing.T) {
			r, gw, conns := ipsecScalarBudgetFixture(t, field)
			raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
			if err == nil {
				t.Fatalf("128KiB IPsec %s produced %d-byte config for16 peers", field, len(raw))
			}
			if raw != nil || r.Client.(*wgBudgetClient).secretReads != 0 {
				t.Fatal("oversized scalar reached credentials/serialization")
			}
		})
	}
}

func BenchmarkIPsecRepeatedIdentityBudget(b *testing.B) {
	r, gw, conns := ipsecScalarBudgetFixture(b, "identity")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = r.buildIPsecConfig(b.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	}
}

func TestIPsecScalarBudgetLatePeerAndLocalIdentityRecovery(t *testing.T) {
	r, gw, conns := ipsecProposalBudgetFixture(t)
	gw.Spec.IPsec.Proposals = nil
	for _, field := range []string{"certificate", "eap", "local"} {
		copy := conns[15].DeepCopy()
		large := "input-canary-" + strings.Repeat("a", 128<<10)
		switch field {
		case "certificate":
			copy.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{Certificate: &sdn.VPNIPsecCertificateAuth{RemoteIdentity: large}}
		case "eap":
			copy.Spec.IPsec.Auth = sdn.VPNConnectionIPsecAuth{EAP: &sdn.VPNIPsecEAPAuth{Identity: large, SecretRef: "credential"}}
		case "local":
			gw.Spec.IPsec.LocalIdentity = large
		}
		input := append([]sdn.VPNConnection(nil), conns...)
		input[15] = *copy
		raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, input, 1280)
		if err == nil || raw != nil || r.Client.(*wgBudgetClient).secretReads != 0 || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
			t.Fatal("late invalid scalar reached credential work or diagnostic")
		}
		gw.Spec.IPsec.LocalIdentity = ""
	}
	conns = conns[:1]
	conns[0].Spec.IPsec.RemoteIdentity = "keyid:" + strings.Repeat("a", 4096-len("keyid:"))
	conns[0].Spec.IPsec.PeerAddress = strings.Repeat("a", 512)
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Peers []struct {
			Identity string `json:"remoteIdentity"`
			Address  string `json:"peerAddress"`
		} `json:"peers"`
	}
	if err := json.Unmarshal(raw, &config); err != nil || len(config.Peers) != 1 || config.Peers[0].Identity != conns[0].Spec.IPsec.RemoteIdentity || config.Peers[0].Address != conns[0].Spec.IPsec.PeerAddress {
		t.Fatal("bounded identity/address changed in configuration")
	}
}
