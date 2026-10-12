package sdn

import (
	"encoding/json"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestIPsecPoolNamePreflightBeforeCredentialsAndLookup(t *testing.T) {
	r, gw, conns := ipsecProposalBudgetFixture(t)
	gw.Spec.IPsec.Proposals = nil
	bad := "input-canary-" + strings.Repeat("a", 128<<10)
	gw.Spec.IPsec.AddressPools = []sdn.VPNIPsecAddressPool{{Name: "clients", CIDR: "192.0.2.0/24"}, {Name: bad, CIDR: "198.51.100.0/24"}}
	if problem := vpnGatewayInputProblem(gw); problem == "" || len(problem) > 128 || strings.Contains(problem, "input-canary") {
		t.Fatal("gateway preflight admitted or echoed pool name")
	}
	for _, latePeer := range []bool{false, true} {
		if latePeer {
			gw.Spec.IPsec.AddressPools[1].Name = "other"
			conns[len(conns)-1].Spec.IPsec.AddressPool = bad
			if problem := vpnConnectionReferenceProblem(&conns[len(conns)-1]); problem == "" || len(problem) > 128 || strings.Contains(problem, "input-canary") {
				t.Fatal("connection preflight admitted or echoed pool name")
			}
		}
		raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
		if err == nil || raw != nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") || r.Client.(*wgBudgetClient).secretReads != 0 {
			t.Fatal("oversized pool name reached credentials/JSON or input echoed", err)
		}
		if err := applyIPsecAddressPools(gw, conns); err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
			t.Fatal("oversized name reached lookup or diagnostic", err)
		}
	}
	conns[len(conns)-1].Spec.IPsec.AddressPool = ""
	want := strings.Repeat("a", 255)
	gw.Spec.IPsec.AddressPools[1].Name = want
	raw, err := r.buildIPsecConfig(t.Context(), gw, []*sdn.VPC{{}}, conns, 1280)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Pools []struct {
			Name string `json:"name"`
		} `json:"pools"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil || len(cfg.Pools) != 2 || cfg.Pools[1].Name != want {
		t.Fatal("255-byte name was not preserved exactly", err)
	}
}
