package vpnnet

import (
	"slices"
	"testing"
)

func TestOrgGatewayRules(t *testing.T) {
	rules, err := orgGatewayRules("eth0", []string{"10.240.0.5/32"}, "10.96.0.10")
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-o", "eth0", "-d", "10.240.0.5/32", "-p", "tcp", "-m", "multiport", "--dports", "80,443", "-j", "MASQUERADE"},
		{"-o", "eth0", "-d", "10.96.0.10/32", "-p", "udp", "--dport", "53", "-j", "MASQUERADE"},
		{"-o", "eth0", "-d", "10.96.0.10/32", "-p", "tcp", "--dport", "53", "-j", "MASQUERADE"},
	}
	if !slices.EqualFunc(rules, want, slices.Equal[[]string]) {
		t.Fatalf("rules = %v", rules)
	}
	for _, bad := range []string{"10.240.0.0/24", "fd00::5/128", "-j ACCEPT"} {
		if _, err := orgGatewayRules("eth0", []string{bad}, ""); err == nil {
			t.Fatalf("destination %q accepted", bad)
		}
	}
	if _, err := orgGatewayRules("eth0", nil, "fd00::a"); err == nil {
		t.Fatal("IPv6 cluster DNS accepted")
	}
}

type fakeNAT struct {
	exists bool
	calls  []string
}

func (f *fakeNAT) ChainExists(_, _ string) (bool, error) { return f.exists, nil }
func (f *fakeNAT) ClearChain(_, c string) error          { f.calls = append(f.calls, "clear "+c); return nil }
func (f *fakeNAT) ClearAndDeleteChain(_, c string) error {
	f.calls = append(f.calls, "delete "+c)
	return nil
}
func (f *fakeNAT) Append(_, c string, r ...string) error {
	f.calls = append(f.calls, "append "+c)
	return nil
}
func (f *fakeNAT) AppendUnique(_, c string, r ...string) error {
	f.calls = append(f.calls, "jump "+c+" "+r[len(r)-1])
	return nil
}
func (f *fakeNAT) DeleteIfExists(_, c string, r ...string) error {
	f.calls = append(f.calls, "unjump "+c+" "+r[len(r)-1])
	return nil
}

// The chain is rebuilt on every start: with nothing to install a leftover chain
// and its jump are removed, with rules it is cleared before being refilled.
func TestOrgGatewayChainRebuiltOnEveryStart(t *testing.T) {
	leftover := &fakeNAT{exists: true}
	if err := syncOrgGatewayChain(leftover, nil); err != nil {
		t.Fatal(err)
	}
	if want := []string{"unjump POSTROUTING " + orgGatewayChain, "delete " + orgGatewayChain}; !slices.Equal(leftover.calls, want) {
		t.Fatalf("empty input: %v, want %v", leftover.calls, want)
	}
	none := &fakeNAT{}
	if err := syncOrgGatewayChain(none, nil); err != nil || len(none.calls) != 0 {
		t.Fatalf("no chain, no rules: %v %v", none.calls, err)
	}
	fresh := &fakeNAT{}
	if err := syncOrgGatewayChain(fresh, [][]string{{"-j", "MASQUERADE"}}); err != nil {
		t.Fatal(err)
	}
	if want := []string{"clear " + orgGatewayChain, "append " + orgGatewayChain, "jump POSTROUTING " + orgGatewayChain}; !slices.Equal(fresh.calls, want) {
		t.Fatalf("rules: %v, want %v", fresh.calls, want)
	}
}
