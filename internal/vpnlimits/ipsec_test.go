package vpnlimits

import (
	"strings"
	"testing"
)

func TestIPsecProposalBudgetBoundaries(t *testing.T) {
	boundary := make([]string, IPsecProposals)
	for i := range boundary {
		boundary[i] = strings.Repeat("a", IPsecProposalBytes)
	}
	for _, proposals := range [][]string{nil, {}, {"aes256gcm16-prfsha384-ecp384"}, boundary} {
		if problem := IPsecProposalProblem(proposals); problem != "" {
			t.Fatal(problem)
		}
	}
	for _, proposals := range [][]string{make([]string, IPsecProposals+1), {strings.Repeat("a", IPsecProposalBytes+1)}, {"input-canary-" + strings.Repeat("a", 128<<10)}} {
		problem := IPsecProposalProblem(proposals)
		if problem == "" || len(problem) > 128 || strings.Contains(problem, "input-canary") {
			t.Fatal("unbounded or absent proposal rejection")
		}
	}
}

func TestIPsecScalarByteBudgetBoundaries(t *testing.T) {
	if problem := IPsecScalarProblem(strings.Repeat("a", 512), strings.Repeat("b", 4096), ""); problem != "" {
		t.Fatal(problem)
	}
	if problem := IPsecScalarProblem(""); problem != "" {
		t.Fatal(problem)
	}
	for _, problem := range []string{IPsecScalarProblem(strings.Repeat("a", 513)), IPsecScalarProblem("", "", strings.Repeat("b", 4097))} {
		if problem == "" || len(problem) > 128 {
			t.Fatal("unbounded or absent scalar rejection")
		}
	}
}
