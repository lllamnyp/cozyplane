package main

import (
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestHostFirewallRejectsExpandedSnapshotBeforeAllocation(t *testing.T) {
	ports := make([]sdn.HostFirewallPort, 600)
	for i := range ports {
		ports[i] = sdn.HostFirewallPort{Protocol: "TCP", Port: 1, EndPort: 64}
	}
	hf := &sdn.HostFirewall{Spec: sdn.HostFirewallSpec{Ingress: []sdn.HostFirewallRule{{Ports: ports}}}}
	c := compileHostFirewalls([]*sdn.HostFirewall{hf}, nil)
	if c.err == nil || len(c.in) != 0 || len(c.eg) != 0 {
		t.Fatal("oversized host snapshot materialized", len(c.in), len(c.eg), c.err)
	}
	hf.Spec.Ingress[0].Ports = ports[:1]
	c = compileHostFirewalls([]*sdn.HostFirewall{hf}, nil)
	if c.err != nil || len(c.in) != 128 {
		t.Fatal("bounded host snapshot failed to recover", len(c.in), c.err)
	}
}

func TestSecurityGroupPreflightBoundsRowsAcrossObjects(t *testing.T) {
	groups := make([]*sdn.SecurityGroup, 2)
	for i := range groups {
		groups[i] = &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{Ingress: make([]sdn.SecurityGroupRule, 17000)}}
	}
	if err := validateSGCompilation(groups, nil); err == nil {
		t.Fatal("cross-object expanded rows were accepted")
	}
	if err := validateSGCompilation(groups[:1], nil); err != nil {
		t.Fatal("bounded snapshot rejected", err)
	}
}

func TestCompileWarningStringsBoundedBeforeDedup(t *testing.T) {
	var warnings []string
	for i := 0; i < 10000; i++ {
		addCompileWarnings(&warnings, "repeated invalid rule")
	}
	if len(warnings) != maxCompileWarnings+1 {
		t.Fatal("warning heap exceeded bound", len(warnings))
	}
	var previous compileWarnings
	if _, truncated := previous.update(warnings); !truncated {
		t.Fatal("truncated raw warnings were not reported")
	}
}
