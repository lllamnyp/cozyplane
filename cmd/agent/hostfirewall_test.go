/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
)

func hfObj(name string, sel map[string]string, ingress ...sdnv1alpha1.HostFirewallRule) *sdnv1alpha1.HostFirewall {
	return &sdnv1alpha1.HostFirewall{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdnv1alpha1.HostFirewallSpec{
			NodeSelector: metav1.LabelSelector{MatchLabels: sel},
			Ingress:      ingress,
		},
	}
}

func countHF(entries []datapath.HFAllow, proto uint8, port uint16, allow bool) int {
	n := 0
	for _, e := range entries {
		if e.Proto == proto && e.Port == port && e.Allow == allow {
			n++
		}
	}
	return n
}

func TestHFSelection(t *testing.T) {
	node := labels.Set{"role": "worker"}

	// No object selects: not isolated.
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("cp", map[string]string{"role": "control-plane"}),
	}, node)
	if c.ingress || c.egress {
		t.Fatal("non-matching selector isolated the node")
	}

	// A matching selector with NO rules: ingress-isolated, default-deny (no
	// rows), and NOT egress-isolated (egress is opt-in).
	c = compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("w", map[string]string{"role": "worker"}),
	}, node)
	if !c.ingress || len(c.in) != 0 {
		t.Fatalf("empty-rules selection: ingress=%v entries=%d", c.ingress, len(c.in))
	}
	if c.egress {
		t.Fatal("an ingress-only object turned on egress isolation")
	}

	// The empty selector selects every node.
	c = compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("all", nil),
	}, node)
	if !c.ingress {
		t.Fatal("empty selector did not select")
	}
}

func TestHFDefaults(t *testing.T) {
	// Empty from -> any source both families; empty ports -> any port both
	// protocols: 2 peers x 2 proto rows = 4 allow entries at port 0.
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("open", nil, sdnv1alpha1.HostFirewallRule{}),
	}, labels.Set{})
	entries, warns := c.in, c.warnings
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	if len(entries) != 4 ||
		countHF(entries, 6, 0, true) != 2 || countHF(entries, 17, 0, true) != 2 {
		t.Fatalf("empty rule entries: %+v", entries)
	}
	for _, e := range entries {
		if ones, bits := e.CIDR.Mask.Size(); ones != 0 || (bits != 32 && bits != 128) {
			t.Fatalf("expected any-source rows, got %v", e.CIDR)
		}
	}
}

func TestHFExceptAndPorts(t *testing.T) {
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("ssh", nil, sdnv1alpha1.HostFirewallRule{
			From: []sdnv1alpha1.HostFirewallPeer{
				{CIDR: "192.168.10.0/24", Except: []string{"192.168.10.7/32"}},
			},
			Ports: []sdnv1alpha1.HostFirewallPort{
				{Protocol: "TCP", Port: 22},
				{Protocol: "UDP", Port: 9000, EndPort: 9003},
			},
		}),
	}, labels.Set{})
	entries, warns := c.in, c.warnings
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %v", warns)
	}
	// 5 port rows (22 + the 4-port range) x (1 allow + 1 except deny).
	if len(entries) != 10 {
		t.Fatalf("expected 10 entries, got %d: %+v", len(entries), entries)
	}
	if countHF(entries, 6, 22, true) != 1 || countHF(entries, 6, 22, false) != 1 {
		t.Fatalf("port 22 rows wrong: %+v", entries)
	}
	for p := uint16(9000); p <= 9003; p++ {
		if countHF(entries, 17, p, true) != 1 || countHF(entries, 17, p, false) != 1 {
			t.Fatalf("udp %d rows wrong", p)
		}
	}
}

func TestHFFailClosed(t *testing.T) {
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("bad", nil,
			// A wide range: skipped, warned.
			sdnv1alpha1.HostFirewallRule{Ports: []sdnv1alpha1.HostFirewallPort{
				{Protocol: "TCP", Port: 1000, EndPort: 2000},
			}},
			// An unserved protocol: skipped, warned.
			sdnv1alpha1.HostFirewallRule{Ports: []sdnv1alpha1.HostFirewallPort{
				{Protocol: "SCTP", Port: 5060},
			}},
			// A broken except poisons its whole peer (dropping just the
			// except would fail OPEN).
			sdnv1alpha1.HostFirewallRule{From: []sdnv1alpha1.HostFirewallPeer{
				{CIDR: "10.0.0.0/8", Except: []string{"not-a-cidr"}},
			}},
			// A broken cidr skips the peer.
			sdnv1alpha1.HostFirewallRule{From: []sdnv1alpha1.HostFirewallPeer{
				{CIDR: "bogus"},
			}},
		),
	}, labels.Set{})
	entries, warns := c.in, c.warnings
	if len(entries) != 0 {
		t.Fatalf("fail-closed rules leaked entries: %+v", entries)
	}
	if len(warns) != 4 {
		t.Fatalf("expected 4 warnings, got %v", warns)
	}
	for _, w := range warns {
		if !strings.Contains(w, "fail closed") {
			t.Fatalf("warning without fail-closed note: %q", w)
		}
	}
}

func TestHFUnionAcrossObjects(t *testing.T) {
	// Two objects select; their rules union.
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfObj("a", nil, sdnv1alpha1.HostFirewallRule{
			From:  []sdnv1alpha1.HostFirewallPeer{{CIDR: "10.0.0.0/8"}},
			Ports: []sdnv1alpha1.HostFirewallPort{{Protocol: "TCP", Port: 22}},
		}),
		hfObj("b", map[string]string{}, sdnv1alpha1.HostFirewallRule{
			From:  []sdnv1alpha1.HostFirewallPeer{{CIDR: "2001:db8::/64"}},
			Ports: []sdnv1alpha1.HostFirewallPort{{Protocol: "TCP", Port: 443}},
		}),
	}, labels.Set{"any": "thing"})
	entries := c.in
	if countHF(entries, 6, 22, true) != 1 || countHF(entries, 6, 443, true) != 1 {
		t.Fatalf("union missing rows: %+v", entries)
	}
}

func hfEgObj(name string, types []sdnv1alpha1.HostFirewallPolicyType, egress ...sdnv1alpha1.HostFirewallEgressRule) *sdnv1alpha1.HostFirewall {
	return &sdnv1alpha1.HostFirewall{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdnv1alpha1.HostFirewallSpec{
			PolicyTypes: types,
			Egress:      egress,
		},
	}
}

func TestHFEgressIsolationDefaults(t *testing.T) {
	// Egress rules present, no explicit policyTypes: both directions isolate
	// (the NetworkPolicy defaulting rule).
	c := compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfEgObj("both", nil, sdnv1alpha1.HostFirewallEgressRule{
			To:    []sdnv1alpha1.HostFirewallPeer{{CIDR: "10.0.0.0/8"}},
			Ports: []sdnv1alpha1.HostFirewallPort{{Protocol: "TCP", Port: 443}},
		}),
	}, labels.Set{})
	if !c.ingress || !c.egress {
		t.Fatalf("egress rules should isolate both by default: %+v", c)
	}
	if countHF(c.eg, 6, 443, true) != 1 {
		t.Fatalf("missing egress row: %+v", c.eg)
	}
	if len(c.in) != 0 {
		t.Fatalf("egress rules leaked into the ingress map: %+v", c.in)
	}

	// Egress-ONLY: ingress must stay open (its map empty and unarmed).
	c = compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfEgObj("egonly", []sdnv1alpha1.HostFirewallPolicyType{sdnv1alpha1.HostFirewallPolicyTypeEgress},
			sdnv1alpha1.HostFirewallEgressRule{
				To: []sdnv1alpha1.HostFirewallPeer{{CIDR: "0.0.0.0/0", Except: []string{"169.254.0.0/16"}}},
			}),
	}, labels.Set{})
	if c.ingress {
		t.Fatal("an Egress-only object isolated ingress")
	}
	if !c.egress {
		t.Fatal("Egress policyType did not isolate egress")
	}
	// Empty ports on the wide rule: any-port rows for both protocols, plus an
	// except deny per protocol.
	if countHF(c.eg, 6, 0, true) != 1 || countHF(c.eg, 17, 0, true) != 1 ||
		countHF(c.eg, 6, 0, false) != 1 || countHF(c.eg, 17, 0, false) != 1 {
		t.Fatalf("egress default rows wrong: %+v", c.eg)
	}

	// Declaring Egress in policyTypes with NO egress rules is default-deny.
	c = compileHostFirewalls([]*sdnv1alpha1.HostFirewall{
		hfEgObj("deny", []sdnv1alpha1.HostFirewallPolicyType{sdnv1alpha1.HostFirewallPolicyTypeEgress}),
	}, labels.Set{})
	if !c.egress || len(c.eg) != 0 {
		t.Fatalf("egress default-deny: egress=%v rows=%d", c.egress, len(c.eg))
	}
}
