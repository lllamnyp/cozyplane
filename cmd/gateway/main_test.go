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
)

func joined(rules [][]string) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = strings.Join(r, " ")
	}
	return out
}

func assertRules(t *testing.T, got [][]string, want []string) {
	t.Helper()
	j := joined(got)
	if len(j) != len(want) {
		t.Fatalf("rules = %v, want %v", j, want)
	}
	for i := range want {
		if j[i] != want[i] {
			t.Errorf("rule %d = %q, want %q", i, j[i], want[i])
		}
	}
}

// The gateway's trust boundary is rule ORDER: replies, then internal-CIDR
// drops, then the off-cluster accept — under a DROP policy. A reordering
// (the generic accept before the drops) would open the cluster to tenants.
func TestForwardRuleOrder(t *testing.T) {
	assertRules(t, forwardRules("eth1", []string{"10.244.0.0/16", "10.96.0.0/16"}), []string{
		"-m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-i eth1 -d 10.244.0.0/16 -j DROP",
		"-i eth1 -d 10.96.0.0/16 -j DROP",
		"-i eth1 -j ACCEPT",
	})
}

// DNS to any cluster-internal destination is not forwarded but intercepted: a
// REDIRECT to the local proxy, whose own sockets get the node's Service
// translation. Matching only the ClusterIP is not enough — Cilium's socket-LB
// rewrites it to a CoreDNS pod IP inside the client — so the pod/service
// CIDRs are matched too. External resolvers are left alone.
func TestDNSIsRedirectedNotForwarded(t *testing.T) {
	assertRules(t, dnsRedirectRules("eth1", "10.96.0.10", []string{"10.244.0.0/16"}), []string{
		"-i eth1 -d 10.96.0.10/32 -p udp --dport 53 -j REDIRECT --to-ports 53",
		"-i eth1 -d 10.96.0.10/32 -p tcp --dport 53 -j REDIRECT --to-ports 53",
		"-i eth1 -d 10.244.0.0/16 -p udp --dport 53 -j REDIRECT --to-ports 53",
		"-i eth1 -d 10.244.0.0/16 -p tcp --dport 53 -j REDIRECT --to-ports 53",
	})
	if got := dnsRedirectRules("eth1", "", nil); got != nil {
		t.Errorf("no redirect expected without --cluster-dns, got %v", got)
	}
}

// The VPC side may address the gateway itself only on :53 (the DNS proxy);
// everything else to the gateway is dropped.
func TestInputRestrictedToDNS(t *testing.T) {
	assertRules(t, inputRules("eth1"), []string{
		"-i eth1 -p udp --dport 53 -j ACCEPT",
		"-i eth1 -p tcp --dport 53 -j ACCEPT",
		"-i eth1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"-i eth1 -j DROP",
	})
}

func TestNATMasqueradesFabricLegOnly(t *testing.T) {
	assertRules(t, masqueradeRules("eth0"), []string{"-o eth0 -j MASQUERADE"})
}
