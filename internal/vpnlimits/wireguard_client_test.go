package vpnlimits

import (
	"fmt"
	"strings"
	"testing"
)

func TestWireGuardAddressPoolsValidation(t *testing.T) {
	valid := []WireGuardAddressPool{
		{Name: "workstations-v4", CIDR: "198.18.0.17/24", DNS: []string{"198.18.2.53"}},
		{Name: "workstations-v6", CIDR: "2001:db8:100::/64", DNS: []string{"2001:db8:200::53"}},
	}
	if problem := WireGuardAddressPoolsProblem(valid); problem != "" {
		t.Fatal(problem)
	}
	for _, test := range []struct {
		name string
		pool WireGuardAddressPool
	}{
		{"duplicate name", WireGuardAddressPool{Name: valid[0].Name, CIDR: "198.19.0.0/24"}},
		{"overlap", WireGuardAddressPool{Name: "other", CIDR: "198.18.0.128/25"}},
		{"missing name", WireGuardAddressPool{CIDR: "198.19.0.0/24"}},
		{"bad name", WireGuardAddressPool{Name: "bad/name", CIDR: "198.19.0.0/24"}},
		{"bad cidr", WireGuardAddressPool{Name: "other", CIDR: "not-a-prefix"}},
		{"mapped cidr", WireGuardAddressPool{Name: "other", CIDR: "::ffff:198.19.0.0/120"}},
		{"bad dns", WireGuardAddressPool{Name: "other", CIDR: "198.19.0.0/24", DNS: []string{"resolver.example"}}},
		{"zoned dns", WireGuardAddressPool{Name: "other", CIDR: "198.19.0.0/24", DNS: []string{"fe80::53%eth0"}}},
		{"multicast dns", WireGuardAddressPool{Name: "other", CIDR: "198.19.0.0/24", DNS: []string{"ff02::1"}}},
		{"dns budget", WireGuardAddressPool{Name: "other", CIDR: "198.19.0.0/24", DNS: make([]string, PoolDNSServers+1)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pools := append(append([]WireGuardAddressPool(nil), valid...), test.pool)
			if problem := WireGuardAddressPoolsProblem(pools); problem == "" {
				t.Fatal("invalid pool accepted")
			}
		})
	}
	pools := make([]WireGuardAddressPool, AddressPools+1)
	for i := range pools {
		pools[i] = WireGuardAddressPool{Name: fmt.Sprintf("pool-%d", i), CIDR: fmt.Sprintf("198.18.%d.0/24", i)}
	}
	if problem := WireGuardAddressPoolsProblem(pools); problem == "" {
		t.Fatal("oversized pools accepted")
	}
	if problem := WireGuardAddressPoolsProblem(pools[:AddressPools]); problem != "" {
		t.Fatal("exact pool limit refused", problem)
	}
}

func TestWireGuardClientValidation(t *testing.T) {
	valid := WireGuardPeer{PublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for _, test := range []struct {
		name                string
		peer                WireGuardPeer
		pools, vpcs, remote []string
		valid               bool
	}{
		{"single family", valid, []string{"v4"}, []string{"app"}, nil, true},
		{"dual family", valid, []string{"v4", "v6"}, []string{"app", "db"}, nil, true},
		{"missing key", WireGuardPeer{}, []string{"v4"}, []string{"app"}, nil, false},
		{"fixed endpoint", WireGuardPeer{PublicKey: valid.PublicKey, Endpoint: "192.0.2.1:51820"}, []string{"v4"}, []string{"app"}, nil, false},
		{"paired keys", WireGuardPeer{PublicKeys: []string{valid.PublicKey, valid.PublicKey}}, []string{"v4"}, []string{"app"}, nil, false},
		{"remote routes", valid, []string{"v4"}, []string{"app"}, []string{"0.0.0.0/0"}, false},
		{"missing pool", valid, nil, []string{"app"}, nil, false},
		{"duplicate pools", valid, []string{"v4", "v4"}, []string{"app"}, nil, false},
		{"too many pools", valid, []string{"v4", "v6", "extra"}, []string{"app"}, nil, false},
		{"missing vpc", valid, []string{"v4"}, nil, nil, false},
		{"duplicate vpcs", valid, []string{"v4"}, []string{"app", "app"}, nil, false},
		{"bad vpc", valid, []string{"v4"}, []string{"bad/name"}, nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			problem := WireGuardClientProblem(test.peer, test.pools, test.vpcs, test.remote)
			if (problem == "") != test.valid {
				t.Fatalf("valid=%v, problem=%q", test.valid, problem)
			}
		})
	}
}

func TestWireGuardClientDiagnosticsNeverEchoInputs(t *testing.T) {
	canary := "input-canary-" + strings.Repeat("x", 1<<20)
	peer := WireGuardPeer{PublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for _, problem := range []string{
		WireGuardAddressPoolsProblem([]WireGuardAddressPool{{Name: canary, CIDR: "198.18.0.0/24"}}),
		WireGuardAddressPoolsProblem([]WireGuardAddressPool{{Name: "pool", CIDR: canary}}),
		WireGuardAddressPoolsProblem([]WireGuardAddressPool{{Name: "pool", CIDR: "198.18.0.0/24", DNS: []string{canary}}}),
		WireGuardClientProblem(peer, []string{canary}, []string{"app"}, nil),
		WireGuardClientProblem(peer, []string{"pool"}, []string{canary}, nil),
	} {
		if problem == "" || len(problem) > 256 || strings.Contains(problem, "input-canary") {
			t.Fatal("diagnostic retains invalid input")
		}
	}
}
