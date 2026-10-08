package main

import (
	"net"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestGroupPeerReferenceBounds(t *testing.T) {
	name := strings.Repeat("a.", 126) + "a"
	for _, test := range []struct {
		name  string
		peer  sdn.SecurityGroupPeer
		valid bool
	}{
		{"local", sdn.SecurityGroupPeer{Group: "policy"}, true},
		{"maximum", sdn.SecurityGroupPeer{Group: name, VPC: &sdn.VPCRef{Namespace: strings.Repeat("a", 63), Name: name}}, true},
		{"empty", sdn.SecurityGroupPeer{}, false},
		{"large group", sdn.SecurityGroupPeer{Group: strings.Repeat("x", 128<<10)}, false},
		{"bad group", sdn.SecurityGroupPeer{Group: "bad/name"}, false},
		{"empty peer", sdn.SecurityGroupPeer{Group: "policy", VPC: &sdn.VPCRef{}}, false},
		{"large namespace", sdn.SecurityGroupPeer{Group: "policy", VPC: &sdn.VPCRef{Namespace: strings.Repeat("x", 128<<10), Name: "net"}}, false},
		{"large VPC", sdn.SecurityGroupPeer{Group: "policy", VPC: &sdn.VPCRef{Namespace: "tenant-b", Name: strings.Repeat("x", 128<<10)}}, false},
		{"mixed CIDR", sdn.SecurityGroupPeer{Group: "policy", CIDR: "0.0.0.0/0"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validGroupPeerReference(test.peer); got != test.valid {
				t.Fatalf("reference validity = %v, want %v", got, test.valid)
			}
		})
	}
}

func TestSecurityGroupCompilersRejectPortNarrowing(t *testing.T) {
	_, cidr, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		compile func([]sdn.SecurityGroupPort) bool
	}{
		{"ingress group", func(ports []sdn.SecurityGroupPort) bool {
			rows := compileRulePorts(100, 100, 1, 2, ports)
			return len(rows) == 1 && rows[0].Port == 80
		}},
		{"egress group", func(ports []sdn.SecurityGroupPort) bool {
			rows := compileEgressPorts(100, 100, 1, 2, ports)
			return len(rows) == 1 && rows[0].Port == 80
		}},
		{"ingress CIDR", func(ports []sdn.SecurityGroupPort) bool {
			rows := compileCidrPorts(100, cidr, 2, ports)
			return len(rows) == 1 && rows[0].Port == 80
		}},
		{"egress CIDR", func(ports []sdn.SecurityGroupPort) bool {
			rows := compileEgressCidrPorts(100, cidr, 2, ports)
			return len(rows) == 1 && rows[0].Port == 80
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ports := []sdn.SecurityGroupPort{{Protocol: "TCP", Port: 65536}, {Protocol: "UDP", Port: -1}, {Protocol: "TCP", Port: 2147483647}, {Protocol: "TCP", Port: 80}}
			if !test.compile(ports) {
				t.Fatal("invalid port was narrowed into a datapath rule or valid port disappeared")
			}
		})
	}
}
