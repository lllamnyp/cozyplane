package main

import (
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"net"
	"testing"
)

func TestMalformedStoredGroupPortsNeverCompileWildcard(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.0.2.0/24")
	for _, test := range []struct {
		protocol string
		port     int32
		valid    bool
	}{{"TCP", 0, true}, {"UDP", 65535, true}, {"TCP", 65536, false}, {"UDP", -1, false}, {"TCP", 2147483647, false}, {"invalid", 80, false}} {
		ports := []sdnv1alpha1.SecurityGroupPort{{Protocol: test.protocol, Port: test.port}}
		ingress := compileRulePorts(100, 100, 1, 2, ports)
		egress := compileEgressPorts(100, 100, 1, 2, ports)
		cidrIngress := compileCidrPorts(100, cidr, 2, ports)
		cidrEgress := compileEgressCidrPorts(100, cidr, 2, ports)
		want := 0
		if test.valid {
			want = 1
		}
		for path, count := range map[string]int{"ingress": len(ingress), "egress": len(egress), "cidrIngress": len(cidrIngress), "cidrEgress": len(cidrEgress)} {
			if count != want {
				t.Fatal("malformed stored rule broadened permissions", path, test, count)
			}
		}
		if test.valid && (ingress[0].Port != uint16(test.port) || egress[0].Port != uint16(test.port) || cidrIngress[0].Port != uint16(test.port) || cidrEgress[0].Port != uint16(test.port)) {
			t.Fatal("valid port changed")
		}
	}
}
