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
	"math"
	"net"
	"strconv"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func TestSecurityGroupPortCompilersFailClosed(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("10.0.0.0/24")
	for _, protocol := range []string{"TCP", "UDP", "", "ICMP", "tcp"} {
		for _, port := range []int32{-1, 0, 1, 65535, 65536, 65537, math.MaxInt32} {
			t.Run(protocol+"/"+strconv.FormatInt(int64(port), 10), func(t *testing.T) {
				ports := []sdnv1alpha1.SecurityGroupPort{{Protocol: protocol, Port: port}}
				valid := (protocol == "TCP" || protocol == "UDP") && port >= 0 && port <= 65535
				got := [][]uint16{{}, {}, {}, {}}
				for _, rule := range compileRulePorts(100, 101, 1, 1, ports) {
					got[0] = append(got[0], rule.Port)
				}
				for _, rule := range compileEgressPorts(100, 101, 1, 1, ports) {
					got[1] = append(got[1], rule.Port)
				}
				for _, rule := range compileCidrPorts(100, cidr, 1, ports) {
					got[2] = append(got[2], rule.Port)
				}
				for _, rule := range compileEgressCidrPorts(100, cidr, 1, ports) {
					got[3] = append(got[3], rule.Port)
				}
				for i, compiled := range got {
					if !valid && len(compiled) != 0 {
						t.Fatalf("compiler %d admitted invalid port %d/%q: %v", i, port, protocol, compiled)
					}
					if valid && (len(compiled) != 1 || int32(compiled[0]) != port) {
						t.Fatalf("compiler %d changed valid port %d: %v", i, port, compiled)
					}
				}
			})
		}
	}
	for i, count := range []int{len(compileRulePorts(100, 101, 1, 1, nil)), len(compileEgressPorts(100, 101, 1, 1, nil)), len(compileCidrPorts(100, cidr, 1, nil)), len(compileEgressCidrPorts(100, cidr, 1, nil))} {
		if count != 2 {
			t.Fatalf("compiler %d removed explicit all-port policy: %d", i, count)
		}
	}
}
