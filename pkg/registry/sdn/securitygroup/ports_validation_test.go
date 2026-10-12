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

package securitygroup

import (
	"context"
	"math"
	"strconv"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func TestSecurityGroupExplicitPortsAreBounded(t *testing.T) {
	for _, direction := range []string{"ingress", "egress"} {
		for _, protocol := range []string{"TCP", "UDP", "", "ICMP", "tcp"} {
			for _, port := range []int32{-1, 0, 1, 65535, 65536, math.MaxInt32} {
				t.Run(direction+"/"+protocol+"/"+fmtPort(port), func(t *testing.T) {
					sg := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: "test"}}}
					ports := []sdn.SecurityGroupPort{{Protocol: protocol, Port: port}}
					if direction == "ingress" {
						sg.Spec.Ingress = []sdn.SecurityGroupRule{{From: sdn.SecurityGroupPeer{CIDR: "10.0.0.0/24"}, Ports: ports}}
					} else {
						sg.Spec.Egress = []sdn.SecurityGroupEgressRule{{To: sdn.SecurityGroupPeer{CIDR: "10.0.0.0/24"}, Ports: ports}}
					}
					valid := (protocol == "TCP" || protocol == "UDP") && port >= 0 && port <= 65535
					strategy := NewStrategy(nil, nil)
					old := &sdn.SecurityGroup{Spec: sdn.SecurityGroupSpec{VPCRef: sg.Spec.VPCRef}}
					for _, errs := range []field.ErrorList{strategy.Validate(context.Background(), sg), strategy.ValidateUpdate(context.Background(), sg, old)} {
						if (len(errs) == 0) != valid {
							t.Fatalf("protocol %q port %d: errors %v, valid %v", protocol, port, errs, valid)
						}
					}
				})
			}
		}
	}
}

func fmtPort(port int32) string {
	return strconv.FormatInt(int64(port), 10)
}
