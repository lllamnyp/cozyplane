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

package route

import (
	"context"
	"testing"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

func TestValidateRoute(t *testing.T) {
	nat := sdn.RouteTarget{NATGateway: &sdn.LocalNATGatewayRef{Name: "egress"}}
	for _, tc := range []struct {
		name string
		spec sdn.RouteSpec
		ok   bool
	}{
		{"valid NAT route", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "0.0.0.0/0", Target: nat}, true},
		{"valid v6 blackhole", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "2001:db8::/32",
			Target: sdn.RouteTarget{Blackhole: &sdn.RouteBlackholeTarget{}}}, true},
		{"host bits set", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "192.0.2.1/24", Target: nat}, false},
		{"not a CIDR", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "192.0.2.1", Target: nat}, false},
		{"no target", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "0.0.0.0/0"}, false},
		{"two targets", sdn.RouteSpec{RouteTableRef: sdn.LocalRouteTableRef{Name: "main"}, Destination: "0.0.0.0/0",
			Target: sdn.RouteTarget{NATGateway: nat.NATGateway, Internet: &sdn.RouteInternetTarget{}}}, false},
		{"no table", sdn.RouteSpec{Destination: "0.0.0.0/0", Target: nat}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			errs := NewStrategy(nil).Validate(context.Background(), &sdn.Route{Spec: tc.spec})
			if (len(errs) == 0) != tc.ok {
				t.Errorf("errors = %v, want ok=%v", errs, tc.ok)
			}
		})
	}
}
