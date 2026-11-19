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

package datapath

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func testRoute(dst string, gw string, link int) netlink.Route {
	r := netlink.Route{LinkIndex: link}
	if dst != "" {
		_, n, err := net.ParseCIDR(dst)
		if err != nil {
			panic(err)
		}
		r.Dst = n
	}
	if gw != "" {
		r.Gw = net.ParseIP(gw)
	}
	return r
}

// TestDefaultRouteIn checks only a 0.0.0.0/0 route with a gateway counts as the default route.
func TestDefaultRouteIn(t *testing.T) {
	cases := []struct {
		name   string
		routes []netlink.Route
		want   int
		ok     bool
	}{
		{"none", nil, 0, false},
		{"nil destination with a gateway", []netlink.Route{testRoute("", "10.0.0.1", 2)}, 2, true},
		{"0.0.0.0/0 with a gateway", []netlink.Route{testRoute("10.0.0.0/24", "", 2), testRoute("0.0.0.0/0", "10.0.0.1", 3)}, 3, true},
		{"0.0.0.0/0 without a gateway", []netlink.Route{testRoute("0.0.0.0/0", "", 2)}, 0, false},
		{"four /2 routes are not a default route", []netlink.Route{
			testRoute("0.0.0.0/2", "10.0.0.1", 2),
			testRoute("64.0.0.0/2", "10.0.1.1", 3),
			testRoute("128.0.0.0/2", "10.0.2.1", 4),
			testRoute("192.0.0.0/2", "10.0.3.1", 5),
		}, 0, false},
	}
	for _, c := range cases {
		got, ok := defaultRouteIn(c.routes)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: defaultRouteIn = (%d, %v), want (%d, %v)", c.name, got, ok, c.want, c.ok)
		}
	}
}
