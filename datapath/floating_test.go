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
)

// The taxonomy of external addresses, and where the floating machinery binds
// for each. The node-owned rows are the regression: lo must never be the
// selected link.
func TestFloatFactsBindLink(t *testing.T) {
	const (
		lo       = 1
		uplink   = 2 // eth0, the default route link; from_uplink already here
		vlan     = 3 // a secondary NIC
		otherNIC = 4
	)

	for _, tc := range []struct {
		name    string
		facts   floatFacts
		want    int
		wantErr bool
	}{{
		// A routed pool: something upstream forwards it to us, so it arrives on
		// the default uplink.
		name:  "routed to us via a gateway",
		facts: floatFacts{RouteLink: uplink, RouteGw: net.ParseIP("10.0.0.1"), DefaultUplink: uplink},
		want:  0,
	}, {
		name:  "on-link on the default uplink",
		facts: floatFacts{RouteLink: uplink, DefaultUplink: uplink},
		want:  0,
	}, {
		// The floating case: an OCI L2 VLAN carries the range while the
		// default route rides the native NIC.
		name:  "on-link on a secondary NIC",
		facts: floatFacts{RouteLink: vlan, DefaultUplink: uplink},
		want:  vlan,
	}, {
		name:  "FIB named no link",
		facts: floatFacts{RouteLink: 0, DefaultUplink: uplink},
		want:  0,
	}, {
		// The FIB says lo; the address lives on eth0, which is already hooked
		// and whose default route resolves an off-subnet reply. Nothing to
		// program.
		name: "node-owned, on the default uplink",
		facts: floatFacts{
			RouteLink: lo, RouteViaLo: true,
			OwnerLink: uplink, DefaultUplink: uplink,
		},
		want: 0,
	}, {
		// Node-owned but on a NIC that is not the default route link: the reply
		// to an off-subnet client cannot be resolved by the FIB out of that
		// link, so the floating machinery must bind there — to the OWNING link,
		// never to lo.
		name: "node-owned, on a secondary NIC",
		facts: floatFacts{
			RouteLink: lo, RouteViaLo: true,
			OwnerLink: otherNIC, DefaultUplink: uplink,
		},
		want: otherNIC,
	}, {
		// The FIB calls it local but no interface admits to carrying it. Refuse
		// loudly rather than bind something arbitrary.
		name: "local but owned by no link",
		facts: floatFacts{
			RouteLink: lo, RouteViaLo: true,
			OwnerLink: 0, DefaultUplink: uplink,
		},
		wantErr: true,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.facts.bindLink()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("bindLink() = %d, nil; want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("bindLink() error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("bindLink() = %d, want %d", got, tc.want)
			}
		})
	}
}

// lo must never be selected, whatever else is true: it has no MAC and no
// covering subnet, so binding it can only produce a black hole.
func TestFloatFactsNeverBindsLoopback(t *testing.T) {
	const lo = 1
	for _, f := range []floatFacts{
		{RouteLink: lo, RouteViaLo: true, OwnerLink: 2, DefaultUplink: 2},
		{RouteLink: lo, RouteViaLo: true, OwnerLink: 3, DefaultUplink: 2},
		{RouteLink: lo, RouteViaLo: true, OwnerLink: lo, DefaultUplink: 2},
	} {
		got, err := f.bindLink()
		if err != nil {
			continue // refusing is always acceptable
		}
		if got == lo {
			t.Fatalf("bindLink() selected the loopback for %+v", f)
		}
	}
}
