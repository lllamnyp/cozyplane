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

package sdn

import (
	"k8s.io/apimachinery/pkg/util/validation"
	"testing"
)

func TestIPv6ClaimNamesAreDNSSubdomains(t *testing.T) {
	names := make(map[string]string)
	for _, ip := range []string{"::", "::1", "::2", "fd00:1::", "fd00:2::", "fd00::1", "fd00:a::2", "10.0.0.2"} {
		for _, name := range []string{PortName(100, ip), ServiceVIPName(100, ip)} {
			if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
				t.Errorf("%s: invalid claim %q: %v", ip, name, errs)
			}
			if previous, found := names[name]; found {
				t.Errorf("collision %s / %s", previous, ip)
			}
			names[name] = ip
		}
	}
}

func TestClaimNames(t *testing.T) {
	if got := PortName(100, "10.10.0.2"); got != "v100.10-10-0-2" {
		t.Errorf("PortName v4 = %q", got)
	}
	if got := PortName(100, "fd00:a::2"); got != "v100.fd00-a--2" {
		t.Errorf("PortName v6 = %q", got)
	}
	if got := ServiceVIPName(105, "10.0.0.254"); got != "sv105.10-0-0-254" {
		t.Errorf("ServiceVIPName v4 = %q", got)
	}
	if got := ServiceVIPName(105, "fd00:a::fffe"); got != "sv105.fd00-a--fffe" {
		t.Errorf("ServiceVIPName v6 = %q", got)
	}
}

func TestParseClaim(t *testing.T) {
	cases := []struct {
		prefix, name string
		vni          int32
		esc          string
		ok           bool
	}{
		{ClaimPrefixPort, "v100.10-10-0-2", 100, "10-10-0-2", true},
		{ClaimPrefixPort, "v105.fd00-a--2", 105, "fd00-a--2", true},
		{ClaimPrefixServiceVIP, "sv105.10-0-0-254", 105, "10-0-0-254", true},
		{ClaimPrefixPort, "sv105.10-0-0-254", 0, "", false}, // wrong kind
		{ClaimPrefixServiceVIP, "v105.10-0-0-2", 0, "", false},
		{ClaimPrefixPort, "v0.10-0-0-2", 0, "", false},  // VNI 0 reserved
		{ClaimPrefixPort, "v-1.10-0-0-2", 0, "", false}, // negative
		{ClaimPrefixPort, "v105.", 0, "", false},        // empty address half
		{ClaimPrefixPort, "v.10-0-0-2", 0, "", false},   // empty VNI half
		{ClaimPrefixPort, "v5x10-0-0-2", 0, "", false},  // no dot
		{ClaimPrefixPort, "web", 0, "", false},
		{ClaimPrefixPort, "", 0, "", false},
	}
	for _, c := range cases {
		vni, esc, ok := ParseClaim(c.prefix, c.name)
		if vni != c.vni || esc != c.esc || ok != c.ok {
			t.Errorf("ParseClaim(%q, %q) = (%d, %q, %v), want (%d, %q, %v)",
				c.prefix, c.name, vni, esc, ok, c.vni, c.esc, c.ok)
		}
	}
}

// The claim is only sound if the round trip is exact: a valid name parses back
// to halves that rebuild the identical name.
func TestClaimRoundTrip(t *testing.T) {
	for _, ip := range []string{"10.0.0.2", "192.168.255.254", "fd00::1", "fd00:a:b::ff"} {
		name := PortName(107, ip)
		vni, _, ok := ParseClaim(ClaimPrefixPort, name)
		if !ok || PortName(vni, ip) != name {
			t.Errorf("Port round trip failed for %s: %q", ip, name)
		}
		vname := ServiceVIPName(107, ip)
		vvni, _, vok := ParseClaim(ClaimPrefixServiceVIP, vname)
		if !vok || ServiceVIPName(vvni, ip) != vname {
			t.Errorf("ServiceVIP round trip failed for %s: %q", ip, vname)
		}
	}
}
