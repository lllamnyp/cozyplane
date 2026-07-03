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

// The eBPF programs read addresses straight out of the packet, in network byte
// order, into a 16-byte struct addr128. The Go side stores addresses in the same
// 16-byte network-order layout (a byte array — inherently endianness-free), a v4
// address in its RFC 6052 NAT64 form 64:ff9b::a.b.c.d. These tests lock that
// layout and the NAT64 mapping so a drift from bpf/overlay.c's v4_to_128 fails
// loudly, and confirm v6 CIDRs are accepted natively (dual-stack).

func TestLocalKeyIsNat64MappedAndScoped(t *testing.T) {
	key, err := localKey(101, net.ParseIP("10.20.30.40"))
	if err != nil {
		t.Fatalf("localKey: %v", err)
	}
	if key.Net != 101 {
		t.Fatalf("localKey net = %d, want 101", key.Net)
	}
	want := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 20, 30, 40}
	if key.Ip.B != want {
		t.Fatalf("localKey IP = %v, want NAT64-mapped %v", key.Ip.B, want)
	}
}

func TestLpmKeyV4IsNat64MappedPrefixAndScope(t *testing.T) {
	key, err := lpmKey(101, "10.20.30.0/24")
	if err != nil {
		t.Fatalf("lpmKey: %v", err)
	}
	// scope(32) + NAT64 prefix(96) + v4 ones(24); lookups never cross scopes.
	if key.Prefixlen != 32+96+24 {
		t.Fatalf("prefixlen = %d, want %d", key.Prefixlen, 32+96+24)
	}
	if key.ScopeNet != 101 {
		t.Fatalf("scope = %d, want 101", key.ScopeNet)
	}
	want := [16]byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 10, 20, 30, 0}
	if key.Addr.B != want {
		t.Fatalf("lpmKey addr = %v, want %v", key.Addr.B, want)
	}
}

func TestLpmKeyV6IsNativePrefixAndScope(t *testing.T) {
	key, err := lpmKey(7, "2001:db8:abcd::/48")
	if err != nil {
		t.Fatalf("lpmKey v6: %v", err)
	}
	// scope(32) + v6 ones(48). No NAT64 prefix for a native v6 CIDR.
	if key.Prefixlen != 32+48 {
		t.Fatalf("prefixlen = %d, want %d", key.Prefixlen, 32+48)
	}
	want := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd}
	if key.Addr.B != want {
		t.Fatalf("lpmKey v6 addr = %v, want %v", key.Addr.B, want)
	}
}

func TestLpmKeyRejectsGarbage(t *testing.T) {
	for _, cidr := range []string{"not-a-cidr", "10.0.0.0/33", "2001:db8::/129"} {
		if _, err := lpmKey(0, cidr); err == nil {
			t.Errorf("lpmKey(%q) = nil error, want error", cidr)
		}
	}
}

// addr128 <-> IP round-trips for both families (v4 via NAT64, v6 native).
func TestAddr128RoundTrips(t *testing.T) {
	for _, s := range []string{"10.20.30.40", "2001:db8::1"} {
		a, err := addr128Str(s)
		if err != nil {
			t.Fatalf("addr128Str(%q): %v", s, err)
		}
		if got := addr128ToIP(a).String(); got != net.ParseIP(s).String() {
			t.Errorf("addr128 round-trip %q -> %q", s, got)
		}
	}
}
