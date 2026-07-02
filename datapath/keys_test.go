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
	"encoding/binary"
	"net"
	"testing"
)

// The eBPF programs read IPv4 addresses straight out of the packet
// (`ip->daddr`), i.e. in network byte order. The map keys the Go side writes
// must therefore marshal to the same network-order bytes, whatever the host
// endianness. These tests assert that on-wire layout (not the particular
// helper used to produce it), so an accidental endianness "fix" fails loudly.

func networkOrder(t *testing.T, key uint32) [4]byte {
	t.Helper()
	var buf [4]byte
	// The map is serialized in the host's native endianness; reading the key
	// back the same way must reproduce the network-order address bytes.
	binary.NativeEndian.PutUint32(buf[:], key)
	return buf
}

func TestLocalKeyIsNetworkOrderAndScoped(t *testing.T) {
	ip := net.ParseIP("10.20.30.40")
	key := localKey(101, ip)
	if key.Net != 101 {
		t.Fatalf("localKey net = %d, want 101", key.Net)
	}
	got := networkOrder(t, key.Ip)
	want := [4]byte{10, 20, 30, 40}
	if got != want {
		t.Fatalf("localKey(%s) IP marshals to %v, want network order %v", ip, got, want)
	}
}

func TestLpmKeyNetworkOrderPrefixAndScope(t *testing.T) {
	key, err := lpmKey(101, "10.20.30.0/24")
	if err != nil {
		t.Fatalf("lpmKey: %v", err)
	}
	// The scope net occupies the leading 32 key bits, so a /24 CIDR has
	// prefixlen 32 + 24 and lookups never cross scopes.
	if key.Prefixlen != 32+24 {
		t.Fatalf("prefixlen = %d, want %d", key.Prefixlen, 32+24)
	}
	if key.ScopeNet != 101 {
		t.Fatalf("scope = %d, want 101", key.ScopeNet)
	}
	got := networkOrder(t, key.Addr)
	want := [4]byte{10, 20, 30, 0}
	if got != want {
		t.Fatalf("lpmKey addr marshals to %v, want network order %v", got, want)
	}
}

func TestLpmKeyRejectsNonIPv4AndGarbage(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/64", "not-a-cidr", "10.0.0.0/33"} {
		if _, err := lpmKey(0, cidr); err == nil {
			t.Errorf("lpmKey(%q) = nil error, want error", cidr)
		}
	}
}
