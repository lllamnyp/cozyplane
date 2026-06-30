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

func TestLocalKeyIsNetworkOrder(t *testing.T) {
	ip := net.ParseIP("10.20.30.40")
	got := networkOrder(t, localKey(ip))
	want := [4]byte{10, 20, 30, 40}
	if got != want {
		t.Fatalf("localKey(%s) marshals to %v, want network order %v", ip, got, want)
	}
}

func TestLpmKeyNetworkOrderAndPrefix(t *testing.T) {
	key, err := lpmKey("10.20.30.0/24")
	if err != nil {
		t.Fatalf("lpmKey: %v", err)
	}
	if key.Prefixlen != 24 {
		t.Fatalf("prefixlen = %d, want 24", key.Prefixlen)
	}
	got := networkOrder(t, key.Addr)
	want := [4]byte{10, 20, 30, 0}
	if got != want {
		t.Fatalf("lpmKey addr marshals to %v, want network order %v", got, want)
	}
}

func TestLpmKeyRejectsNonIPv4AndGarbage(t *testing.T) {
	for _, cidr := range []string{"2001:db8::/64", "not-a-cidr", "10.0.0.0/33"} {
		if _, err := lpmKey(cidr); err == nil {
			t.Errorf("lpmKey(%q) = nil error, want error", cidr)
		}
	}
}
