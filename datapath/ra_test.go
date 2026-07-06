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

// icmp6Checksum recomputes the ICMPv6 checksum of a full ethernet frame
// independently of the builder under test.
func icmp6Checksum(f []byte) uint16 {
	ip := f[14:54]
	payload := f[54:]
	var sum uint32
	add16 := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add16(ip[8:40]) // src + dst
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(len(payload)))
	add16(ln[:])
	add16([]byte{0, 58})
	add16(payload)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

func TestRAFrame(t *testing.T) {
	mac, _ := net.ParseMAC("0e:bb:38:b6:63:6e")
	pod := net.ParseIP("fd00:a::2")
	dns := net.ParseIP("fd00:10:96::a")

	for _, tc := range []struct {
		name  string
		rdnss net.IP
	}{{"no-rdnss", nil}, {"rdnss", dns}} {
		f := raFrame(mac, pod, 1450, tc.rdnss)

		if got := binary.BigEndian.Uint16(f[12:14]); got != 0x86dd {
			t.Fatalf("%s: ethertype %#x", tc.name, got)
		}
		payloadLen := int(binary.BigEndian.Uint16(f[18:20]))
		if want := len(f) - 54; payloadLen != want {
			t.Fatalf("%s: payload length %d, frame carries %d", tc.name, payloadLen, want)
		}
		if f[20] != 58 || f[21] != 255 {
			t.Fatalf("%s: next-header/hop-limit %d/%d", tc.name, f[20], f[21])
		}
		if !net.IP(f[22:38]).Equal(net.ParseIP("fe80::1")) {
			t.Fatalf("%s: source %v", tc.name, net.IP(f[22:38]))
		}
		ra := f[54:]
		if ra[0] != 134 || ra[1] != 0 {
			t.Fatalf("%s: type/code %d/%d", tc.name, ra[0], ra[1])
		}
		if ra[5] != 0xc0 {
			t.Fatalf("%s: M/O flags %#x", tc.name, ra[5])
		}
		// The checksum over a frame including its checksum field must fold to
		// 0xffff.
		if got := icmp6Checksum(f); got != 0xffff {
			t.Fatalf("%s: checksum folds to %#x, want 0xffff", tc.name, got)
		}
		// PIO carries the pod address at /128.
		pio := ra[16:48]
		if pio[0] != 3 || pio[2] != 128 || !net.IP(pio[16:32]).Equal(pod) {
			t.Fatalf("%s: PIO %v", tc.name, pio)
		}
	}
}

func TestBuildDHCP6Reply(t *testing.T) {
	mac, _ := net.ParseMAC("0e:bb:38:b6:63:6e")
	pod := net.ParseIP("fd00:a::2")

	// A minimal SOLICIT: type+txid, CLIENTID, IA_NA(iaid=0x01020304).
	sol := []byte{1, 0xaa, 0xbb, 0xcc}
	sol = appendOpt(sol, dhcp6OptClientID, []byte{0, 1, 0, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
	iana := make([]byte, 12)
	copy(iana[0:4], []byte{1, 2, 3, 4})
	sol = appendOpt(sol, dhcp6OptIANA, iana)

	rep := buildDHCP6Reply(sol, mac, pod, nil)
	if rep == nil || rep[0] != dhcp6Advertise {
		t.Fatalf("want ADVERTISE, got %v", rep)
	}
	if string(rep[1:4]) != string(sol[1:4]) {
		t.Fatalf("txid not echoed")
	}
	// The advertised IA_NA must contain the pod address with the echoed iaid.
	found := false
	for opts := rep[4:]; len(opts) >= 4; {
		code := binary.BigEndian.Uint16(opts[0:2])
		olen := int(binary.BigEndian.Uint16(opts[2:4]))
		body := opts[4 : 4+olen]
		if code == dhcp6OptIANA {
			if string(body[0:4]) != "\x01\x02\x03\x04" {
				t.Fatalf("iaid not echoed: %v", body[0:4])
			}
			addr := body[12+4 : 12+4+16]
			if !net.IP(addr).Equal(pod) {
				t.Fatalf("leased %v, want %v", net.IP(addr), pod)
			}
			found = true
		}
		opts = opts[4+olen:]
	}
	if !found {
		t.Fatalf("no IA_NA in reply")
	}
}
