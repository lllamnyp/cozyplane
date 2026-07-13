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

func TestGuestAnnouncedItself(t *testing.T) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}
	other := net.HardwareAddr{0x52, 0x54, 0x00, 0x11, 0x22, 0x33}
	v4 := net.ParseIP("10.70.0.5")
	v6 := net.ParseIP("fd00:70::5")

	// A gratuitous ARP is exactly what garpFrame builds — the parser must
	// accept the announcement form cozyplane itself emits.
	garp := garpFrame(mac, v4.To4())
	na := unsolicitedNAFrame(mac, v6.To16())

	tests := []struct {
		name   string
		frame  []byte
		mac    net.HardwareAddr
		ip     net.IP
		v4     bool
		accept bool
	}{
		{"gratuitous arp match", garp, mac, v4, true, true},
		{"gratuitous arp wrong ip", garp, mac, net.ParseIP("10.70.0.6"), true, false},
		{"gratuitous arp wrong mac", garp, other, v4, true, false},
		{"unsolicited na match", na, mac, v6, false, true},
		{"unsolicited na wrong ip", na, mac, net.ParseIP("fd00:70::6"), false, false},
		{"unsolicited na wrong mac", na, other, v6, false, false},
		{"arp frame under v6 expectation", garp, mac, v6, false, false},
		{"na frame under v4 expectation", na, mac, v4, true, false},
		{"truncated", garp[:20], mac, v4, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := guestAnnouncedItself(tc.frame, tc.mac, tc.ip, tc.v4); got != tc.accept {
				t.Fatalf("guestAnnouncedItself = %v, want %v", got, tc.accept)
			}
		})
	}
}

// garpFrame builds an ARP announcement. It used to live in the datapath (cozyplane
// EMITTED these for floating IPs); cozyplane no longer announces anything
// (docs/north-south.md, tenet 3), but the live-migration listener still has to
// RECOGNISE one when a guest sends it, so the test builds its own.
func garpFrame(mac net.HardwareAddr, ip4 net.IP) []byte {
	f := make([]byte, 42)
	for i := 0; i < 6; i++ {
		f[i] = 0xff // broadcast
	}
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x0806) // ARP
	arp := f[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)      // htype ethernet
	binary.BigEndian.PutUint16(arp[2:4], 0x0800) // ptype IPv4
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 1) // op request (announcement form)
	copy(arp[8:14], mac)                    // sha
	copy(arp[14:18], ip4)                   // spa
	copy(arp[24:28], ip4)                   // tpa
	return f
}

// unsolicitedNAFrame builds an unsolicited Neighbor Advertisement — the v6 twin of
// a gratuitous ARP. Same story as garpFrame: cozyplane no longer emits these, but
// the live-migration listener still has to recognise one from a guest.
func unsolicitedNAFrame(mac net.HardwareAddr, ip6 net.IP) []byte {
	f := make([]byte, 14+40+32)
	copy(f[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}) // all-nodes mcast MAC
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x86dd) // IPv6

	ip := f[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 32) // payload length
	ip[6] = 58                              // ICMPv6
	ip[7] = 255                             // hop limit (NDP requirement)
	copy(ip[8:24], ip6)
	copy(ip[24:40], net.ParseIP("ff02::1"))

	na := f[54:]
	na[0] = 136                                     // neighbor advertisement
	binary.BigEndian.PutUint32(na[4:8], 0x20000000) // override (not solicited)
	copy(na[8:24], ip6)                             // target
	na[24], na[25] = 2, 1                           // target link-layer option
	copy(na[26:32], mac)

	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
	}
	add(ip[8:40])
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], 32)
	add(ln[:])
	add([]byte{0, 58})
	add(na[:32])
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(na[2:4], ^uint16(sum))
	return f
}
