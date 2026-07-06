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
