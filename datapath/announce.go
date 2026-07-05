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
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// AnnounceAddress broadcasts a floating address's new location on the uplink:
// a gratuitous ARP (v4, announcement form: request with spa == tpa) or an
// unsolicited Neighbor Advertisement (v6, override flag, to all-nodes).
// Without it, external peers keep resolving the address to the PREVIOUS
// node's MAC until their cache entry expires — the datapath answers new
// queries immediately (floating_arp / floating_ndp), but nothing prompts a
// peer holding a warm cache to re-ask. Best-effort by nature: a lost
// announcement only means waiting out the peer's cache.
func (m *Manager) AnnounceAddress(ip net.IP) error {
	if m.uplinkIfindex == 0 || len(m.uplinkMAC) != 6 {
		return fmt.Errorf("uplink not attached")
	}
	var frame []byte
	if v4 := ip.To4(); v4 != nil {
		frame = garpFrame(m.uplinkMAC, v4)
	} else if v6 := ip.To16(); v6 != nil {
		frame = unsolicitedNAFrame(m.uplinkMAC, v6)
	} else {
		return fmt.Errorf("invalid address %q", ip)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		return fmt.Errorf("packet socket: %w", err)
	}
	defer unix.Close(fd)
	addr := &unix.SockaddrLinklayer{Ifindex: m.uplinkIfindex, Halen: 6}
	copy(addr.Addr[:], frame[0:6]) // the frame's destination
	if err := unix.Sendto(fd, frame, 0, addr); err != nil {
		return fmt.Errorf("send announcement: %w", err)
	}
	return nil
}

// garpFrame builds an ARP announcement: a broadcast ARP request whose sender
// and target protocol addresses are both the announced IP.
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
	copy(arp[24:28], ip4)                   // tpa (tha stays zero)
	return f
}

// unsolicitedNAFrame builds an unsolicited Neighbor Advertisement to
// all-nodes with the override flag and a target link-layer option.
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
	copy(ip[8:24], ip6)                     // src = the announced address
	allNodes := net.ParseIP("ff02::1")
	copy(ip[24:40], allNodes)

	na := f[54:]
	na[0] = 136                                     // neighbor advertisement
	binary.BigEndian.PutUint32(na[4:8], 0x20000000) // override (not solicited)
	copy(na[8:24], ip6)                             // target
	na[24], na[25] = 2, 1                           // target link-layer option
	copy(na[26:32], mac)

	// ICMPv6 checksum over the pseudo-header + payload.
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
	}
	add(ip[8:40]) // src + dst
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], 32)
	add(ln[:])         // upper-layer length
	add([]byte{0, 58}) // next header
	add(na[:32])       // the NA itself (checksum field is zero)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(na[2:4], ^uint16(sum))
	return f
}
