package datapath

import (
	"encoding/binary"
	"net"
	"testing"
)

func boundaryNeighborPacket(src, dst, target net.IP, kind byte) []byte {
	packet := make([]byte, 14+40+24)
	copy(packet[:6], []byte{0x33, 0x33, 0xff, 0, 0, 1})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip, body := packet[14:54], packet[54:]
	ip[0], ip[6], ip[7] = 0x60, 58, 255
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(body)))
	copy(ip[8:24], src.To16())
	copy(ip[24:40], dst.To16())
	body[0] = kind
	copy(body[8:24], target.To16())
	pseudo := make([]byte, 40)
	copy(pseudo[:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(body)))
	pseudo[39] = 58
	binary.BigEndian.PutUint16(body[2:4], boundaryPacketChecksum(append(pseudo, body...)))
	return packet
}

func TestBoundaryPacketIPv6NeighborDiscoveryKeepsGatewayReachable(t *testing.T) {
	f := newBoundaryPacketFixture(t, true)
	linkLocal, gateway := net.ParseIP("fe80::2"), net.ParseIP("fe80::1")
	multicast := net.ParseIP("ff02::1:ff00:1")
	for _, tc := range []struct {
		name   string
		packet []byte
		mutate func([]byte) []byte
		want   uint32
	}{
		{"link-local solicitation", boundaryNeighborPacket(linkLocal, multicast, gateway, 135), nil, 0},
		{"link-local advertisement", boundaryNeighborPacket(linkLocal, gateway, linkLocal, 136), nil, 0},
		{"DAD unspecified source", boundaryNeighborPacket(net.IPv6zero, net.ParseIP("ff02::1:ff00:10"), f.a, 135), nil, 0},
		{"wrong hop limit", boundaryNeighborPacket(linkLocal, multicast, gateway, 135), func(p []byte) []byte { p[21] = 64; return p }, 2},
		{"wrong code", boundaryNeighborPacket(linkLocal, multicast, gateway, 135), func(p []byte) []byte { p[55] = 1; return p }, 2},
		{"short declared payload", boundaryNeighborPacket(linkLocal, multicast, gateway, 135), func(p []byte) []byte { binary.BigEndian.PutUint16(p[18:20], 23); return p }, 2},
		{"truncated body", boundaryNeighborPacket(linkLocal, multicast, gateway, 135), func(p []byte) []byte { return p[:len(p)-1] }, 2},
		{"multicast target", boundaryNeighborPacket(linkLocal, multicast, multicast, 135), nil, 2},
		{"global destination", boundaryNeighborPacket(linkLocal, f.world, gateway, 135), nil, 2},
		{"global-scope multicast", boundaryNeighborPacket(linkLocal, net.ParseIP("ff0e::1"), gateway, 135), nil, 2},
		{"echo is data", boundaryPacket(linkLocal, gateway, 58, 12, 0x8000, 0), nil, 2},
		{"UDP is data", boundaryPacket(linkLocal, gateway, 17, 42000, 443, 0), nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := tc.packet
			if tc.mutate != nil {
				packet = tc.mutate(packet)
			}
			f.verdict(t, false, 1, packet, tc.want)
		})
	}
	if err := f.objects.LbProg.Delete(uint32(4)); err != nil {
		t.Fatal(err)
	}
	t.Run("solicitation without continuation", func(t *testing.T) {
		f.verdict(t, false, 1, boundaryNeighborPacket(linkLocal, multicast, gateway, 135), 0)
	})
	t.Run("data without continuation stays closed", func(t *testing.T) {
		f.verdict(t, false, 1, boundaryPacket(f.a, f.b, 6, 42000, 443, 2), 2)
	})
}
