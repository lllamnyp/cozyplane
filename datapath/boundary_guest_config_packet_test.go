package datapath

import (
	"encoding/binary"
	"net"
	"testing"
)

func boundaryDHCP6Packet(src, dst net.IP, sport, dport uint16) []byte {
	p := append(boundaryPacket(src, dst, 17, sport, dport, 0), 1, 0, 0, 1)
	binary.BigEndian.PutUint16(p[18:20], 12)
	binary.BigEndian.PutUint16(p[58:60], 12)
	p[60], p[61] = 0, 0
	pseudo := make([]byte, 40)
	copy(pseudo[:16], src.To16())
	copy(pseudo[16:32], dst.To16())
	binary.BigEndian.PutUint32(pseudo[32:36], 12)
	pseudo[39] = 17
	binary.BigEndian.PutUint16(p[60:62], boundaryPacketChecksum(append(pseudo, p[54:]...)))
	return p
}

func TestBoundaryPacketIPv6GuestConfiguration(t *testing.T) {
	f := newBoundaryPacketFixture(t, true)
	link, gateway := net.ParseIP("fe80::2"), net.ParseIP("fe80::1")
	routers, servers := net.ParseIP("ff02::2"), net.ParseIP("ff02::1:2")
	rs := func(src, dst net.IP) []byte {
		p := boundaryPacket(src, dst, 58, 0, 133<<8, 0)
		p[21] = 255
		return p
	}
	wrongHop := rs(link, routers)
	wrongHop[21] = 64
	wrongCode := rs(link, routers)
	wrongCode[55] = 1
	wrongLength := boundaryDHCP6Packet(link, servers, 546, 547)
	binary.BigEndian.PutUint16(wrongLength[58:60], 8)
	truncated := boundaryDHCP6Packet(link, servers, 546, 547)
	truncated = truncated[:len(truncated)-1]
	for _, tc := range []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{"router solicitation", rs(link, routers), 0},
		{"unspecified router solicitation", rs(net.IPv6zero, routers), 0},
		{"DHCPv6 multicast", boundaryDHCP6Packet(link, servers, 546, 547), 0},
		{"DHCPv6 renewal", boundaryDHCP6Packet(link, gateway, 546, 547), 0},
		{"global source solicitation", rs(f.world, routers), 2},
		{"wrong multicast router", rs(link, net.ParseIP("ff02::3")), 2},
		{"wrong solicitation hop limit", wrongHop, 2},
		{"wrong solicitation code", wrongCode, 2},
		{"wrong DHCP client port", boundaryDHCP6Packet(link, servers, 545, 547), 2},
		{"wrong DHCP server port", boundaryDHCP6Packet(link, servers, 546, 548), 2},
		{"global DHCP destination", boundaryDHCP6Packet(link, f.world, 546, 547), 2},
		{"global multicast DHCP", boundaryDHCP6Packet(link, net.ParseIP("ff0e::1:2"), 546, 547), 2},
		{"unspecified DHCP source", boundaryDHCP6Packet(net.IPv6zero, servers, 546, 547), 2},
		{"global DHCP source", boundaryDHCP6Packet(f.world, servers, 546, 547), 2},
		{"short DHCP message", boundaryPacket(link, servers, 17, 546, 547, 0), 2},
		{"inconsistent DHCP length", wrongLength, 2},
		{"truncated DHCP message", truncated, 2},
		{"router advertisement from guest", boundaryPacket(link, routers, 58, 0, 134<<8, 0), 2},
		{"link-local data", boundaryPacket(link, gateway, 17, 42000, 443, 0), 2},
	} {
		t.Run(tc.name, func(t *testing.T) { f.verdict(t, false, 1, tc.packet, tc.want) })
	}
	if err := f.objects.LbProg.Delete(uint32(4)); err != nil {
		t.Fatal(err)
	}
	f.verdict(t, false, 1, rs(link, routers), 0)
	f.verdict(t, false, 1, boundaryDHCP6Packet(link, servers, 546, 547), 0)
	f.verdict(t, false, 1, boundaryPacket(f.a, f.b, 6, 42000, 443, 2), 2)
}
