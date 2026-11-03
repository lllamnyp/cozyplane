package datapath

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// Exercise the actual continuation as well as the wrapper: internal DNS must
// be redirected to the isolated resolver, never admitted to the wire backend.
func TestBoundaryPacketDNSAfterSocketLB(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			dns := net.ParseIP("10.96.0.10")
			backend := net.ParseIP("10.244.1.53")
			node := net.ParseIP("192.0.2.10")
			fabric := net.ParseIP("10.244.2.10")
			family := uint32(0)
			sourceOffset, destinationOffset, portOffset := 26, 30, 36
			if ipv6 {
				dns, backend = net.ParseIP("fd96::a"), net.ParseIP("fd24::53")
				node, fabric = net.ParseIP("2001:db8::10"), net.ParseIP("fd24:2::10")
				family = 1
				sourceOffset, destinationOffset, portOffset = 22, 38, 56
				boundaryPacketPut(t, f.objects.NodeIp6, uint32(0), boundaryPacketAddress(t, node))
			} else {
				boundaryPacketPut(t, f.objects.Params, cfgNodeIP, binary.NativeEndian.Uint32(node.To4()))
				node, fabric = node.To4(), fabric.To4()
			}
			boundaryPacketPut(t, f.objects.Params, cfgResolverPort, uint32(ResolverPort))
			boundaryPacketPut(t, f.objects.DnsIps, family, boundaryPacketAddress(t, dns))
			boundaryPacketPut(t, f.objects.Internal, overlayLpmKey{Prefixlen: 160, Addr: boundaryPacketAddress(t, backend)}, uint8(1))
			boundaryPacketPut(t, f.objects.FabricOf, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, f.a)}, boundaryPacketAddress(t, fabric))
			boundaryPacketPut(t, f.objects.Ports, f.ifindex, uint32(1))
			boundaryPacketPut(t, f.objects.LbProg, uint32(4), uint32(f.objects.CozyplaneFromPodContinue.FD()))
			for _, protocol := range []uint8{6, 17} {
				for _, destination := range []net.IP{dns, backend} {
					packet := boundaryPacket(f.a, destination, protocol, 42000, 53, 2)
					action, rewritten, err := f.objects.CozyplaneFromPod.Test(packet)
					if err != nil {
						t.Fatal(err)
					}
					if action != 0 || !bytes.Equal(rewritten[sourceOffset:sourceOffset+len(fabric)], fabric) ||
						!bytes.Equal(rewritten[destinationOffset:destinationOffset+len(node)], node) ||
						binary.BigEndian.Uint16(rewritten[portOffset:portOffset+2]) != ResolverPort {
						t.Fatalf("proto=%d destination=%s action=%d: query was not redirected to the isolated resolver", protocol, destination, action)
					}
				}
				f.verdict(t, false, 1, boundaryPacket(f.a, backend, protocol, 42000, 54, 2), 2)
				f.verdict(t, false, 1, boundaryPacket(f.a, f.world, protocol, 42000, 53, 2), 2)
				// Even an internal peer destination remains subject to its boundary.
				boundaryPacketPut(t, f.objects.Internal, overlayLpmKey{Prefixlen: 160, Addr: boundaryPacketAddress(t, f.b)}, uint8(1))
				f.verdict(t, false, 1, boundaryPacket(f.a, f.b, protocol, 42000, 53, 2), 2)
			}
			f.verdict(t, false, 1, boundaryPacket(f.a, backend, 6, 42000, 443, 2), 2)
			boundaryPacketPut(t, f.objects.Params, cfgResolverPort, uint32(0))
			f.verdict(t, false, 1, boundaryPacket(f.a, backend, 17, 42000, 53, 0), 2)
		})
	}
}
