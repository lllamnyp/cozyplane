package datapath

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBoundaryPacketRelatedICMPErrors(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		t.Run(family, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			echoProto, echoType := uint8(1), uint16(8<<8)
			if ipv6 {
				echoProto = 58
				echoType = 128 << 8
			}
			flows := []struct {
				name                string
				protocol            uint8
				source, destination uint16
				flags               uint8
			}{
				{"TCP", 6, 43000, 443, 2}, {"UDP", 17, 43001, 8443, 0}, {"echo", echoProto, 557, echoType, 0},
			}
			types := []uint16{3<<8 | 4, 3<<8 | 3, 11 << 8, 12 << 8}
			if ipv6 {
				types = []uint16{1<<8 | 4, 2 << 8, 3 << 8, 4 << 8}
			}
			for _, flow := range flows {
				t.Run(flow.name, func(t *testing.T) {
					request := boundaryPacket(f.a, f.b, flow.protocol, flow.source, flow.destination, flow.flags)
					f.allow(t, flow.protocol, flow.destination)
					for _, tc := range types {
						errorPacket := boundaryRelatedError(f.b, f.a, tc, request[14:])
						f.verdict(t, false, 2, errorPacket, 2)
						f.verdict(t, true, 1, errorPacket, 2)
					}
					f.verdict(t, false, 1, request, 0)
					// Admission on the source hook alone does not acknowledge the
					// destination hook or its return traffic.
					f.verdict(t, false, 2, boundaryRelatedError(f.b, f.a, types[0], request[14:]), 2)
					f.verdict(t, true, 2, request, 0)
					for _, tc := range types {
						errorPacket := boundaryRelatedError(f.b, f.a, tc, request[14:])
						f.verdict(t, false, 2, errorPacket, 0)
						f.verdict(t, true, 1, errorPacket, 0)
					}
					wrongTuple := boundaryPacket(f.a, f.b, flow.protocol, flow.source+1, flow.destination, flow.flags)
					f.verdict(t, false, 2, boundaryRelatedError(f.b, f.a, types[0], wrongTuple[14:]), 2)
					f.verdict(t, true, 1, boundaryRelatedError(f.b, f.a, types[0], wrongTuple[14:]), 2)
				})
			}
			request := boundaryPacket(f.a, f.b, 6, 43000, 443, 2)
			errorPacket := boundaryRelatedError(f.b, f.a, types[0], request[14:])
			boundaryPacketPut(t, f.objects.BoundaryPolicy, uint32(1), overlayBoundaryPolicy{Revision: 2, Identity: 1})
			f.verdict(t, false, 2, errorPacket, 2)
			f.verdict(t, true, 1, errorPacket, 2)
			f.policies(t)
			boundaryPacketPut(t, f.objects.BoundaryPolicy, uint32(2), overlayBoundaryPolicy{Revision: 1, Identity: 99})
			f.verdict(t, false, 2, errorPacket, 2)
			f.verdict(t, true, 1, errorPacket, 2)
		})
	}
}

func TestBoundaryPacketRelatedICMPRejectsUnverifiableQuotes(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		t.Run(family, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			f.allow(t, 6, 443)
			request := boundaryPacket(f.a, f.b, 6, 44000, 443, 2)
			f.verdict(t, false, 1, request, 0)
			f.verdict(t, true, 2, request, 0)
			tc := uint16(3<<8 | 4)
			if ipv6 {
				tc = 2 << 8
			}
			quote := append([]byte{}, request[14:]...)
			for _, kind := range []string{"truncated", "fragment or extension", "wrong family", "unrelated destination"} {
				t.Run(kind, func(t *testing.T) {
					bad := append([]byte{}, quote...)
					destination := f.a
					switch kind {
					case "truncated":
						bad = bad[:12]
					case "fragment or extension":
						if ipv6 {
							bad[6] = 44
						} else {
							bad[6] = 0x20
						}
					case "wrong family":
						if ipv6 {
							bad[0] = 0x45
						} else {
							bad[0] = 0x60
						}
					case "unrelated destination":
						destination = f.secondary
					}
					packet := boundaryRelatedError(f.b, destination, tc, bad)
					f.verdict(t, false, 2, packet, 2)
					f.verdict(t, true, 1, packet, 2)
				})
			}
		})
	}
}

func TestBoundaryPacketRelatedICMPDoesNotGrantOrProlongFlows(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "IPv4"
		if ipv6 {
			family = "IPv6"
		}
		t.Run(family, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			proto, tc := uint8(1), uint16(3<<8|4)
			if ipv6 {
				proto = 58
				tc = 2 << 8
			}
			// Even an explicit error rule does not authorize a quotation of a
			// flow that never passed the ordinary transport policy.
			boundaryPacketPut(t, f.objects.BoundaryRules, overlayBoundaryRule{Revision: 1, Net: 2, Peer: 1, Port: htons(tc), Proto: proto}, uint8(1))
			boundaryPacketPut(t, f.objects.BoundaryRules, overlayBoundaryRule{Revision: 1, Net: 1, Peer: 2, Port: htons(tc), Proto: proto, Direction: 1}, uint8(1))
			request := boundaryPacket(f.a, f.b, 17, 45000, 8443, 0)
			errorPacket := boundaryRelatedError(f.b, f.a, tc, request[14:])
			f.verdict(t, false, 2, errorPacket, 2)
			f.verdict(t, true, 1, errorPacket, 2)
			f.allow(t, 17, 8443)
			f.verdict(t, false, 1, request, 0)
			f.verdict(t, true, 2, request, 0)
			before := boundaryRelatedState(t, f)
			f.verdict(t, false, 2, errorPacket, 0)
			f.verdict(t, true, 1, errorPacket, 0)
			after := boundaryRelatedState(t, f)
			if len(before) != len(after) {
				t.Fatal("related error created new flow state")
			}
			for key, value := range before {
				if after[key] != value {
					t.Fatal("related error changed or prolonged existing flow state")
				}
			}
			for key, value := range after {
				value.Expires = 1
				boundaryPacketPut(t, f.objects.BoundaryCt, key, value)
			}
			f.verdict(t, false, 2, errorPacket, 2)
			f.verdict(t, true, 1, errorPacket, 2)
		})
	}
}

func boundaryRelatedState(t *testing.T, f *boundaryPacketFixture) map[overlayBoundaryFlow]overlayBoundaryFlowValue {
	t.Helper()
	state := map[overlayBoundaryFlow]overlayBoundaryFlowValue{}
	iterator := f.objects.BoundaryCt.Iterate()
	var key overlayBoundaryFlow
	var value overlayBoundaryFlowValue
	for iterator.Next(&key, &value) {
		state[key] = value
	}
	if err := iterator.Err(); err != nil {
		t.Fatal(err)
	}
	return state
}

func boundaryRelatedError(src, dst net.IP, typeCode uint16, quoted []byte) []byte {
	ipv6 := src.To4() == nil
	protocol, iplen := uint8(1), 20
	if ipv6 {
		protocol = 58
		iplen = 40
	}
	packet := boundaryPacket(src, dst, protocol, 0, typeCode, 0)
	// ICMPv4's required quotation is the original IP header and eight L4 bytes.
	// The same compact quote identifies the ordinary IPv6 flows tested here.
	if len(quoted) > iplen+8 {
		quoted = quoted[:iplen+8]
	}
	packet = append(packet, quoted...)
	ip, l4 := packet[14:14+iplen], packet[14+iplen:]
	l4[2], l4[3] = 0, 0
	if ipv6 {
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(l4)))
		if typeCode == 2<<8 {
			binary.BigEndian.PutUint32(l4[4:8], 1280)
		}
		pseudo := make([]byte, 40)
		copy(pseudo[:16], src.To16())
		copy(pseudo[16:32], dst.To16())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(l4)))
		pseudo[39] = protocol
		binary.BigEndian.PutUint16(l4[2:4], boundaryPacketChecksum(append(pseudo, l4...)))
	} else {
		binary.BigEndian.PutUint16(ip[2:4], uint16(iplen+len(l4)))
		ip[10], ip[11] = 0, 0
		binary.BigEndian.PutUint16(ip[10:12], boundaryPacketChecksum(ip))
		if typeCode == 3<<8|4 {
			binary.BigEndian.PutUint16(l4[6:8], 1280)
		}
		binary.BigEndian.PutUint16(l4[2:4], boundaryPacketChecksum(l4))
	}
	return packet
}
