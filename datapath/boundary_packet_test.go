package datapath

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

// These tests execute the real boundary wrappers in the kernel. Continuations
// return TC_ACT_OK, so packet verdicts isolate policy from routing and attach no
// program to a host or tenant interface.
type boundaryPacketFixture struct {
	objects                overlayObjects
	a, b, secondary, world net.IP
	ifindex                uint32
}

func newBoundaryPacketFixture(t *testing.T, ipv6 bool) *boundaryPacketFixture {
	t.Helper()
	if os.Getenv("COZYPLANE_REQUIRE_BPF") != "1" {
		t.Skip("requires isolated privileged Linux BPF validation")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	f := &boundaryPacketFixture{a: net.ParseIP("10.60.0.10"), b: net.ParseIP("10.61.0.20"), secondary: net.ParseIP("10.60.0.11"), world: net.ParseIP("203.0.113.80")}
	if ipv6 {
		f.a = net.ParseIP("fd60::10")
		f.b = net.ParseIP("fd61::20")
		f.secondary = net.ParseIP("fd60::11")
		f.world = net.ParseIP("2001:db8:ffff::80")
	}
	if err := spec.LoadAndAssign(&f.objects, nil); err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("kernel verifier: %+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.objects.Close() })
	// SchedCLS test-run supplies a device context. Read its real ifindex rather
	// than assuming zero, which would turn every wrapper invocation into legacy
	// traffic by missing the authoritative ports entry.
	contextProbe, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "boundary_ctx", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.LoadMem(asm.R0, asm.R1, 40, asm.Word), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	f.ifindex, _, err = contextProbe.Test(boundaryPacket(f.a, f.b, 6, 42000, 443, 2))
	_ = contextProbe.Close()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("kernel test context ifindex=%d", f.ifindex)
	continuation, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "boundary_test_ok", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = continuation.Close() })
	for _, slot := range []uint32{4, 5} {
		boundaryPacketPut(t, f.objects.LbProg, slot, uint32(continuation.FD()))
	}
	for _, endpoint := range []struct {
		net uint32
		ip  net.IP
	}{{1, f.a}, {2, f.b}, {1, f.secondary}} {
		boundaryPacketPut(t, f.objects.Locals, overlayLocalKey{Net: endpoint.net, Ip: boundaryPacketAddress(t, endpoint.ip)}, overlayEndpoint{Ifindex: f.ifindex})
	}
	for _, scope := range []uint32{1, 2} {
		for _, peer := range []struct {
			net uint32
			ip  net.IP
		}{{1, f.a}, {2, f.b}} {
			boundaryPacketPut(t, f.objects.Networks, overlayLpmKey{Prefixlen: 160, ScopeNet: scope, Addr: boundaryPacketAddress(t, peer.ip)}, peer.net)
		}
	}
	for _, ip := range []net.IP{f.a, f.b} {
		bits := 64
		mask := net.CIDRMask(64, 128)
		if ip.To4() != nil {
			bits = 120
			mask = net.CIDRMask(24, 32)
			ip = ip.To4()
		}
		boundaryPacketPut(t, f.objects.BoundaryCidrs, overlayBoundaryCidr{Prefixlen: uint32(bits), Addr: boundaryPacketAddress(t, ip.Mask(mask))}, uint8(1))
	}
	f.policies(t)
	return f
}

func boundaryPacketAddress(t *testing.T, ip net.IP) overlayAddr128 {
	t.Helper()
	address, err := addr128(ip)
	if err != nil {
		t.Fatal(err)
	}
	return address
}

func boundaryPacketPut(t *testing.T, m *ebpf.Map, key, value any) {
	t.Helper()
	if err := m.Put(key, value); err != nil {
		t.Fatal(err)
	}
}

func (f *boundaryPacketFixture) policies(t *testing.T) {
	t.Helper()
	for _, n := range []uint32{1, 2} {
		boundaryPacketPut(t, f.objects.BoundaryPolicy, n, overlayBoundaryPolicy{Revision: 1, Identity: uint64(n)})
	}
}

func (f *boundaryPacketFixture) allow(t *testing.T, protocol uint8, port uint16) {
	t.Helper()
	boundaryPacketPut(t, f.objects.BoundaryRules, overlayBoundaryRule{Revision: 1, Net: 1, Peer: 2, Port: htons(port), Proto: protocol}, uint8(1))
	boundaryPacketPut(t, f.objects.BoundaryRules, overlayBoundaryRule{Revision: 1, Net: 2, Peer: 1, Port: htons(port), Proto: protocol, Direction: 1}, uint8(1))
}

func (f *boundaryPacketFixture) verdict(t *testing.T, ingress bool, network uint32, packet []byte, want uint32) {
	t.Helper()
	boundaryPacketPut(t, f.objects.Ports, f.ifindex, network)
	program := f.objects.CozyplaneFromPod
	if ingress {
		program = f.objects.CozyplaneToPod
	}
	got, _, err := program.Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("ingress=%v network=%d action=%d want=%d", ingress, network, got, want)
	}
}

func TestBoundaryPacketTCPAdmissionAndRevocation(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			f.allow(t, 6, 443)
			ack := boundaryPacket(f.a, f.b, 6, 42000, 443, 0x10)
			f.verdict(t, false, 1, ack, 2)
			f.verdict(t, true, 2, ack, 2)
			wrongPort := boundaryPacket(f.a, f.b, 6, 42000, 444, 0x02)
			f.verdict(t, false, 1, wrongPort, 2)
			f.verdict(t, true, 2, wrongPort, 2)
			syn := boundaryPacket(f.a, f.b, 6, 42000, 443, 0x02)
			f.verdict(t, false, 1, syn, 0)
			f.verdict(t, true, 2, syn, 0)
			f.verdict(t, false, 1, ack, 0)
			f.verdict(t, true, 2, ack, 0)
			reply := boundaryPacket(f.b, f.a, 6, 443, 42000, 0x12)
			f.verdict(t, false, 2, reply, 0)
			f.verdict(t, true, 1, reply, 0)
			boundaryPacketPut(t, f.objects.BoundaryPolicy, uint32(1), overlayBoundaryPolicy{Revision: 2, Identity: 1})
			f.verdict(t, false, 1, ack, 2)
			f.verdict(t, true, 2, ack, 2)
			f.verdict(t, false, 2, reply, 2)
			f.verdict(t, true, 1, reply, 2)
		})
	}
}

func TestBoundaryPacketOneMissingPolicyStaysClosed(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			f.allow(t, 6, 443)
			for _, missing := range []uint32{1, 2} {
				f.policies(t)
				if err := f.objects.BoundaryPolicy.Delete(missing); err != nil {
					t.Fatal(err)
				}
				syn := boundaryPacket(f.a, f.b, 6, 42000+uint16(missing), 443, 0x02)
				f.verdict(t, false, 1, syn, 2)
				f.verdict(t, true, 2, syn, 2)
			}
		})
	}
}

func TestBoundaryPacketTrackedUDPAndEchoReplies(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			f.allow(t, 17, 8443)
			udpReply := boundaryPacket(f.b, f.a, 17, 8443, 42000, 0)
			f.verdict(t, false, 2, udpReply, 2)
			f.verdict(t, true, 1, udpReply, 2)
			request := boundaryPacket(f.a, f.b, 17, 42000, 8443, 0)
			f.verdict(t, false, 1, request, 0)
			f.verdict(t, true, 2, request, 0)
			f.verdict(t, false, 2, udpReply, 0)
			f.verdict(t, true, 1, udpReply, 0)
			wrongTuple := boundaryPacket(f.b, f.a, 17, 8443, 42001, 0)
			f.verdict(t, false, 2, wrongTuple, 2)
			f.verdict(t, true, 1, wrongTuple, 2)
			proto, requestType, replyType := uint8(1), uint16(8<<8), uint16(0)
			if ipv6 {
				proto = 58
				requestType = 128 << 8
				replyType = 129 << 8
			}
			f.allow(t, proto, requestType)
			echoReply := boundaryPacket(f.b, f.a, proto, 555, replyType, 0)
			f.verdict(t, false, 2, echoReply, 2)
			f.verdict(t, true, 1, echoReply, 2)
			echoRequest := boundaryPacket(f.a, f.b, proto, 555, requestType, 0)
			f.verdict(t, false, 1, echoRequest, 0)
			f.verdict(t, true, 2, echoRequest, 0)
			f.verdict(t, false, 2, echoReply, 0)
			f.verdict(t, true, 1, echoReply, 0)
			wrongEcho := boundaryPacket(f.b, f.a, proto, 556, replyType, 0)
			f.verdict(t, false, 2, wrongEcho, 2)
			f.verdict(t, true, 1, wrongEcho, 2)
		})
	}
}

func TestBoundaryPacketInternetRequiresPrimaryAndBlocksManagedCIDREscape(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			world := boundaryPacket(f.a, f.world, 6, 42000, 443, 0x02)
			f.verdict(t, false, 1, world, 2)
			boundaryPacketPut(t, f.objects.BoundaryPrimary, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, f.a)}, uint8(1))
			f.verdict(t, false, 1, world, 2)
			boundaryPacketPut(t, f.objects.BoundaryPolicy, uint32(1), overlayBoundaryPolicy{Revision: 1, Identity: 1, Internet: 1})
			f.verdict(t, false, 1, world, 0)
			f.verdict(t, false, 1, boundaryPacket(f.secondary, f.world, 6, 42000, 443, 0x02), 2)
			if err := f.objects.Networks.Delete(overlayLpmKey{Prefixlen: 160, ScopeNet: 1, Addr: boundaryPacketAddress(t, f.b)}); err != nil {
				t.Fatal(err)
			}
			f.verdict(t, false, 1, boundaryPacket(f.a, f.b, 6, 42000, 443, 0x02), 2)
		})
	}
}

// Build ordinary, unfragmented Ethernet/IP frames with valid IP and L4 checksums.
// ICMP's source field holds its identifier and destination holds type/code.
func boundaryPacket(src, dst net.IP, protocol uint8, sport, dport uint16, tcpFlags uint8) []byte {
	ipv6 := src.To4() == nil
	l4len := 8
	if protocol == 6 {
		l4len = 20
	}
	iplen := 20
	if ipv6 {
		iplen = 40
	}
	packet := make([]byte, 14+iplen+l4len)
	copy(packet[:6], []byte{2, 0, 0, 0, 0, 2})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 1})
	ip, l4 := packet[14:14+iplen], packet[14+iplen:]
	if ipv6 {
		binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(l4len))
		ip[6] = protocol
		ip[7] = 64
		copy(ip[8:24], src.To16())
		copy(ip[24:40], dst.To16())
	} else {
		binary.BigEndian.PutUint16(packet[12:14], 0x0800)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(iplen+l4len))
		ip[8] = 64
		ip[9] = protocol
		copy(ip[12:16], src.To4())
		copy(ip[16:20], dst.To4())
		binary.BigEndian.PutUint16(ip[10:12], boundaryPacketChecksum(ip))
	}
	checksumOffset := 2
	if protocol == 6 || protocol == 17 {
		binary.BigEndian.PutUint16(l4[:2], sport)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		if protocol == 6 {
			l4[12] = 0x50
			l4[13] = tcpFlags
			binary.BigEndian.PutUint16(l4[14:16], 1024)
			checksumOffset = 16
		} else {
			binary.BigEndian.PutUint16(l4[4:6], uint16(l4len))
			checksumOffset = 6
		}
	} else {
		binary.BigEndian.PutUint16(l4[:2], dport)
		binary.BigEndian.PutUint16(l4[4:6], sport)
		binary.BigEndian.PutUint16(l4[6:8], 1)
	}
	checksumData := append([]byte{}, l4...)
	if protocol != 1 {
		pseudo := make([]byte, 12)
		if ipv6 {
			pseudo = make([]byte, 40)
			copy(pseudo[:16], src.To16())
			copy(pseudo[16:32], dst.To16())
			binary.BigEndian.PutUint32(pseudo[32:36], uint32(l4len))
			pseudo[39] = protocol
		} else {
			copy(pseudo[:4], src.To4())
			copy(pseudo[4:8], dst.To4())
			pseudo[9] = protocol
			binary.BigEndian.PutUint16(pseudo[10:12], uint16(l4len))
		}
		checksumData = append(pseudo, l4...)
	}
	checksum := boundaryPacketChecksum(checksumData)
	if checksum == 0 && protocol == 17 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(l4[checksumOffset:checksumOffset+2], checksum)
	return packet
}

func boundaryPacketChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
