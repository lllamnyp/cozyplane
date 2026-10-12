package vpnclientfilter

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
)

// This exercises real kernel verification and packet verdicts, not a Go model.
func TestKernelClientPacketAuthorization(t *testing.T) {
	if os.Getenv("COZYPLANE_KERNEL_TEST") != "1" {
		t.Skip("set COZYPLANE_KERNEL_TEST=1 in an isolated privileged Linux container")
	}
	var objects clientObjects
	if err := loadClientObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	r, err := compile([]Peer{
		{Addresses: []string{"10.200.0.2/32", "fd00:200::2/128"}, Destinations: []string{"10.1.0.0/24", "fd00:1::/64"}},
		{Addresses: []string{"10.200.0.3/32"}, Destinations: []string{"10.2.0.0/24", "10.200.0.0/24"}},
	}, []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("fd00:1::1")})
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range r.sources {
		if err := objects.Sources.Put(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range r.denied {
		if err := objects.Denied.Put(k, v); err != nil {
			t.Fatal(err)
		}
	}
	for k, v := range r.destinations {
		if err := objects.Destinations.Put(k, v); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name, src, dst string
		allow          bool
	}{
		{"authorized v4", "10.200.0.2", "10.1.0.5", true},
		{"authorized v6", "fd00:200::2", "fd00:1::5", true},
		{"other VPC", "10.200.0.2", "10.2.0.5", false},
		{"second peer VPC", "10.200.0.3", "10.2.0.5", true},
		{"unknown source", "10.200.0.4", "10.1.0.5", false},
		{"appliance v4", "10.200.0.2", "10.1.0.1", false},
		{"appliance v6", "fd00:200::2", "fd00:1::1", false},
		{"client to client", "10.200.0.3", "10.200.0.2", false},
		{"self", "10.200.0.3", "10.200.0.3", false},
		{"internet", "10.200.0.2", "203.0.113.5", false},
		{"native NAT64 source", "64:ff9b::10.200.0.2", "64:ff9b::10.1.0.5", false},
		{"native NAT64 dest", "fd00:200::2", "64:ff9b::10.1.0.5", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			packet := ipPacket(netip.MustParseAddr(test.src), netip.MustParseAddr(test.dst))
			verdict, _, err := objects.VpnClientIngress.Test(packet)
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(2)
			if test.allow {
				want = 0
			}
			if verdict != want {
				t.Fatalf("verdict=%d want=%d", verdict, want)
			}
		})
	}
	shortV4, shortV6 := make([]byte, 14), make([]byte, 20)
	shortV4[0], shortV6[0] = 0x45, 0x60
	// SCHED_CLS BPF_PROG_TEST_RUN requires at least an Ethernet-sized buffer,
	// even when the real attachment is a layer-three WireGuard interface.
	for _, packet := range [][]byte{shortV4, shortV6, make([]byte, 20)} {
		verdict, _, err := objects.VpnClientIngress.Test(packet)
		if err != nil {
			t.Fatal(err)
		}
		if verdict != 2 {
			t.Fatal("accepted malformed packet")
		}
	}
}

func ipPacket(src, dst netip.Addr) []byte {
	if src.Is4() {
		packet := make([]byte, 28)
		packet[0] = 0x45
		packet[8] = 64
		packet[9] = 17
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		s, d := src.As4(), dst.As4()
		copy(packet[12:16], s[:])
		copy(packet[16:20], d[:])
		return packet
	}
	packet := make([]byte, 48)
	packet[0] = 0x60
	packet[6] = 17
	packet[7] = 64
	binary.BigEndian.PutUint16(packet[4:6], 8)
	s, d := src.As16(), dst.As16()
	copy(packet[8:24], s[:])
	copy(packet[24:40], d[:])
	return packet
}
