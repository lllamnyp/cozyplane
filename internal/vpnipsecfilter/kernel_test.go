package vpnipsecfilter

import (
	"net/netip"
	"os"
	"testing"
)

func TestKernelIPsecPacketAuthorization(t *testing.T) {
	if os.Getenv("COZYPLANE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated Linux BPF-capable container")
	}
	var objects ipsecObjects
	if err := loadIpsecObjects(&objects, nil); err != nil {
		t.Fatal(err)
	}
	defer objects.Close()
	r, err := compile([]string{"10.1.0.0/24", "fd00:1::/64"}, []netip.Addr{netip.MustParseAddr("10.1.0.1"), netip.MustParseAddr("fd00:1::1"), netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
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
	for _, tc := range []struct {
		name, dst string
		allow     bool
	}{
		{"served IPv4", "10.1.0.5", true}, {"served IPv6", "fd00:1::5", true},
		{"appliance IPv4", "10.1.0.1", false}, {"appliance IPv6", "fd00:1::1", false},
		{"management", "192.0.2.1", false}, {"other VPC", "10.2.0.5", false},
		{"internet", "203.0.113.9", false}, {"NAT64 family confusion", "64:ff9b::10.1.0.5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dst := netip.MustParseAddr(tc.dst)
			packet := make([]byte, 54)
			ip := packet[14:]
			if dst.Is4() {
				packet[12], packet[13] = 8, 0
				ip[0] = 0x45
				b := dst.As4()
				copy(ip[16:20], b[:])
			} else {
				packet[12], packet[13] = 0x86, 0xdd
				ip[0] = 0x60
				b := dst.As16()
				copy(ip[24:40], b[:])
			}
			verdict, _, err := objects.VpnIpsecIngress.Test(packet)
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(2)
			if tc.allow {
				want = 0
			}
			if verdict != want {
				t.Fatalf("verdict %d want %d", verdict, want)
			}
		})
	}
	for _, packet := range [][]byte{append([]byte{0x45}, make([]byte, 13)...), append([]byte{0x60}, make([]byte, 19)...), make([]byte, 40)} {
		verdict, _, err := objects.VpnIpsecIngress.Test(packet)
		if err != nil || verdict != 2 {
			t.Fatal("malformed packet admitted", verdict, err)
		}
	}
}
