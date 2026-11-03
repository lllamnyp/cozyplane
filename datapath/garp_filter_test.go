package datapath

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/net/bpf"
)

func TestGuestAnnouncementSocketFilter(t *testing.T) {
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, address := range []string{"192.0.2.99", "fd00:100::99"} {
		t.Run(address, func(t *testing.T) {
			ip := net.ParseIP(address)
			filter, err := guestAnnouncementFilter(mac, ip)
			if err != nil {
				t.Fatal(err)
			}
			raw := make([]bpf.RawInstruction, len(filter))
			for i, f := range filter {
				raw[i] = bpf.RawInstruction{Op: f.Code, Jt: f.Jt, Jf: f.Jf, K: f.K}
			}
			instructions, decoded := bpf.Disassemble(raw)
			if !decoded {
				t.Fatal("filter did not decode")
			}
			vm, err := bpf.NewVM(instructions)
			if err != nil {
				t.Fatal(err)
			}
			frame := unsolicitedNAFrame(mac, ip.To16())
			minimum := 78
			if ip.To4() != nil {
				frame = garpFrame(mac, ip.To4())
				minimum = 42
			}
			check := func(frame []byte, accept bool) {
				t.Helper()
				got, err := vm.Run(frame)
				if err != nil || (got > 0) != accept {
					t.Fatalf("filter verdict=%d accept=%v error=%v", got, accept, err)
				}
			}
			check(frame, true)
			for size := 0; size < minimum; size++ {
				check(frame[:size], false)
			}
			mutate := func(offset int) []byte { out := append([]byte(nil), frame...); out[offset] ^= 1; return out }
			if ip.To4() != nil {
				for _, offset := range []int{12, 14, 16, 18, 22, 26, 28} {
					check(mutate(offset), false)
				}
				for _, op := range []uint16{0, 2, 3} {
					out := append([]byte(nil), frame...)
					binary.BigEndian.PutUint16(out[20:22], op)
					check(out, op == 2)
				}
			} else {
				for _, offset := range []int{6, 10, 12, 20, 54, 62, 66, 70, 74} {
					check(mutate(offset), false)
				}
			}
		})
	}
	if _, err := guestAnnouncementFilter(nil, net.ParseIP("192.0.2.1")); err == nil {
		t.Fatal("missing MAC accepted")
	}
	if _, err := guestAnnouncementFilter(mac, nil); err == nil {
		t.Fatal("missing IP accepted")
	}
}
