package datapath

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func managementARP() []byte {
	packet := make([]byte, 42)
	copy(packet[:6], []byte{255, 255, 255, 255, 255, 255})
	copy(packet[6:12], []byte{2, 0, 0, 0, 0, 1})
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)
	binary.BigEndian.PutUint16(packet[14:16], 1)
	binary.BigEndian.PutUint16(packet[16:18], 0x0800)
	packet[18], packet[19] = 6, 4
	binary.BigEndian.PutUint16(packet[20:22], 1)
	copy(packet[22:28], packet[6:12])
	copy(packet[28:32], net.ParseIP("192.0.2.10").To4())
	copy(packet[38:42], net.ParseIP("192.0.2.20").To4())
	return packet
}

func TestBoundaryMissingContinuationKeepsARPAndDropsIP(t *testing.T) {
	f := newBoundaryPacketFixture(t, false)
	if err := f.objects.Ports.Delete(f.ifindex); err != nil && !isNotExist(err) {
		t.Fatal(err)
	}
	if err := f.objects.LbProg.Delete(uint32(4)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{"management ARP", managementARP(), 0},
		{"IPv4 still closed", boundaryPacket(net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), 6, 42000, 443, 2), 2},
		{"IPv6 still closed", boundaryPacket(net.ParseIP("2001:db8::10"), net.ParseIP("2001:db8::20"), 6, 42000, 443, 2), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := f.objects.CozyplaneFromPod.Test(tc.packet)
			if err != nil || got != tc.want {
				t.Fatalf("verdict=%d want=%d err=%v", got, tc.want, err)
			}
		})
	}
}

// A pinned entry program can outlive its agent. Program references keep ordinary
// maps alive, but do not retain the userspace reference that protects PROG_ARRAY
// entries. Run the actual wrapper after closing every agent object and callee FD.
func TestBoundaryAgentObjectCloseKeepsManagement(t *testing.T) {
	if os.Getenv("COZYPLANE_REQUIRE_BPF") != "1" {
		t.Skip("requires isolated privileged Linux BPF validation")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	pinDir := t.TempDir()
	if err := unix.Mount("bpf", pinDir, "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(pinDir, 0); err != nil {
			t.Errorf("unmount private bpffs: %v", err)
		}
	})
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the production pinning choice for lb_prog, isolating other maps.
	for name, mapping := range spec.Maps {
		if name != "lb_prog" {
			mapping.Pinning = ebpf.PinNone
		}
	}
	var objects overlayObjects
	if err := spec.LoadAndAssign(&objects, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}); err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Fatalf("kernel verifier: %+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objects.Close() })
	entry, err := objects.CozyplaneFromPod.Clone()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = entry.Close() })
	callee, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "lifecycle_ok", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = callee.Close() })
	if err := objects.LbProg.Put(uint32(4), callee); err != nil {
		t.Fatal(err)
	}
	packet := boundaryPacket(net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.20"), 6, 42000, 443, 2)
	if got, _, err := entry.Test(packet); err != nil || got != 0 {
		t.Fatalf("before agent close: verdict=%d err=%v", got, err)
	}
	if err := objects.Close(); err != nil {
		t.Fatal(err)
	}
	if err := callee.Close(); err != nil {
		t.Fatal(err)
	}
	if got, _, err := entry.Test(packet); err != nil || got != 0 {
		t.Fatalf("management lost after agent close: verdict=%d err=%v", got, err)
	}
	pinned, err := ebpf.LoadPinnedMap(filepath.Join(pinDir, "lb_prog"), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pinned.Close() })
	var programID uint32
	if err := pinned.Lookup(uint32(4), &programID); err != nil || programID == 0 {
		t.Fatalf("continuation absent after reopening: id=%d err=%v", programID, err)
	}
	if err := pinned.Close(); err != nil {
		t.Fatal(err)
	}
	if got, _, err := entry.Test(packet); err != nil || got != 0 {
		t.Fatalf("management lost after reopened FD close: verdict=%d err=%v", got, err)
	}
}
