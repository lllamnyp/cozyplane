package datapath

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestKernelTCXReconcileReapsDetachedPins(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if entries, err := os.ReadDir(PinRoot); err == nil && len(entries) > 0 {
		t.Fatal("refusing to touch existing pinned state")
	}
	if err := unix.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer unix.Unmount("/sys/fs/bpf", 0)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SchedCLS, License: "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	m := &Manager{objs: overlayObjects{overlayPrograms: overlayPrograms{CozyplaneFromPod: prog, CozyplaneToPod: prog}}}
	active, _ := guestAnnouncementTestVeth(t, "cphtcxgcactive")
	if err := attachTCX(active.Attrs().Index, prog, ebpf.AttachTCXIngress, true, link.Head()); err != nil {
		t.Fatal(err)
	}
	defer DetachVeth(active.Attrs().Index)
	// This active hook has no rebuild alias, like an uplink or legacy endpoint;
	// absence from ListLocalPortVeths must not authorize its removal.
	const endpoints = 48 // more than one directory batch
	foreignPin := filepath.Join(PinRoot, "links", "foreign-keep")
	defer removeTCXPin(foreignPin)
	for iteration := range endpoints {
		veth, _ := guestAnnouncementTestVeth(t, fmt.Sprintf("cphtcxgc%d", iteration))
		index := veth.Attrs().Index
		if err := attachTCX(index, prog, ebpf.AttachTCXIngress, true, link.Head()); err != nil {
			t.Fatal(err)
		}
		if err := attachTCX(index, prog, ebpf.AttachTCXEgress, false, link.Tail()); err != nil {
			t.Fatal(err)
		}
		if err := installTCXGuard(index, ebpf.AttachTCXIngress, linkPinPath(index, true)+"-guard"); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkDel(veth); err != nil {
			t.Fatal(err)
		}
		pinned, err := link.LoadPinnedLink(linkPinPath(index, true), nil)
		if err != nil {
			t.Fatal("deleting veth unexpectedly removed its pin", err)
		}
		info, err := pinned.Info()
		pinned.Close()
		if err != nil || info.TCX() == nil || info.TCX().Ifindex != 0 {
			t.Fatalf("deleted interface link not detached: info=%+v err=%v", info, err)
		}
		if iteration == 0 {
			foreign, err := link.NewFromID(info.ID)
			if err != nil {
				t.Fatal(err)
			}
			err = foreign.Pin(foreignPin)
			foreign.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	before, err := os.ReadDir(filepath.Join(PinRoot, "links"))
	if err != nil || len(before) != endpoints*3+2 {
		t.Fatalf("expected detached pins plus active and foreign hooks: count=%d err=%v", len(before), err)
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ReconcilePodTCXOrder(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadDir(filepath.Join(PinRoot, "links"))
	if err != nil || len(after) != 2 {
		t.Fatalf("detached TCX objects retained after reconciliation: count=%d err=%v", len(after), err)
	}
	if _, err := os.Stat(foreignPin); err != nil {
		t.Fatal("GC removed unknown pin", err)
	}
	afterFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(afterFDs) > len(fds)+2 {
		t.Fatalf("GC retained FDs: before=%d after=%d err=%v", len(fds), len(afterFDs), err)
	}
	activeLink, err := link.LoadPinnedLink(linkPinPath(active.Attrs().Index, true), nil)
	if err != nil {
		t.Fatal("GC removed active hook", err)
	}
	defer activeLink.Close()
	info, err := activeLink.Info()
	if err != nil || info.TCX().Ifindex != uint32(active.Attrs().Index) {
		t.Fatal("active hook was detached", err)
	}
}
