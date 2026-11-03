package datapath

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestKernelTCXReplacementFailureKeepsEnforcement(t *testing.T) {
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
	veth, _ := guestAnnouncementTestVeth(t, "cphtcxguard")
	index := veth.Attrs().Index
	defer DetachVeth(index)
	for _, direction := range []struct {
		name    string
		attach  ebpf.AttachType
		ingress bool
	}{
		{"ingress", ebpf.AttachTCXIngress, true},
		{"egress", ebpf.AttachTCXEgress, false},
	} {
		t.Run(direction.name, func(t *testing.T) {
			newProgram := func(name string, verdict int32) *ebpf.Program {
				t.Helper()
				p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
					Name: name, Type: ebpf.SchedCLS, License: "GPL",
					Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, verdict), asm.Return()},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { p.Close() })
				return p
			}
			old := newProgram("old_deny", 2)
			if err := attachTCX(index, old, direction.attach, direction.ingress, link.Tail()); err != nil {
				t.Fatal(err)
			}
			foreign := newProgram("foreign_next", -1)
			foreignLink, err := link.AttachTCX(link.TCXOptions{Interface: index, Program: foreign, Attach: direction.attach, Anchor: link.Head()})
			if err != nil {
				t.Fatal(err)
			}
			defer foreignLink.Close()
			failed := newProgram("closed_program", 2)
			failed.Close() // deterministically reject the new attachment after the old pin is removed
			if err := attachTCX(index, failed, direction.attach, direction.ingress, link.Head()); err == nil {
				t.Fatal("closed replacement unexpectedly attached")
			}
			result, err := link.QueryPrograms(link.QueryOptions{Target: index, Attach: direction.attach})
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Programs) < 2 {
				t.Fatalf("replacement failure removed enforcement: %d attached programs (only foreign NEXT remains)", len(result.Programs))
			}
			guard, err := ebpf.NewProgramFromID(result.Programs[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			verdict, _, err := guard.Test(make([]byte, 60))
			guard.Close()
			if err != nil || verdict != 2 {
				t.Fatalf("failure guard verdict=%d err=%v", verdict, err)
			}
			// Repeated failures replace the guard instead of accumulating pinned
			// links/programs. A successful retry then removes the guard.
			fds, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for range 16 {
				if err := attachTCX(index, failed, direction.attach, direction.ingress, link.Head()); err == nil {
					t.Fatal("closed replacement unexpectedly attached on retry")
				}
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				err = attachTCX(index, old, direction.attach, direction.ingress, link.Head())
				if err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("guard prevented recovery", err)
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := os.Stat(linkPinPath(index, direction.ingress) + "-guard"); !os.IsNotExist(err) {
				t.Fatal("successful retry retained guard", err)
			}
			deadline = time.Now().Add(2 * time.Second)
			for {
				result, err = link.QueryPrograms(link.QueryOptions{Target: index, Attach: direction.attach})
				if err != nil {
					t.Fatal(err)
				}
				if len(result.Programs) == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("guard links leaked after retries: %d programs", len(result.Programs))
				}
				time.Sleep(10 * time.Millisecond)
			}
			info, err := old.Info()
			if err != nil {
				t.Fatal(err)
			}
			id, _ := info.ID()
			if result.Programs[0].ID != id {
				t.Fatal("recovered program was not moved to head")
			}
			afterFDs, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(afterFDs) > len(fds)+2 {
				t.Fatalf("FDs grew across retries: before=%d after=%d err=%v", len(fds), len(afterFDs), err)
			}
		})
	}
}

func TestKernelTCXReconcileRestoresBothOrdersAfterInterruption(t *testing.T) {
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
	veth, _ := guestAnnouncementTestVeth(t, "cphtcxorder")
	index := veth.Attrs().Index
	defer DetachVeth(index)
	newProgram := func() *ebpf.Program {
		p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
			Type: ebpf.SchedCLS, License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, -1), asm.Return()},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { p.Close() })
		return p
	}
	ingress, egress := newProgram(), newProgram()
	m := &Manager{objs: overlayObjects{overlayPrograms: overlayPrograms{CozyplaneFromPod: ingress, CozyplaneToPod: egress}}}
	hooks := []struct {
		program *ebpf.Program
		attach  ebpf.AttachType
		ingress bool
	}{{ingress, ebpf.AttachTCXIngress, true}, {egress, ebpf.AttachTCXEgress, false}}
	for _, h := range hooks {
		if err := attachTCX(index, h.program, h.attach, h.ingress, link.Tail()); err != nil {
			t.Fatal(err)
		}
		foreign, err := link.AttachTCX(link.TCXOptions{Interface: index, Program: newProgram(), Attach: h.attach, Anchor: link.Head()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { foreign.Close() })
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	for iteration := range 16 {
		netID := uint32(0)
		if iteration%2 == 0 {
			netID = 100
		}
		if err := netlink.LinkSetAlias(veth, FormatVethAlias(netID, []net.IP{net.ParseIP("192.0.2.10")}, mac)); err != nil {
			t.Fatal(err)
		}
		// Simulate a process interrupted after guard publication: no userspace
		// handle remains, and the ordinary hook is still attached.
		for _, h := range hooks {
			if err := installTCXGuard(index, h.attach, linkPinPath(index, h.ingress)+"-guard"); err != nil {
				t.Fatal(err)
			}
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			_, reconcileErr := m.ReconcilePodTCXOrder()
			ready := true
			for _, h := range hooks {
				result, err := link.QueryPrograms(link.QueryOptions{Target: index, Attach: h.attach})
				if err != nil {
					t.Fatal(err)
				}
				info, _ := h.program.Info()
				id, _ := info.ID()
				position := 0
				if netID == 0 {
					position = len(result.Programs) - 1
				}
				if len(result.Programs) != 2 || result.Programs[position].ID != id {
					ready = false
				}
			}
			if ready {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("iteration=%d net=%d did not recover: %v", iteration, netID, reconcileErr)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if err := DetachVeth(index); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(PinRoot + "/links")
	if err != nil || len(entries) != 0 {
		t.Fatalf("DEL retained link pins: %v err=%v", entries, err)
	}
}
