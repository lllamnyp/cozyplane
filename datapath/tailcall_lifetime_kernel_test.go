package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func TestKernelHostFirewallTailCallsSurviveAgentMapFDClosure(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := unix.Mount("bpf", root, "bpf", 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(root, 0); err != nil {
			t.Error(err)
		}
	})
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "cozyplane_from_pod" && name != "cozyplane_hf_ingress" && name != "cozyplane_hf_egress" {
			delete(spec.Programs, name)
		}
	}
	for name, mp := range spec.Maps {
		if name != "lb_prog" {
			mp.Pinning = ebpf.PinNone
		}
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: root}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	caller, err := c.Programs["cozyplane_from_pod"].Clone()
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], HfModes: c.Maps["hf_modes"], HfSelf: c.Maps["hf_self"],
		HfAllow: c.Maps["hf_allow"], HfEallow: c.Maps["hf_eallow"],
	}}}
	if err := m.SyncHFSelf([]net.IP{net.ParseIP("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if err := m.ApplyHFIngress(true, nil); err != nil {
		t.Fatal(err)
	}
	for slot, program := range map[uint32]string{2: "cozyplane_hf_ingress", 3: "cozyplane_hf_egress"} {
		if err := c.Maps["lb_prog"].Put(slot, uint32(c.Programs[program].FD())); err != nil {
			t.Fatal(err)
		}
	}
	p := make([]byte, 54)
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14], p[22], p[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(p[16:18], 40)
	copy(p[26:30], []byte{198, 51, 100, 10})
	copy(p[30:34], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(p[34:36], 40000)
	binary.BigEndian.PutUint16(p[36:38], 443)
	p[46], p[47] = 0x50, 2
	check := func() {
		t.Helper()
		got, err := caller.Run(&ebpf.RunOptions{Data: p})
		if err != nil || got != 2 {
			t.Fatalf("isolated host lost enforcement after map FD closure: verdict=%d want=2 err=%v", got, err)
		}
	}
	check()
	// Attached/pinned programs keep kernel map references, but those alone
	// do not preserve ProgramArray slots when the agent's last FD closes.
	if err := c.Maps["lb_prog"].Close(); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		time.Sleep(10 * time.Millisecond) // includes deferred kernel map clearing
		check()
	}
	retained, err := ebpf.LoadPinnedMap(filepath.Join(root, "lb_prog"), nil)
	if err != nil {
		t.Fatal("tail-call map not retained by bpffs", err)
	}
	defer retained.Close()
	for _, slot := range []uint32{2, 3} {
		var id uint32
		if err := retained.Lookup(slot, &id); err != nil || id == 0 {
			t.Fatal("retained firewall tail-call target missing", slot, id, err)
		}
	}
	info, err := retained.Info()
	if err != nil {
		t.Fatal(err)
	}
	mapID, ok := info.ID()
	if !ok {
		t.Fatal("kernel map ID unavailable")
	}
	c.Close() // all agent-owned program/map FDs are now gone
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	check() // only bpffs pin + the attached-classifier stand-in remain
	reused, err := ebpf.NewMapWithOptions(spec.Maps["lb_prog"], ebpf.MapOptions{PinPath: root})
	if err != nil {
		t.Fatal(err)
	}
	defer reused.Close()
	info, err = reused.Info()
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := info.ID(); !ok || id != mapID {
		t.Fatal("compatible restart allocated another tail-call map", id, mapID)
	}
	if err := reused.Close(); err != nil {
		t.Fatal(err)
	}
	if err := caller.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "lb_prog")); err != nil {
		t.Fatal(err)
	}
	// Once the explicit owners are removed, no permanent kernel map/program
	// cycle may remain. Allow deferred kernel destruction to finish.
	deadline := time.Now().Add(3 * time.Second)
	for {
		remaining, err := ebpf.NewMapFromID(mapID)
		if isNotExist(err) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		remaining.Close()
		if time.Now().After(deadline) {
			t.Fatal("tail-call map retained after final pin/classifier removal")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
