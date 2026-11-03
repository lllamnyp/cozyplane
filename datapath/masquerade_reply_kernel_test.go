package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The cluster-egress masquerade must only translate connections a pod OPENS. A
// pod answering a LoadBalancer / externalIP client that sits outside the internal
// CIDRs sends its SYN-ACK out of the uplink with its own address; the service
// datapath reverses it to the service address after us. Lab, 30/10/2026: a VPN
// client (10.0.8.0/24, no longer NATed by the router) never opened the ingress
// VIP because its SYN-ACK came back from the node IP.
func TestKernelMasqueradeOnlyTranslatesOutboundOpenings(t *testing.T) {
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
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "cozyplane_from_pod" {
			delete(spec.Programs, name)
		}
	}
	for _, mp := range spec.Maps {
		mp.Pinning = ebpf.PinNone
	}
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatalf("load collection: %+v", err)
	}
	defer c.Close()

	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "cpmasqup"}}); err != nil {
		t.Fatal(err)
	}
	uplink, err := netlink.LinkByName("cpmasqup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(uplink) })

	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], MasqSrcs: c.Maps["masq_srcs"], Internal: c.Maps["internal"],
	}}}
	nodeIP := net.ParseIP("192.0.2.1")
	if err := m.SyncMasqSources([]string{"10.244.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetInternal([]string{"10.244.0.0/16", "192.0.2.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetMasqIP(nodeIP); err != nil {
		t.Fatal(err)
	}
	if err := m.objs.Params.Put(cfgUplinkIfindex, uint32(uplink.Attrs().Index)); err != nil {
		t.Fatal(err)
	}

	pod, remote := net.ParseIP("10.244.1.5"), net.ParseIP("203.0.113.5")
	segment := func(sport, dport uint16, flags byte) []byte {
		p := policyFamilyPacket(pod, remote)
		binary.BigEndian.PutUint16(p[34:36], sport)
		binary.BigEndian.PutUint16(p[36:38], dport)
		p[34+13] = flags
		return p
	}
	for _, tc := range []struct {
		name         string
		sport, dport uint16
		flags        byte
		masqueraded  bool
	}{
		{"the pod opens a connection", 40000, 443, 0x02, true},
		{"data of the connection it opened", 40000, 443, 0x10, true},
		{"SYN-ACK to an inbound client", 443, 50000, 0x12, false},
		{"data to an inbound client", 443, 50000, 0x18, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := segment(tc.sport, tc.dport, tc.flags)
			ctx, out := make([]byte, 192), make([]byte, len(p))
			binary.LittleEndian.PutUint32(ctx[40:44], uint32(uplink.Attrs().Index))
			got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: p, DataOut: out, Context: ctx})
			// At the uplink a passed packet is TC_ACT_NEXT (-1): Cilium runs after us
			// and is the one that reverses an inbound service flow.
			if err != nil || got != 0xffffffff {
				t.Fatalf("verdict=%d err=%v, want TC_ACT_NEXT", got, err)
			}
			src := net.IP(out[26:30])
			if tc.masqueraded && !src.Equal(nodeIP) {
				t.Fatalf("source %v, want the node IP %v", src, nodeIP)
			}
			if !tc.masqueraded && !src.Equal(pod) {
				t.Fatalf("source %v rewritten: a reply to an inbound flow must keep the pod address %v", src, pod)
			}
		})
	}
}
