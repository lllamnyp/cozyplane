package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelScopedForwardingCIDRFamilies(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
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
		t.Fatal(err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Networks: c.Maps["networks"]}}}
	context := make([]byte, 192)
	binary.LittleEndian.PutUint32(context[40:44], 1)
	for _, tc := range []struct {
		name, prefix, src, dst string
		allowed                bool
		scope                  uint32
	}{
		{"IPv6 wildcard rejects IPv4", "::/0", "198.51.100.10", "203.0.113.20", false, 1},
		{"IPv6 specific rejects IPv4", "64:ff9b::/96", "198.51.100.10", "203.0.113.20", false, 1},
		{"IPv6 specific admits IPv6", "64:ff9b::/96", "64:ff9b::198.51.100.10", "2001:db8:1::20", true, 1},
		{"IPv4 wildcard rejects native IPv6", "0.0.0.0/0", "64:ff9b::198.51.100.10", "2001:db8:1::20", false, 1},
		{"IPv4 range admits IPv4", "198.51.100.0/24", "198.51.100.10", "203.0.113.20", true, 1},
		{"mapped input admits IPv4", "::ffff:198.51.100.0/120", "198.51.100.10", "203.0.113.20", true, 1},
		{"IPv6 wildcard admits IPv6", "::/0", "2001:db8:2::10", "2001:db8:1::20", true, 1},
		{"unrelated range rejects IPv4", "192.0.2.0/24", "198.51.100.10", "203.0.113.20", false, 1},
		{"another leg cannot grant IPv4", "198.51.100.0/24", "198.51.100.10", "203.0.113.20", false, 2},
		{"another leg cannot grant IPv6", "::/0", "2001:db8:2::10", "2001:db8:1::20", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := net.ParseIP(tc.src), net.ParseIP(tc.dst)
			prefix := dst.String() + "/128"
			if dst.To4() != nil {
				prefix = dst.String() + "/32"
			}
			if err := m.SetNetwork(101, prefix, 101); err != nil {
				t.Fatal(err)
			}
			dest, _ := localKey(101, dst)
			if err := c.Maps["locals"].Put(dest, overlayEndpoint{Ifindex: 2}); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["ports"].Put(uint32(1), uint32(101)|PortForwardFlag|PortForwardScopedFlag); err != nil {
				t.Fatal(err)
			}
			key, err := fwdCIDRKey(tc.scope, tc.prefix)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["fwd_cidrs"].Put(key, uint8(1)); err != nil {
				t.Fatal(err)
			}
			cpus, err := ebpf.PossibleCPU()
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["sg_drops"].Put(uint32(101), make([]uint64, cpus)); err != nil {
				t.Fatal(err)
			}
			want, wantDrops := uint32(2), uint64(1)
			if tc.allowed {
				want, wantDrops = 7, 0 // direct delivery after origin anti-spoof
			}
			got, runErr := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: policyFamilyPacket(src, dst), Context: context})
			var drops []uint64
			if err := c.Maps["sg_drops"].Lookup(uint32(101), &drops); err != nil {
				t.Fatal(err)
			}
			var total uint64
			for _, n := range drops {
				total += n
			}
			if err := c.Maps["fwd_cidrs"].Delete(key); err != nil {
				t.Fatal(err)
			}
			if runErr != nil || got != want || total != wantDrops {
				t.Fatalf("verdict=%d want=%d origin drops=%d want=%d err=%v", got, want, total, wantDrops, runErr)
			}
		})
	}
}
