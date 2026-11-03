package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelHostFirewallFailedSyncDeniesNewFlows(t *testing.T) {
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
		if name != "cozyplane_hf_ingress" && name != "cozyplane_hf_egress" && name != "cozyplane_from_pod" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	spec.Maps["hf_allow"].MaxEntries = 1
	spec.Maps["hf_eallow"].MaxEntries = 1
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], HfAllow: c.Maps["hf_allow"], HfModes: c.Maps["hf_modes"],
		HfEallow: c.Maps["hf_eallow"], HfSelf: c.Maps["hf_self"],
	}}}
	node, peer := net.ParseIP("192.0.2.1"), net.ParseIP("198.51.100.10")
	if err := m.SyncHFSelf([]net.IP{node}); err != nil {
		t.Fatal(err)
	}
	packet := func(src, dst net.IP) []byte {
		p := make([]byte, 54)
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14], p[22], p[23] = 0x45, 64, 6
		binary.BigEndian.PutUint16(p[16:18], 40)
		copy(p[26:30], src.To4())
		copy(p[30:34], dst.To4())
		binary.BigEndian.PutUint16(p[34:36], 40000)
		binary.BigEndian.PutUint16(p[36:38], 443)
		p[46], p[47] = 0x50, 0x02 // TCP SYN
		return p
	}
	allow := func(ip net.IP, port uint16) HFAllow {
		return HFAllow{Proto: 6, Port: port, CIDR: &net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, Allow: true}
	}
	check := func(t *testing.T, prog string, p []byte, want uint32) {
		t.Helper()
		got, err := c.Programs[prog].Run(&ebpf.RunOptions{Data: p})
		if err != nil || got != want {
			t.Fatalf("%s verdict=%d want=%d err=%v", prog, got, want, err)
		}
	}
	t.Run("SCTP cannot bypass selected host firewall directions", func(t *testing.T) {
		for _, ipv6 := range []bool{false, true} {
			self, remote := node, peer
			if ipv6 {
				self, remote = net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
			}
			if err := m.SyncHFSelf([]net.IP{self}); err != nil {
				t.Fatal(err)
			}
			sctp := func(src, dst net.IP, dport uint16) []byte {
				l4 := 34
				if ipv6 {
					l4 = 54
				}
				p := make([]byte, l4+32)
				if ipv6 {
					binary.BigEndian.PutUint16(p[12:14], 0x86dd)
					p[14], p[20], p[21] = 0x60, 132, 64
					binary.BigEndian.PutUint16(p[18:20], 32)
					copy(p[22:38], src.To16())
					copy(p[38:54], dst.To16())
				} else {
					binary.BigEndian.PutUint16(p[12:14], 0x0800)
					p[14], p[22], p[23] = 0x45, 64, 132
					binary.BigEndian.PutUint16(p[16:18], 52)
					copy(p[26:30], src.To4())
					copy(p[30:34], dst.To4())
				}
				binary.BigEndian.PutUint16(p[l4:l4+2], 40000)
				binary.BigEndian.PutUint16(p[l4+2:l4+4], dport)
				p[l4+12] = 1 // SCTP INIT; no SCTP allow rule is supported
				binary.BigEndian.PutUint16(p[l4+14:l4+16], 20)
				binary.BigEndian.PutUint32(p[l4+16:l4+20], 1)
				binary.BigEndian.PutUint32(p[l4+20:l4+24], 65535)
				binary.BigEndian.PutUint16(p[l4+24:l4+26], 1)
				binary.BigEndian.PutUint16(p[l4+26:l4+28], 1)
				binary.BigEndian.PutUint32(p[l4+28:l4+32], 1)
				return p
			}
			if err := m.ApplyHFIngress(true, nil); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFEgress(false, nil); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 443), 2)
			check(t, "cozyplane_hf_ingress", sctp(self, remote, 443), 0)
			check(t, "cozyplane_hf_egress", sctp(self, remote, 443), 0)
			if err := c.Maps["params"].Put(cfgGenevePort, uint32(6081)); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 6081), 2)
			selfAddr, _ := addr128(self)
			remoteAddr, _ := addr128(remote)
			pin := overlayNpCtKey{Pod: selfAddr, Peer: remoteAddr, Pport: htons(443), Rport: htons(40000), Proto: 17}
			if err := c.Maps["hf_ct"].Put(pin, uint8(1)); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 443), 2)
			if err := c.Maps["hf_ct"].Delete(pin); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFIngress(false, nil); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFEgress(true, nil); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 443), 0)
			check(t, "cozyplane_hf_ingress", sctp(self, remote, 443), 2)
			check(t, "cozyplane_hf_egress", sctp(self, remote, 443), 2)
			// Exercise from_pod's remote route, not just the tail-call target.
			// Encapsulation cannot succeed in BPF_PROG_TEST_RUN, so the firewall
			// drop counter proves this packet reached the actual egress gate.
			remoteKey := overlayLpmKey{Prefixlen: 160, Addr: remoteAddr}
			if err := c.Maps["remotes"].Put(remoteKey, uint32(1)); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["lb_prog"].Put(uint32(3), uint32(c.Programs["cozyplane_hf_egress"].FD())); err != nil {
				t.Fatal(err)
			}
			egressDrops := func() uint64 {
				var perCPU []uint64
				if err := c.Maps["hf_drops"].Lookup(uint32(1), &perCPU); err != nil {
					t.Fatal(err)
				}
				var total uint64
				for _, count := range perCPU {
					total += count
				}
				return total
			}
			before := egressDrops()
			check(t, "cozyplane_from_pod", sctp(self, remote, 443), 2)
			if got := egressDrops(); got != before+1 {
				t.Fatalf("remote SCTP bypassed HostFirewall: drops=%d want=%d", got, before+1)
			}
			if err := c.Maps["remotes"].Delete(remoteKey); err != nil {
				t.Fatal(err)
			}
			if err := m.BlockHostFirewall(); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["np_nodes"].Put(remoteAddr, uint8(1)); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 443), 0)
			check(t, "cozyplane_hf_ingress", sctp(self, remote, 443), 0)
			if err := c.Maps["np_nodes"].Delete(remoteAddr); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFIngress(false, nil); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFEgress(false, nil); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", sctp(remote, self, 443), 0)
			check(t, "cozyplane_hf_ingress", sctp(self, remote, 443), 0)
		}
		if err := m.SyncHFSelf([]net.IP{node}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("IPv6 CIDR cannot authorize IPv4 packets", func(t *testing.T) {
		rule := HFAllow{Proto: 6, Port: 443, CIDR: cidr("::/0"), Allow: true}
		if err := m.ApplyHFIngress(true, []HFAllow{rule}); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 2)
	})
	t.Run("params reset preserves active firewall", func(t *testing.T) {
		rule := HFAllow{Proto: 6, Port: 443, CIDR: cidr("::ffff:198.51.100.0/120"), Allow: true}
		if err := m.ApplyHFIngress(true, []HFAllow{rule}); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 0)
		check(t, "cozyplane_hf_ingress", packet(net.ParseIP("203.0.113.10"), node), 2)
		if err := m.ApplyHFIngress(true, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["params"].Put(cfgHFEnabled, uint32(0)); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 2)
		if err := m.ApplyHFIngress(false, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing rules arm durable deny before recovery", func(t *testing.T) {
		rules := []HFAllow{allow(peer, 443)}
		if err := m.ApplyHFIngress(true, rules); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 0)
		if err := m.armHFBootstrap(map[string]bool{"hf_allow": true}); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 2)
		if err := m.ApplyHFIngress(true, rules); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, node), 0)
		if err := m.ApplyHFIngress(false, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("lost host identity restored before publication", func(t *testing.T) {
		if err := m.ApplyHFIngress(true, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncHFSelf(nil); err != nil {
			t.Fatal(err)
		}
		if err := m.armHFBootstrap(map[string]bool{"hf_self": true}); err != nil {
			t.Fatal(err)
		}
		check(t, "cozyplane_hf_ingress", packet(peer, net.ParseIP("127.0.0.1")), 2)
		if err := m.ApplyHFIngress(false, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncHFSelf([]net.IP{node}); err != nil {
			t.Fatal(err)
		}
	})
	for _, direction := range []struct {
		name     string
		apply    func(bool, []HFAllow) error
		ip       net.IP
		p        []byte
		programs []string
	}{
		{"ingress", m.ApplyHFIngress, peer, packet(peer, node), []string{"cozyplane_hf_ingress"}},
		{"egress", m.ApplyHFEgress, peer, packet(node, peer), []string{"cozyplane_hf_ingress", "cozyplane_hf_egress"}},
	} {
		t.Run(direction.name, func(t *testing.T) {
			if err := m.BlockHostFirewall(); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", packet(peer, node), 2)
			check(t, "cozyplane_hf_egress", packet(node, peer), 2)
			if err := m.ApplyHFIngress(false, nil); err != nil {
				t.Fatal(err)
			}
			if err := m.ApplyHFEgress(false, nil); err != nil {
				t.Fatal(err)
			}
			rules := []HFAllow{allow(direction.ip, 443), allow(direction.ip, 444)}
			if err := direction.apply(true, rules); err == nil {
				t.Fatal("oversized rules unexpectedly fit")
			}
			for _, prog := range direction.programs {
				check(t, prog, direction.p, 2)
			}
			if err := direction.apply(true, rules[:1]); err != nil {
				t.Fatal(err)
			}
			for _, prog := range direction.programs {
				check(t, prog, direction.p, 0)
			}
			if err := direction.apply(true, rules); err == nil {
				t.Fatal("replacement unexpectedly fit")
			}
			for _, prog := range direction.programs {
				check(t, prog, direction.p, 2)
			}
			// Node-to-node plumbing remains available during a failed update.
			a, _ := addr128(peer)
			if err := c.Maps["np_nodes"].Put(a, uint8(1)); err != nil {
				t.Fatal(err)
			}
			check(t, "cozyplane_hf_ingress", direction.p, 0)
			if err := c.Maps["np_nodes"].Delete(a); err != nil {
				t.Fatal(err)
			}
			if err := direction.apply(false, nil); err != nil {
				t.Fatal(err)
			}
			for _, prog := range direction.programs {
				check(t, prog, direction.p, 0)
			}
		})
	}
}
