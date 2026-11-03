package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelCIDRPolicyPacketFamilies(t *testing.T) {
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
		if name != "cozyplane_to_pod" && name != "cozyplane_from_pod" && name != "cozyplane_hf_ingress" && name != "cozyplane_hf_egress" {
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
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], NpIdent: c.Maps["np_ident"], NpAllow: c.Maps["np_allow"], NpCidr: c.Maps["np_cidr"],
		HfAllow: c.Maps["hf_allow"], HfEallow: c.Maps["hf_eallow"], HfModes: c.Maps["hf_modes"], HfSelf: c.Maps["hf_self"],
	}}}
	ctx := make([]byte, 192)
	binary.LittleEndian.PutUint32(ctx[40:44], 1)
	if err := c.Maps["ports"].Put(uint32(1), uint32(0)); err != nil {
		t.Fatal(err)
	}

	check := func(t *testing.T, program string, data []byte, want uint32) {
		t.Helper()
		got, err := c.Programs[program].Run(&ebpf.RunOptions{Data: data, Context: ctx})
		if err != nil || got != want {
			t.Fatalf("%s verdict=%d want=%d err=%v", program, got, want, err)
		}
	}
	for _, tc := range []struct {
		name, prefix, src, dst string
		want                   uint32
		except, legacy         bool
	}{
		{"IPv6 wildcard rejects IPv4", "::/0", "198.51.100.10", "203.0.113.20", 2, false, false},
		{"IPv6 wildcard admits IPv6", "::/0", "2001:db8::10", "2001:db8::20", 0, false, false},
		{"IPv4 wildcard admits IPv4", "0.0.0.0/0", "198.51.100.10", "203.0.113.20", 0, false, false},
		{"IPv4 wildcard rejects native NAT64 IPv6", "0.0.0.0/0", "64:ff9b::198.51.100.10", "64:ff9b::203.0.113.20", 2, false, false},
		{"native NAT64 IPv6 grant", "64:ff9b::/96", "64:ff9b::198.51.100.10", "64:ff9b::203.0.113.20", 0, false, false},
		{"mapped IPv4 input", "::ffff:0.0.0.0/96", "198.51.100.10", "203.0.113.20", 0, false, false},
		{"IPv4 exception", "0.0.0.0/0", "198.51.100.10", "203.0.113.20", 2, true, false},
		{"IPv6 exception", "::/0", "2001:db8::10", "2001:db8::20", 2, true, false},
		{"legacy wildcard rejects IPv4", "::/0", "198.51.100.10", "203.0.113.20", 2, false, true},
		{"legacy wildcard rejects IPv6", "::/0", "2001:db8::10", "2001:db8::20", 2, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := net.ParseIP(tc.src), net.ParseIP(tc.dst)
			data := policyFamilyPacket(src, dst)
			for _, direction := range []uint8{NPDirIn, NPDirEg} {
				self, peer, flag := dst, src, NPIngIsolated
				if direction == NPDirEg {
					self, peer, flag = src, dst, NPEgIsolated
				}
				prefix := cidr(tc.prefix)
				rows := []NPCidr{{ID: 10, Dir: direction, Proto: 6, Port: 443, CIDR: prefix, Allow: true}}
				hf := []HFAllow{{Proto: 6, Port: 443, CIDR: prefix, Allow: true}}
				if tc.except {
					ones := "/128"
					if peer.To4() != nil {
						ones = "/32"
					}
					rows = append(rows, NPCidr{ID: 10, Dir: direction, Proto: 6, Port: 443, CIDR: cidr(peer.String() + ones)})
					hf = append(hf, HFAllow{Proto: 6, Port: 443, CIDR: cidr(peer.String() + ones)})
				}
				if tc.legacy {
					rows, hf = nil, nil
				}
				if err := m.ApplyNetworkPolicy([]NPIdent{{IP: self, ID: 10, Flags: flag}}, nil, rows); err != nil {
					t.Fatal(err)
				}
				if err := m.ApplyHFIngress(false, nil); err != nil {
					t.Fatal(err)
				}
				if err := m.ApplyHFEgress(false, nil); err != nil {
					t.Fatal(err)
				}
				if tc.legacy {
					if err := c.Maps["np_cidr"].Put(overlayNpCidrKey{Prefixlen: 96, Dir: direction, Proto: 6, Port: htons(443), Id: 10}, uint8(1)); err != nil {
						t.Fatal(err)
					}
				}
				check(t, "cozyplane_to_pod", data, tc.want)
				if direction == NPDirEg {
					addr, _ := localKey(0, src)
					if err := c.Maps["locals"].Put(addr, overlayEndpoint{Ifindex: 1}); err != nil {
						t.Fatal(err)
					}
					drops := func() uint64 {
						var values []uint64
						if err := c.Maps["np_drops"].Lookup(uint32(NPDirEg), &values); err != nil {
							t.Fatal(err)
						}
						var sum uint64
						for _, value := range values {
							sum += value
						}
						return sum
					}
					before := drops()
					if _, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: data, Context: ctx}); err != nil {
						t.Fatal(err)
					}
					delta := uint64(0)
					if tc.want == 2 {
						delta = 1
					}
					if got := drops(); got != before+delta {
						t.Fatal("origin egress gate did not enforce family", got, before, delta)
					}
					if err := c.Maps["locals"].Delete(addr); err != nil {
						t.Fatal(err)
					}
				}
				if err := m.SyncHFSelf([]net.IP{self}); err != nil {
					t.Fatal(err)
				}
				apply, mp, programs := m.ApplyHFIngress, c.Maps["hf_allow"], []string{"cozyplane_hf_ingress"}
				if direction == NPDirEg {
					apply, mp, programs = m.ApplyHFEgress, c.Maps["hf_eallow"], []string{"cozyplane_hf_ingress", "cozyplane_hf_egress"}
				}
				if err := apply(true, hf); err != nil {
					t.Fatal(err)
				}
				if tc.legacy {
					if err := mp.Put(overlayHfAllowKey{Prefixlen: 32, Proto: 6, Port: htons(443)}, uint8(1)); err != nil {
						t.Fatal(err)
					}
				}
				for _, program := range programs {
					check(t, program, data, tc.want)
				}
			}
		})
	}
}

func policyFamilyPacket(src, dst net.IP) []byte {
	l4 := 34
	if src.To4() == nil {
		l4 = 54
	}
	p := make([]byte, l4+20)
	if l4 == 34 {
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14], p[22], p[23] = 0x45, 64, 6
		binary.BigEndian.PutUint16(p[16:18], 40)
		copy(p[26:30], src.To4())
		copy(p[30:34], dst.To4())
	} else {
		binary.BigEndian.PutUint16(p[12:14], 0x86dd)
		p[14], p[20], p[21] = 0x60, 6, 64
		binary.BigEndian.PutUint16(p[18:20], 20)
		copy(p[22:38], src.To16())
		copy(p[38:54], dst.To16())
	}
	binary.BigEndian.PutUint16(p[l4:l4+2], 40000)
	binary.BigEndian.PutUint16(p[l4+2:l4+4], 443)
	p[l4+12], p[l4+13] = 0x50, 2
	return p
}
