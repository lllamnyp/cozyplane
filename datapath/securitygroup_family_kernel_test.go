package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelSpecificSecurityGroupCIDRFamilies(t *testing.T) {
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
		if name != "cozyplane_from_pod" && name != "cozyplane_to_pod" {
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
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Params: c.Maps["params"], Networks: c.Maps["networks"],
		SgMembers: c.Maps["sg_members"], SgRules: c.Maps["sg_rules"], SgCidr: c.Maps["sg_cidr"], SgEgress: c.Maps["sg_egress"], SgEgressCidr: c.Maps["sg_egress_cidr"]}}}
	context := make([]byte, 192)
	binary.LittleEndian.PutUint32(context[40:44], 1)
	if err := c.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
		t.Fatal(err)
	}
	owner := [4]uint64{1}
	for _, tc := range []struct {
		name, prefix, src, dst string
		allowed, legacy        bool
	}{
		{"native IPv6 range rejects IPv4", "64:ff9b::/96", "198.51.100.10", "203.0.113.20", false, false},
		{"native IPv6 range admits IPv6", "64:ff9b::/96", "64:ff9b::198.51.100.10", "64:ff9b::203.0.113.20", true, false},
		{"IPv4 range admits IPv4", "0.0.0.0/0", "198.51.100.10", "203.0.113.20", true, false},
		{"IPv4 range rejects native IPv6", "0.0.0.0/0", "64:ff9b::198.51.100.10", "64:ff9b::203.0.113.20", false, false},
		{"mapped input admits IPv4", "::ffff:0.0.0.0/96", "198.51.100.10", "203.0.113.20", true, false},
		{"native IPv6 wildcard admits IPv6", "::/0", "2001:db8::10", "2001:db8::20", true, false},
		{"legacy keys reject IPv4", "::/0", "198.51.100.10", "203.0.113.20", false, true},
		{"legacy keys reject IPv6", "::/0", "2001:db8::10", "2001:db8::20", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := net.ParseIP(tc.src), net.ParseIP(tc.dst)
			data := policyFamilyPacket(src, dst)
			for _, egress := range []bool{false, true} {
				self := dst
				if egress {
					self = src
				}
				key, _ := localKey(101, self)
				if err := c.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 1, SgOwner: owner}); err != nil {
					t.Fatal(err)
				}
				members := []SGMember{{Net: 101, IP: self, Groups: 2, Owner: owner}}
				var ingress []SGCidr
				var out []SGEgressCidr
				if !tc.legacy {
					if egress {
						out = []SGEgressCidr{{SrcNet: 101, Proto: 6, Port: 443, CIDR: cidr(tc.prefix), AllowedGroups: 2}}
					} else {
						ingress = []SGCidr{{Net: 101, Proto: 6, Port: 443, CIDR: cidr(tc.prefix), AllowedGroups: 2}}
					}
				}
				if err := m.ApplySecurityGroups(members, nil, ingress, nil, out); err != nil {
					t.Fatal(err)
				}
				if tc.legacy {
					if egress {
						if err := c.Maps["sg_egress_cidr"].Put(overlaySgEgressCidrKey{Prefixlen: 64, SrcNet: 101, Proto: 6, Port: htons(443)}, uint64(2)); err != nil {
							t.Fatal(err)
						}
					} else {
						if err := c.Maps["sg_cidr"].Put(overlaySgCidrKey{Prefixlen: 64, Net: 101, Proto: 6, Port: htons(443)}, uint64(2)); err != nil {
							t.Fatal(err)
						}
					}
				}
				program, want := "cozyplane_to_pod", uint32(2)
				binary.LittleEndian.PutUint32(context[8:12], 0x080000) // trusted forwarded ingress
				if tc.allowed {
					want = 0
				}
				if egress {
					program = "cozyplane_from_pod"
					binary.LittleEndian.PutUint32(context[8:12], 0)
					gw, _ := addr128(net.ParseIP("2001:db8:ffff::1"))
					if err := c.Maps["gateways"].Put(uint32(101), overlayGwEntry{GwIp: gw}); err != nil {
						t.Fatal(err)
					}
					if err := c.Maps["locals"].Put(overlayLocalKey{Net: 101, Ip: gw}, overlayEndpoint{Ifindex: 2}); err != nil {
						t.Fatal(err)
					}
					if tc.allowed {
						want = 7
					} // actual local gateway redirect
				}
				got, err := c.Programs[program].Run(&ebpf.RunOptions{Data: data, Context: context})
				if err != nil || got != want {
					t.Fatalf("egress=%v verdict=%d want=%d err=%v", egress, got, want, err)
				}
				if err := c.Maps["locals"].Delete(key); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
