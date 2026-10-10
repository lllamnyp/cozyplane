package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelMappedCIDRPoliciesAndRoutes(t *testing.T) {
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
	maps := map[string]*ebpf.Map{}
	for _, name := range []string{"networks", "np_cidr", "sg_cidr", "sg_egress_cidr"} {
		ms := spec.Maps[name].Copy()
		ms.Pinning = ebpf.PinNone
		mp, err := ebpf.NewMap(ms)
		if err != nil {
			t.Fatal(err)
		}
		defer mp.Close()
		maps[name] = mp
	}
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Networks: maps["networks"], NpCidr: maps["np_cidr"], SgCidr: maps["sg_cidr"], SgEgressCidr: maps["sg_egress_cidr"]}}}
	t.Run("route", func(t *testing.T) {
		if err := m.SetNetwork(101, "::ffff:192.0.2.0/120", 101); err != nil {
			t.Fatal(err)
		}
		key, _ := lpmKey(101, "192.0.2.17/32")
		var value uint32
		if err := maps["networks"].Lookup(key, &value); err != nil || value != 101 {
			t.Fatal(value, err)
		}
		key.ScopeNet = 102
		if err := maps["networks"].Lookup(key, &value); !isNotExist(err) {
			t.Fatal("mapped route crossed scope", err)
		}
	})
	t.Run("network policy", func(t *testing.T) {
		entries := []NPCidr{{ID: 10, Dir: NPDirIn, Proto: 6, Port: 443, CIDR: cidr("::ffff:192.0.2.0/120"), Allow: true}, {ID: 10, Dir: NPDirIn, Proto: 6, Port: 443, CIDR: cidr("::ffff:192.0.2.128/121"), Allow: false}}
		if err := m.SyncNPCidrs(entries); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			ip   string
			want uint8
		}{{"192.0.2.17", 1}, {"192.0.2.200", 0}} {
			a, _ := addr128(net.ParseIP(tc.ip))
			key := overlayNpCidrKey{Prefixlen: 224, Dir: npCIDRDirection(NPDirIn, 4), Proto: 6, Port: htons(443), Id: 10, Addr: a}
			var value uint8
			if err := maps["np_cidr"].Lookup(key, &value); err != nil || value != tc.want {
				t.Fatal(tc, value, err)
			}
		}
	})
	t.Run("security group containment in both directions", func(t *testing.T) {
		if err := m.SyncSGCidr([]SGCidr{{Net: 101, Proto: 6, Port: 443, CIDR: cidr("192.0.2.0/24"), AllowedGroups: 2}, {Net: 101, Proto: 6, Port: 443, CIDR: cidr("::ffff:192.0.2.128/121"), AllowedGroups: 4}}); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncSGEgressCidr([]SGEgressCidr{{SrcNet: 101, Proto: 6, Port: 443, CIDR: cidr("::ffff:192.0.2.0/120"), AllowedGroups: 2}, {SrcNet: 101, Proto: 6, Port: 443, CIDR: cidr("192.0.2.128/25"), AllowedGroups: 4}}); err != nil {
			t.Fatal(err)
		}
		a, _ := addr128(net.ParseIP("192.0.2.200"))
		var ingress, egress uint64
		if err := maps["sg_cidr"].Lookup(overlaySgCidrKey{Prefixlen: 192, Net: 101, Port: htons(443), Proto: 6 | 4<<8, Client: a}, &ingress); err != nil || ingress != 6 {
			t.Fatal("ingress union", ingress, err)
		}
		if err := maps["sg_egress_cidr"].Lookup(overlaySgEgressCidrKey{Prefixlen: 192, SrcNet: 101, Port: htons(443), Proto: 6 | 4<<8, Dest: a}, &egress); err != nil || egress != 6 {
			t.Fatal("egress union", egress, err)
		}
	})
}
