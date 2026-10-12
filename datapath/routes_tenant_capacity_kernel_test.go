package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelRouteCapacityCannotDisableOtherTenantNAT(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux environment")
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
	spec.Maps["vpc_routes"].MaxEntries = 1
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatalf("load classifier: %+v", err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Params: c.Maps["params"], Networks: c.Maps["networks"], VpcRoutes: c.Maps["vpc_routes"], RouteGuard: c.Maps["route_guard"], RouteScopes: c.Maps["route_scopes"], VpcNat: c.Maps["vpc_nat"], NatOf: c.Maps["nat_of"]}}}
	if err := c.Maps["params"].Put(cfgUplinkIfindex, uint32(2)); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["ports"].Put(uint32(1), uint32(202)); err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		name, source, network, dest, public, old, requested string
		offset, size                                        int
	}{
		{"ipv4", "10.202.0.2", "10.202.0.0/24", "198.51.100.20", "203.0.113.22", "192.0.2.0/24", "198.51.100.0/24", 26, 4},
		{"ipv6", "fd02:202::2", "fd02:202::/64", "2001:db8:20::20", "2001:db8:30::22", "2001:db8:10::/64", "2001:db8:20::/64", 22, 16},
	} {
		t.Run(family.name, func(t *testing.T) {
			source := net.ParseIP(family.source)
			if err := m.SetNetwork(202, family.network, 202); err != nil {
				t.Fatal(err)
			}
			key, _ := localKey(202, source)
			owner := SGEndpointOwner("tenant-b-port", "tenant-b-sandbox", "eth0")
			if err := c.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 1, SgOwner: owner}); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["sg_members"].Put(key, overlaySgMember{Owner: owner}); err != nil {
				t.Fatal(err)
			}
			pub4, pub6 := "", ""
			if family.size == 4 {
				pub4 = family.public
			} else {
				pub6 = family.public
			}
			if err := m.SetVPCNAT(202, pub4, pub6, NATPortBase, NATShardSpan); err != nil {
				t.Fatal(err)
			}
			old := RouteEntry{Scope: 101, CIDR: family.old}
			if err := m.SyncRoutes([]RouteEntry{old}); err != nil {
				t.Fatal(err)
			}
			packet := policyFamilyPacket(source, net.ParseIP(family.dest))
			ctx := make([]byte, 192)
			binary.LittleEndian.PutUint32(ctx[40:44], 1)
			run := func() {
				t.Helper()
				out := make([]byte, len(packet))
				got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Context: ctx})
				if err != nil || got != 7 || !net.IP(out[family.offset:family.offset+family.size]).Equal(net.ParseIP(family.public)) {
					t.Fatalf("unrelated tenant NAT verdict=%d want=7 err=%v", got, err)
				}
			}
			run() // Prove the unrelated tenant's ordinary NAT works first.
			if err := m.SyncRoutesScoped(nil, []uint32{101}); err != nil {
				t.Fatal(err)
			}
			run() // Its tenant must not lose egress due to another tenant's rows.
			if err := m.SyncRoutesScoped(nil, []uint32{202}); err != nil {
				t.Fatal(err)
			}
			got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet, Context: ctx})
			if err != nil || got != 2 {
				t.Fatalf("scoped denial bypassed: verdict=%d err=%v", got, err)
			}
			native := policyFamilyPacket(source, source)
			got, err = c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: native, Context: ctx})
			if err != nil || got != 7 {
				t.Fatalf("scoped denial blocked native delivery: verdict=%d err=%v", got, err)
			}
			if err := m.SyncRoutesScoped(nil, nil); err != nil {
				t.Fatal(err)
			}
			run()
		})
	}
}
