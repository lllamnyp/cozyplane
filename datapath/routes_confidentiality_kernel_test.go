package datapath

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Execute the production classifier with real NAT state and a one-row route
// table. No pins, cluster objects or host interfaces are changed.
func TestKernelRouteFailureCannotFallBackToCleartextNAT(t *testing.T) {
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
		t.Fatalf("load classifiers: %+v", err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], Networks: c.Maps["networks"], VpcRoutes: c.Maps["vpc_routes"],
		RouteGuard: c.Maps["route_guard"], RouteScopes: c.Maps["route_scopes"],
		VpcNat: c.Maps["vpc_nat"], NatOf: c.Maps["nat_of"],
	}}}
	if err := c.Maps["params"].Put(cfgUplinkIfindex, uint32(2)); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
		t.Fatal(err)
	}
	for _, family := range []struct {
		name, source, dest, network, public string
		offset                              int
	}{
		{"ipv4", "10.0.0.2", "198.51.100.20", "10.0.0.0/24", "203.0.113.10", 26},
		{"ipv6", "fd01::2", "2001:db8:20::20", "fd01::/64", "2001:db8:30::10", 22},
	} {
		t.Run(family.name, func(t *testing.T) {
			source, dest := net.ParseIP(family.source), net.ParseIP(family.dest)
			if err := m.SetNetwork(101, family.network, 101); err != nil {
				t.Fatal(err)
			}
			key, _ := localKey(101, source)
			owner := SGEndpointOwner("source-port", "source-sandbox", "eth0")
			if err := c.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 1, SgOwner: owner}); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["sg_members"].Put(key, overlaySgMember{Owner: owner}); err != nil {
				t.Fatal(err)
			}
			pub4, pub6 := "", ""
			if source.To4() != nil {
				pub4 = family.public
			} else {
				pub6 = family.public
			}
			if err := m.SetVPCNAT(101, pub4, pub6, NATPortBase, NATShardSpan); err != nil {
				t.Fatal(err)
			}
			old := RouteEntry{Scope: 101, CIDR: "192.0.2.0/24", GwIP: net.ParseIP("10.0.0.1")}
			if err := m.SyncRoutes([]RouteEntry{old}); err != nil {
				t.Fatal(err)
			}
			packet, ctx := policyFamilyPacket(source, dest), make([]byte, 192)
			binary.LittleEndian.PutUint32(ctx[40:44], 1)
			run := func(want uint32, unchanged bool) {
				t.Helper()
				out := make([]byte, len(packet))
				got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet, DataOut: out, Context: ctx})
				end := family.offset + 16
				if source.To4() != nil {
					end = family.offset + 4
				}
				if err != nil || got != want || (unchanged && !bytes.Equal(out[family.offset:end], packet[family.offset:end])) {
					t.Fatalf("verdict=%d want=%d err=%v source=%s original=%s", got, want, err, net.IP(out[family.offset:end]), source)
				}
				if want == 7 && !unchanged && !net.IP(out[family.offset:end]).Equal(net.ParseIP(family.public)) {
					t.Fatalf("ordinary NAT control did not emit expected public source: %s", net.IP(out[family.offset:end]))
				}
			}
			// Positive control: a genuine route miss can use ordinary VPC NAT.
			run(7, false)
			newRoute := RouteEntry{Scope: 101, CIDR: family.dest + "/128", GwIP: net.ParseIP("10.0.0.1")}
			if source.To4() != nil {
				newRoute.CIDR = "198.51.100.0/24"
			}
			if err := m.SyncRoutes([]RouteEntry{old, newRoute}); err == nil {
				t.Fatal("oversized snapshot accepted")
			}
			// This prefix was requested for a tunnel: emitting an SNAT packet is
			// a confidentiality failure, even though the old row survived.
			run(2, true)
			if err := m.SyncRoutes([]RouteEntry{newRoute}); err != nil {
				t.Fatal(err)
			}
			// Route exists but its local appliance is absent: fail closed.
			run(2, true)
			// An explicit remote leg may never fall through to the host's
			// ordinary routing stack while Geneve transport is unavailable.
			remote := newRoute
			remote.NodeIP = net.ParseIP("192.0.2.9")
			if err := m.SyncRoutes([]RouteEntry{remote}); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["params"].Put(cfgGeneveIfindex, uint32(0)); err != nil {
				t.Fatal(err)
			}
			run(2, true)
			if err := c.Maps["params"].Put(cfgGeneveIfindex, uint32(1)); err != nil {
				t.Fatal(err)
			}
			run(7, true) // source preserved inside Geneve, rather than public SNAT
			if err := m.SyncRoutes([]RouteEntry{newRoute}); err != nil {
				t.Fatal(err)
			}
			// A failed kernel write also keeps the guard closed until recovery.
			closed, err := c.Maps["vpc_routes"].Clone()
			if err != nil {
				t.Fatal(err)
			}
			if err := closed.Close(); err != nil {
				t.Fatal(err)
			}
			m.objs.VpcRoutes = closed
			if err := m.SyncRoutes([]RouteEntry{old}); err == nil {
				t.Fatal("closed route map accepted publication")
			}
			m.objs.VpcRoutes = c.Maps["vpc_routes"]
			run(2, true)
			// No next hop is an explicit blackhole, including TCP replies.
			blackhole := newRoute
			blackhole.GwIP = nil
			if err := m.SyncRoutes([]RouteEntry{blackhole}); err != nil {
				t.Fatal(err)
			}
			run(2, true)
			off := len(packet) - 20
			packet[off+13] = 0x10
			run(2, true)
			packet[off+13] = 2
			if err := m.SyncRoutes(nil); err != nil {
				t.Fatal(err)
			}
			run(7, false)
			if err := m.BlockRoutes(); err != nil {
				t.Fatal(err)
			}
			run(2, true)
			// Native delivery in the source VPC stays available while guarded.
			native := policyFamilyPacket(source, source)
			got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: native, Context: ctx})
			if err != nil || got != 7 {
				t.Fatalf("route guard blocked same-VPC delivery: verdict=%d err=%v", got, err)
			}
			if err := m.SyncRoutes(nil); err != nil {
				t.Fatal(err)
			}
			if err := m.SyncRoutes([]RouteEntry{{Scope: 101, CIDR: "invalid"}}); err == nil {
				t.Fatal("invalid route accepted")
			}
			run(2, true)
			if err := m.SyncRoutes(nil); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 100; i++ {
				if err := m.SyncRoutes([]RouteEntry{old, newRoute}); err == nil {
					t.Fatal("capacity unexpectedly available")
				}
				run(2, true)
				if err := m.SyncRoutes(nil); err != nil {
					t.Fatal(err)
				}
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) != len(before) {
				t.Fatalf("route failure/recovery leaked descriptors: before=%d after=%d err=%v", len(before), len(after), err)
			}
		})
	}
}

func TestKernelOverlayExplicitRoutePrecedesDefaultGateway(t *testing.T) {
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
		if name != "cozyplane_from_overlay" {
			delete(spec.Programs, name)
		}
	}
	for _, mp := range spec.Maps {
		mp.Pinning = ebpf.PinNone
	}
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatalf("load classifier: %+v", err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{VpcRoutes: c.Maps["vpc_routes"], RouteGuard: c.Maps["route_guard"], RouteScopes: c.Maps["route_scopes"], Networks: c.Maps["networks"]}}}
	const vni, node = uint32(101), uint32(0xc0000209)
	if err := c.Maps["overlay_nodes"].Put(node, uint8(1)); err != nil {
		t.Fatal(err)
	}
	shim := nativeAliasTunnel(t, c, vni, node)
	gwIP, rtIP := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.10")
	gw, _ := addr128(gwIP)
	if err := c.Maps["gateways"].Put(vni, overlayGwEntry{GwIp: gw}); err != nil {
		t.Fatal(err)
	}
	mac := [6]uint8{2, 0, 0, 0, 0, 10}
	for i, ip := range []net.IP{gwIP, rtIP} {
		key, _ := localKey(vni, ip)
		epMAC := mac
		epMAC[5] = uint8(i + 1)
		if err := c.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 1, Mac: epMAC}); err != nil {
			t.Fatal(err)
		}
	}
	for _, family := range []struct{ name, source, dest, prefix string }{
		{"ipv4", "10.0.0.2", "198.51.100.20", "198.51.100.0/24"},
		{"ipv6", "fd01::2", "2001:db8:20::20", "2001:db8:20::/64"},
	} {
		t.Run(family.name, func(t *testing.T) {
			if err := m.SyncRoutes([]RouteEntry{{Scope: vni, CIDR: family.prefix, GwIP: rtIP}}); err != nil {
				t.Fatal(err)
			}
			packet := policyFamilyPacket(net.ParseIP(family.source), net.ParseIP(family.dest))
			out := make([]byte, len(packet))
			got, err := shim.Run(&ebpf.RunOptions{Data: packet, DataOut: out})
			wantMAC := mac
			wantMAC[5] = 2
			if err != nil || got != 7 || !bytes.Equal(out[:6], wantMAC[:]) {
				t.Fatalf("routed tunnel delivered to wrong leg: verdict=%d err=%v MAC=%x want=%x", got, err, out[:6], wantMAC)
			}
			// If the prefix is native/peered, neither appliance may intercept
			// nonlocal delivery. Migration/fabric plumbing follows afterwards.
			if err := m.SetNetwork(vni, family.prefix, vni); err != nil {
				t.Fatal(err)
			}
			got, err = shim.Run(&ebpf.RunOptions{Data: packet})
			if err != nil || got != 0 {
				t.Fatalf("native prefix intercepted by appliance: verdict=%d err=%v", got, err)
			}
			if err := m.DelNetwork(vni, family.prefix); err != nil {
				t.Fatal(err)
			}
			checkDrop := func() {
				t.Helper()
				got, err := shim.Run(&ebpf.RunOptions{Data: packet})
				if err != nil || got != 2 {
					t.Fatalf("unusable route fell back to gateway: verdict=%d err=%v", got, err)
				}
			}
			if err := m.SyncRoutes([]RouteEntry{{Scope: vni, CIDR: family.prefix}}); err != nil {
				t.Fatal(err)
			}
			checkDrop()
			if err := m.SyncRoutes([]RouteEntry{{Scope: vni, CIDR: family.prefix, GwIP: net.ParseIP("10.0.0.99")}}); err != nil {
				t.Fatal(err)
			}
			checkDrop()
			if err := m.SyncRoutes([]RouteEntry{{Scope: vni, CIDR: family.prefix, GwIP: rtIP, NodeIP: net.ParseIP("192.0.2.10")}}); err != nil {
				t.Fatal(err)
			}
			checkDrop()
			if err := m.SyncRoutes(nil); err != nil {
				t.Fatal(err)
			}
			got, err = shim.Run(&ebpf.RunOptions{Data: packet, DataOut: out})
			wantMAC[5] = 1
			if err != nil || got != 7 || !bytes.Equal(out[:6], wantMAC[:]) {
				t.Fatalf("ordinary miss failed default gateway: verdict=%d err=%v MAC=%x", got, err, out[:6])
			}
			if err := m.BlockRoutes(); err != nil {
				t.Fatal(err)
			}
			checkDrop()
		})
	}
}
