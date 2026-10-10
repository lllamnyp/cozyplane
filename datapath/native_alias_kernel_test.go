package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Run both real classifiers, carrying their actual packet and context output.
// A native VPC destination may also have a globally keyed fabric alias.
func TestKernelNativeVPCFabricAlias(t *testing.T) {
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
	if err := os.MkdirAll(PinRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "cozyplane_to_pod" && name != "cozyplane_from_pod" && name != "cozyplane_from_overlay" {
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
	for _, name := range []string{"ports", "locals", "fwd_cidrs", "bridges", "bridge_owners", "fabric_of"} {
		if err := c.Maps[name].Pin(filepath.Join(PinRoot, name)); err != nil {
			t.Fatal(err)
		}
		defer c.Maps[name].Unpin()
	}
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Networks: c.Maps["networks"], Gateways: c.Maps["gateways"], Params: c.Maps["params"],
		SgMembers: c.Maps["sg_members"], SgRules: c.Maps["sg_rules"], SgCidr: c.Maps["sg_cidr"],
		SgEgress: c.Maps["sg_egress"], SgEgressCidr: c.Maps["sg_egress_cidr"],
		Floating: c.Maps["floating"], FloatingEgress: c.Maps["floating_egress"], DnsIps: c.Maps["dns_ips"],
	}}}
	if err := m.SetNetwork(107, "10.244.4.0/24", 107); err != nil {
		t.Fatal(err)
	}
	srcIP, dstIP := net.ParseIP("10.244.4.2"), net.ParseIP("10.244.4.3")
	src6, dst6 := net.ParseIP("fd07::2"), net.ParseIP("fd07::3")
	if err := m.SetNetwork(107, "fd07::/64", 107); err != nil {
		t.Fatal(err)
	}
	srcMAC, _ := net.ParseMAC("02:00:00:00:0a:02")
	dstMAC, _ := net.ParseMAC("02:00:00:00:0a:03")
	create := func(name, uid, cid string, netID uint32, ips []net.IP, mac net.HardwareAddr) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(l) })
		if err := netlink.LinkSetUp(l); err != nil {
			t.Fatal(err)
		}
		if err := ConfigureEndpoint(l, netID, ips, mac, cid, "eth0", PortVethIdentity{UID: uid}, nil); err != nil {
			t.Fatal(err)
		}
		return l
	}
	source := create("cphaliassrc", "source-port", "source-sandbox", 107, []net.IP{srcIP, src6}, srcMAC)
	target := create("cphaliasdst", "target-port", "target-sandbox", 107, []net.IP{dstIP, dst6}, dstMAC)
	members := []SGMember{
		{Net: 107, IP: srcIP, Owner: SGEndpointOwner("source-port", "source-sandbox", "eth0")},
		{Net: 107, IP: dstIP, Groups: 2, Owner: SGEndpointOwner("target-port", "target-sandbox", "eth0")},
		{Net: 107, IP: src6, Owner: SGEndpointOwner("source-port", "source-sandbox", "eth0")},
		{Net: 107, IP: dst6, Groups: 2, Owner: SGEndpointOwner("target-port", "target-sandbox", "eth0")},
	}
	apply := func() {
		t.Helper()
		if err := m.ApplySecurityGroups(members, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	packet := func(src, dst net.IP, proto byte) []byte {
		p := policyFamilyPacket(src, dst)
		copy(p[:6], dstMAC)
		copy(p[6:12], srcMAC)
		off := 34
		if src.To4() == nil {
			p[20], off = proto, 54
		} else {
			p[23] = proto
		}
		binary.BigEndian.PutUint16(p[off:off+2], 40000)
		binary.BigEndian.PutUint16(p[off+2:off+4], 443)
		if proto == 17 {
			binary.BigEndian.PutUint16(p[off+4:off+6], uint16(len(p)-off))
		} else {
			p[off+12], p[off+13] = 0x50, 2
		}
		return p
	}
	check := func(t *testing.T, origin *ebpf.Program, source netlink.Link, packet []byte, initialMark, want uint32, unchanged bool) {
		t.Helper()
		ctx, outCtx := make([]byte, 192), make([]byte, 192)
		binary.LittleEndian.PutUint32(ctx[36:40], uint32(source.Attrs().Index))
		binary.LittleEndian.PutUint32(ctx[40:44], uint32(source.Attrs().Index))
		binary.LittleEndian.PutUint32(ctx[8:12], initialMark)
		out := make([]byte, len(packet))
		got, err := origin.Run(&ebpf.RunOptions{Data: packet, DataOut: out, Context: ctx, ContextOut: outCtx})
		if err != nil || got != 7 {
			t.Fatalf("origin verdict=%d want=7 err=%v", got, err)
		}
		mark := binary.LittleEndian.Uint32(outCtx[8:12])
		binary.LittleEndian.PutUint32(outCtx[40:44], uint32(target.Attrs().Index))
		delivered, deliveredCtx := make([]byte, len(out)), make([]byte, len(ctx))
		got, err = c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: out, DataOut: delivered, Context: outCtx, ContextOut: deliveredCtx})
		if err != nil || got != want {
			t.Fatalf("native ingress verdict=%d want=%d origin mark=%#x err=%v", got, want, mark, err)
		}
		if want == 0 && unchanged {
			a, b := 26, 34
			if packet[12] == 0x86 {
				a, b = 22, 54
			}
			for i := a; i < b; i++ {
				if delivered[i] != packet[i] {
					t.Fatalf("native addresses were NATed: %x -> %x", packet[a:b], delivered[a:b])
				}
			}
			if mark := binary.LittleEndian.Uint32(deliveredCtx[8:12]); mark&0x040000 != 0 {
				t.Fatalf("native routing proof leaked into pod: %#x", mark)
			}
		}
	}
	cases := []struct {
		name     string
		src, dst net.IP
		proto    byte
	}{
		{"v4-tcp", srcIP, dstIP, 6}, {"v4-udp", srcIP, dstIP, 17},
		{"v6-tcp", src6, dst6, 6}, {"v6-udp", src6, dst6, 17},
	}
	native := c.Programs["cozyplane_from_pod"]
	for _, tc := range cases {
		t.Run("native-default-deny/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 2, false) })
	}
	for _, ip := range []net.IP{dstIP, dst6} {
		if err := AddBridge(ip.String(), ip.String(), target.Attrs().Name, 107, dstMAC); err != nil {
			t.Fatal(err)
		}
	}
	const forgedMarks = uint32(0x040000 | 0x100000 | 0x200000 | 0x400000 | 0x080000)
	for _, tc := range cases {
		t.Run("same-address-fabric-default-deny/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), forgedMarks, 2, false) })
	}
	// Even matching the node address and resolver source port is insufficient
	// for a native VPC packet to enter the stateless DNS-return exemption.
	if err := m.SetResolverPort(ResolverPort); err != nil {
		t.Fatal(err)
	}
	dns4, dns6 := net.ParseIP("10.96.0.10"), net.ParseIP("fd96::10")
	if err := m.SetClusterDNS(dns4, dns6); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["params"].Put(cfgNodeIP, binary.LittleEndian.Uint32(srcIP.To4())); err != nil {
		t.Fatal(err)
	}
	node6, _ := addr128(src6)
	if err := c.Maps["node_ip6"].Put(uint32(0), node6); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run("native-resolver-lookalike/"+tc.name, func(t *testing.T) {
			p := packet(tc.src, tc.dst, tc.proto)
			off := 34
			if tc.src.To4() == nil {
				off = 54
			}
			binary.BigEndian.PutUint16(p[off:off+2], ResolverPort)
			check(t, native, source, p, forgedMarks, 2, false)
			// A real unmarked local resolver response retains its sanctioned
			// rewrite; use a distinct destination port to avoid old DNS CT.
			binary.BigEndian.PutUint16(p[off+2:off+4], 45000)
			ctx, out := make([]byte, 192), make([]byte, len(p))
			binary.LittleEndian.PutUint32(ctx[40:44], uint32(target.Attrs().Index))
			got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: p, DataOut: out, Context: ctx})
			a, b, expected := 26, 30, dns4.To4()
			if tc.src.To4() == nil {
				a, b, expected = 22, 38, dns6.To16()
			}
			if err != nil || got != 0 || string(out[a:b]) != string(expected) || binary.BigEndian.Uint16(out[off:off+2]) != 53 {
				t.Fatalf("resolver return verdict=%d err=%v source=%x want=%x", got, err, out[a:b], expected)
			}
		})
	}
	if err := m.SetResolverPort(0); err != nil {
		t.Fatal(err)
	}
	// Genuine unmarked host probes still use the global bridge, even while the
	// target's SG denies native traffic.
	for _, pair := range [][2]net.IP{{net.ParseIP("192.0.2.9"), dstIP}, {net.ParseIP("fd09::9"), dst6}} {
		t.Run("host-probe/"+pair[1].String(), func(t *testing.T) {
			ctx := make([]byte, 192)
			binary.LittleEndian.PutUint32(ctx[40:44], uint32(target.Attrs().Index))
			p := packet(pair[0], pair[1], 6)
			out := make([]byte, len(p))
			got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: p, DataOut: out, Context: ctx})
			if err != nil || got != 0 {
				t.Fatalf("host probe verdict=%d err=%v", got, err)
			}
		})
	}
	defaultIP := net.ParseIP("198.51.100.9")
	defaultSource := create("cphaliasdef", "", "default-sandbox", 0, []net.IP{defaultIP}, srcMAC)
	for _, registered := range []bool{true, false} {
		if !registered {
			if err := c.Maps["ports"].Delete(uint32(defaultSource.Attrs().Index)); err != nil {
				t.Fatal(err)
			}
		}
		t.Run("global-pod-remains-denied", func(t *testing.T) {
			check(t, native, defaultSource, packet(defaultIP, dstIP, 6), forgedMarks, 2, false)
		})
	}
	// Actual skb tunnel metadata, authenticated by the production overlay hook.
	const node = uint32(0xc0000209)
	if err := c.Maps["overlay_nodes"].Put(node, uint8(1)); err != nil {
		t.Fatal(err)
	}
	overlay := nativeAliasTunnel(t, c, 107, node)
	globalOverlay := nativeAliasTunnel(t, c, 0, node)
	for _, tc := range cases {
		t.Run("native-overlay-default-deny/"+tc.name, func(t *testing.T) { check(t, overlay, source, packet(tc.src, tc.dst, tc.proto), forgedMarks, 2, false) })
		t.Run("global-overlay-default-deny/"+tc.name, func(t *testing.T) {
			check(t, globalOverlay, source, packet(tc.src, tc.dst, tc.proto), forgedMarks, 2, false)
		})
	}
	// Explicit group rules continue to admit selected endpoints through the
	// ordinary VPC policy path, without a fabric rewrite or SG_OK shortcut.
	for i := range members {
		if members[i].IP.Equal(srcIP) || members[i].IP.Equal(src6) {
			members[i].Groups = 4
		}
	}
	var rules []SGRule
	var egress []SGEgress
	for _, proto := range []uint8{6, 17} {
		rules = append(rules, SGRule{Net: 107, SrcNet: 107, Group: 1, Proto: proto, Port: 443, Allowed: 4})
		egress = append(egress, SGEgress{SrcNet: 107, DstNet: 107, Group: 2, Proto: proto, Port: 443, Allowed: 2})
	}
	if err := m.ApplySecurityGroups(members, rules, nil, egress, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run("selected-with-explicit-rule/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
		t.Run("selected-overlay-with-explicit-rule/"+tc.name, func(t *testing.T) { check(t, overlay, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
	}
	// A resolved unselected endpoint is allowed without fabric NAT. A global
	// alias now belonging to another VNI must not displace the scoped owner.
	for i := range members {
		members[i].Groups = 0
	}
	apply()
	for _, tc := range cases {
		t.Run("native-allowed/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
		t.Run("native-overlay-allowed/"+tc.name, func(t *testing.T) { check(t, overlay, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
	}
	other4, other6 := net.ParseIP("10.244.4.88"), net.ParseIP("fd07::88")
	other := create("cphaliasother", "other-port", "other-sandbox", 207, []net.IP{other4, other6}, dstMAC)
	for _, pair := range [][2]net.IP{{dstIP, other4}, {dst6, other6}} {
		if err := AddBridge(pair[0].String(), pair[1].String(), other.Attrs().Name, 207, dstMAC); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range cases {
		t.Run("other-vni-alias-native/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
		t.Run("other-vni-alias-overlay/"+tc.name, func(t *testing.T) { check(t, overlay, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
	}
	for _, pair := range [][2]net.IP{{dstIP, other4}, {dst6, other6}} {
		if err := DelSandboxBridge(pair[0].String(), other.Attrs().Name, "other-sandbox", "eth0"); err != nil {
			t.Fatal(err)
		}
		if err := m.SetFloating(pair[0].String(), pair[1].String(), 207); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range cases {
		t.Run("other-vni-floating-native/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
		t.Run("other-vni-floating-overlay/"+tc.name, func(t *testing.T) { check(t, overlay, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true) })
	}
	// The routing mark does not bypass the current endpoint owner witness.
	replacement := create("cphaliasnext", "next-port", "next-sandbox", 107, []net.IP{dstIP, dst6}, dstMAC)
	for _, tc := range cases {
		t.Run("retired-receiver/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 2, false) })
	}
	target = replacement
	for _, tc := range cases {
		t.Run("stale-membership/"+tc.name, func(t *testing.T) { check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 2, false) })
	}
	for i := range members {
		if members[i].IP.Equal(dstIP) || members[i].IP.Equal(dst6) {
			members[i].Owner = SGEndpointOwner("next-port", "next-sandbox", "eth0")
		}
	}
	apply()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 100; round++ {
		for _, tc := range cases {
			check(t, native, source, packet(tc.src, tc.dst, tc.proto), 0, 0, true)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatalf("native replay leaked descriptors: before=%d after=%d err=%v", len(before), len(after), err)
	}
}

func nativeAliasTunnel(t *testing.T, c *ebpf.Collection, vni, node uint32) *ebpf.Program {
	t.Helper()
	callee, err := ebpf.NewMap(&ebpf.MapSpec{Name: "alias_tunnel", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = callee.Close() })
	if err := callee.Put(uint32(0), uint32(c.Programs["cozyplane_from_overlay"].FD())); err != nil {
		t.Fatal(err)
	}
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	for offset := int16(-48); offset < 0; offset += 4 {
		ins = append(ins, asm.StoreImm(asm.RFP, offset, 0, asm.Word))
	}
	ins = append(ins,
		asm.StoreImm(asm.RFP, -48, int64(vni), asm.Word),
		asm.StoreImm(asm.RFP, -44, int64(node), asm.Word),
		asm.StoreImm(asm.RFP, -20, int64(node), asm.Word),
		asm.StoreImm(asm.RFP, -27, 64, asm.Byte),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -48), asm.Mov.Imm(asm.R3, 44), asm.Mov.Imm(asm.R4, 0), asm.FnSkbSetTunnelKey.Call(),
		asm.JSLT.Imm(asm.R0, 0, "failed"),
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, callee.FD()), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 99).WithSymbol("failed"), asm.Return(),
	)
	shim, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "alias_sender", Type: ebpf.SchedCLS, License: "GPL", Instructions: ins})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shim.Close() })
	return shim
}
