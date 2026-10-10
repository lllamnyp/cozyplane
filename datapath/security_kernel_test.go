package datapath

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
)

// Run only in an isolated privileged Linux test environment; this collection
// has no pinned maps and never touches the agent's live datapath.
func TestKernelQuarantinePrecedesProtocolBypasses(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("set COZYPLANE_BPF_TEST=1 in an isolated privileged Linux container")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := loadOverlay()
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if name != "cozyplane_from_pod" && name != "cozyplane_to_pod" && name != "cozyplane_from_overlay" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	collection, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	if err := collection.Maps["ports"].Put(uint32(1), QuarantineNet); err != nil {
		t.Fatal(err)
	}
	context := make([]byte, 192)                     // Linux __sk_buff test-run context
	binary.LittleEndian.PutUint32(context[40:44], 1) // loopback's ifindex
	packets := map[string][]byte{
		"arp":                 make([]byte, 42),
		"gateway-source-ipv4": make([]byte, 54),
		"link-local-ipv6":     make([]byte, 74),
	}
	binary.BigEndian.PutUint16(packets["arp"][12:14], 0x0806)
	v4 := packets["gateway-source-ipv4"]
	binary.BigEndian.PutUint16(v4[12:14], 0x0800)
	v4[14], v4[23] = 0x45, 6
	binary.BigEndian.PutUint16(v4[16:18], uint16(len(v4)-14))
	copy(v4[26:30], []byte{169, 254, 1, 1})
	copy(v4[30:34], []byte{10, 0, 0, 2})
	v6 := packets["link-local-ipv6"]
	binary.BigEndian.PutUint16(v6[12:14], 0x86dd)
	v6[14], v6[20], v6[22], v6[23] = 0x60, 58, 0xfe, 0x80
	for name, prog := range collection.Programs {
		if name == "cozyplane_from_overlay" {
			continue
		}
		for packetName, packet := range packets {
			t.Run(name+"/"+packetName, func(t *testing.T) {
				verdict, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: context})
				if err != nil {
					t.Fatal(err)
				}
				if verdict != 2 {
					t.Fatalf("quarantined packet verdict = %d, want TC_ACT_SHOT", verdict)
				}
			})
		}
	}
	// Remove quarantine: unsupported IP headers must independently fail closed.
	if err := collection.Maps["ports"].Put(uint32(1), uint32(0)); err != nil {
		t.Fatal(err)
	}
	options := append([]byte(nil), v4...)
	options[14] = 0x46
	fragment := append([]byte(nil), v4...)
	binary.BigEndian.PutUint16(fragment[20:22], 0x2000)
	extension := append([]byte(nil), v6...)
	extension[20] = 60
	for name, prog := range collection.Programs {
		if name == "cozyplane_from_overlay" {
			continue
		}
		for kind, packet := range map[string][]byte{"ipv4-options": options, "ipv4-fragment": fragment, "ipv6-extension": extension} {
			t.Run(name+"/unsupported-"+kind, func(t *testing.T) {
				verdict, err := prog.Run(&ebpf.RunOptions{Data: packet, Context: context})
				if err != nil {
					t.Fatal(err)
				}
				if verdict != 2 {
					t.Fatalf("unsupported IP header passed policy: verdict=%d", verdict)
				}
			})
		}
	}
	packet := append([]byte(nil), v4...)
	copy(packet[26:30], []byte{10, 1, 1, 2})
	copy(packet[30:34], []byte{192, 0, 2, 9})
	address, err := addr128([]byte{10, 1, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	key := overlayLocalKey{Net: 0, Ip: address}
	if err := collection.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 2}); err != nil {
		t.Fatal(err)
	}
	fromPod := collection.Programs["cozyplane_from_pod"]
	verdict, err := fromPod.Run(&ebpf.RunOptions{Data: packet, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("default-network source spoof accepted: verdict=%d err=%v", verdict, err)
	}
	if err := collection.Maps["locals"].Put(key, overlayEndpoint{Ifindex: 1}); err != nil {
		t.Fatal(err)
	}
	const privateMarks = uint32(0x100000 | 0x200000 | 0x400000 | 0x080000)
	binary.LittleEndian.PutUint32(context[8:12], privateMarks|0x4000)
	output := make([]byte, len(context))
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: packet, Context: context, ContextOut: output})
	if err != nil || verdict != 0 {
		t.Fatalf("legitimate source rejected: verdict=%d err=%v", verdict, err)
	}
	mark := binary.LittleEndian.Uint32(output[8:12])
	if mark&privateMarks != 0 || mark&0x4000 == 0 {
		t.Fatalf("forged private marks survived or platform mark lost: %#x", mark)
	}
	verdict, err = collection.Programs["cozyplane_from_overlay"].Run(&ebpf.RunOptions{Data: packet, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("overlay accepted missing tunnel identity: verdict=%d err=%v", verdict, err)
	}
	testOverlayTunnelAuthorization(t, collection, packet, context)
	if err := collection.Maps["np_ident"].Put(address, overlayNpIdentVal{Id: 11, Flags: 3}); err != nil {
		t.Fatal(err)
	}
	udp := append([]byte(nil), packet...)
	udp[23] = 17
	binary.BigEndian.PutUint16(udp[34:36], 50000)
	binary.BigEndian.PutUint16(udp[36:38], 53)
	dst, err := addr128([]byte{192, 0, 2, 9})
	if err != nil {
		t.Fatal(err)
	}
	ctKey := overlayNpCtKey{Pod: address, Peer: dst, Pport: 0x50c3, Rport: 0x3500, Proto: 17}
	for _, knownPod := range []bool{false, true} {
		if knownPod {
			if err := collection.Maps["np_ident"].Put(dst, overlayNpIdentVal{Id: 12}); err != nil {
				t.Fatal(err)
			}
		}
		verdict, err = fromPod.Run(&ebpf.RunOptions{Data: udp, Context: context})
		if err != nil || verdict != 2 {
			t.Fatalf("egress deny bypassed (knownPod=%v): verdict=%d err=%v", knownPod, verdict, err)
		}
		var pin uint8
		if err := collection.Maps["np_ct"].Lookup(ctKey, &pin); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("denied UDP left an ingress authorization: pin=%d err=%v", pin, err)
		}
	}
	allow := overlayNpAllowKey{Prefixlen: 176, Dir: 1, Proto: 17, SrcId: 11, Port: 0x3500}
	if err := collection.Maps["np_allow"].Put(allow, uint8(1)); err != nil {
		t.Fatal(err)
	}
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: udp, Context: context})
	if err != nil || verdict != 0 {
		t.Fatalf("authorized UDP rejected: verdict=%d err=%v", verdict, err)
	}
	var pin uint8
	if err := collection.Maps["np_ct"].Lookup(ctKey, &pin); err != nil || pin != 1 {
		t.Fatalf("authorized UDP not tracked: pin=%d err=%v", pin, err)
	}
	spoof6 := append([]byte(nil), v6...)
	spoof6[20] = 6
	copy(spoof6[22:38], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9})
	copy(spoof6[38:54], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: spoof6, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("IPv6 bridge bypassed source authentication: verdict=%d err=%v", verdict, err)
	}
	// Valid control protocols must still work without a globally assigned source.
	if err := collection.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
		t.Fatal(err)
	}
	ndp := append([]byte(nil), v6...)
	ndp[21], ndp[54], ndp[55] = 255, 135, 0
	copy(ndp[38:54], []byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0, 0, 1})
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: ndp, Context: context})
	if err != nil || verdict != 0 {
		t.Fatalf("valid NDP rejected: %d %v", verdict, err)
	}
	ndp[21] = 64
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: ndp, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("NDP with invalid hop limit accepted: %d %v", verdict, err)
	}
	dhcp := append([]byte(nil), ndp...)
	dhcp[20] = 17
	copy(dhcp[38:54], []byte{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2})
	binary.BigEndian.PutUint16(dhcp[54:56], 546)
	binary.BigEndian.PutUint16(dhcp[56:58], 547)
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: dhcp, Context: context})
	if err != nil || verdict != 0 {
		t.Fatalf("valid DHCPv6 rejected: %d %v", verdict, err)
	}
	binary.BigEndian.PutUint16(dhcp[54:56], 50000)
	verdict, err = fromPod.Run(&ebpf.RunOptions{Data: dhcp, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("arbitrary link-local UDP accepted: %d %v", verdict, err)
	}
	toPod := collection.Programs["cozyplane_to_pod"]
	for _, proto := range []byte{6, 17} {
		incoming := append([]byte(nil), v6...)
		incoming[20] = proto
		copy(incoming[38:54], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
		binary.BigEndian.PutUint16(incoming[54:56], 50000)
		binary.BigEndian.PutUint16(incoming[56:58], 443)
		incoming[67] = 2 // TCP SYN; ignored for UDP.
		for _, source := range []byte{0xfe, 0xff} {
			incoming[22] = source
			verdict, err = toPod.Run(&ebpf.RunOptions{Data: incoming, Context: context})
			if err != nil || verdict != 2 {
				t.Fatalf("link-scoped application ingress bypassed policy (protocol=%d source=%x): %d %v", proto, source, verdict, err)
			}
		}
	}
	ndp[21] = 255
	for _, kind := range []byte{134, 135, 136} {
		ndp[54] = kind
		verdict, err = toPod.Run(&ebpf.RunOptions{Data: ndp, Context: context})
		if err != nil || verdict != 0 {
			t.Fatalf("valid ingress NDP type %d rejected: %d %v", kind, verdict, err)
		}
	}
	ndp[21] = 64
	verdict, err = toPod.Run(&ebpf.RunOptions{Data: ndp, Context: context})
	if err != nil || verdict != 2 {
		t.Fatalf("ingress NDP with invalid hop limit accepted: %d %v", verdict, err)
	}
	binary.BigEndian.PutUint16(dhcp[54:56], 547)
	binary.BigEndian.PutUint16(dhcp[56:58], 546)
	verdict, err = toPod.Run(&ebpf.RunOptions{Data: dhcp, Context: context})
	if err != nil || verdict != 0 {
		t.Fatalf("valid ingress DHCPv6 rejected: %d %v", verdict, err)
	}
	// Host probes still use the sanctioned fabric bridge, which explicitly
	// translates their source to fe80::1 after admission.
	probe := append([]byte(nil), v6...)
	probe[20], probe[21], probe[22], probe[23] = 6, 64, 0x20, 1
	probe[24], probe[25], probe[37] = 0x0d, 0xb8, 99
	copy(probe[38:54], []byte{0x20, 1, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(probe[54:56], 50000)
	binary.BigEndian.PutUint16(probe[56:58], 443)
	probe[67] = 2
	fabric := overlayAddr128{}
	copy(fabric.B[:], probe[38:54])
	vpc := fabric
	vpc.B[5] = 0
	if err := collection.Maps["bridges"].Put(fabric, overlayBridgeEp{Net: 101, VpcIp: vpc}); err != nil {
		t.Fatal(err)
	}
	hostContext := append([]byte(nil), context...)
	binary.LittleEndian.PutUint32(hostContext[8:12], 0)
	translated := make([]byte, len(probe))
	verdict, err = toPod.Run(&ebpf.RunOptions{Data: probe, DataOut: translated, Context: hostContext})
	if err != nil || verdict != 0 || translated[22] != 0xfe || translated[23] != 0x80 || translated[37] != 1 || translated[43] != 0 {
		t.Fatalf("IPv6 fabric probe failed or was not translated: verdict=%d err=%v packet=%x", verdict, err, translated)
	}
	// A selected group without an ID is default-deny, even though no rules
	// can yet be compiled for it. Other resolved groups still union normally.
	membership := overlayLocalKey{Net: 101, Ip: vpc}
	binary.LittleEndian.PutUint32(hostContext[8:12], 0x400000) // NS_MARK
	for _, ids := range [][]int32{{0}, {-1}, {63}, {64}} {
		if err := collection.Maps["sg_members"].Put(membership, overlaySgMember{Groups: SGMembershipBitmap(ids)}); err != nil {
			t.Fatal(err)
		}
		verdict, err = toPod.Run(&ebpf.RunOptions{Data: probe, Context: hostContext})
		if err != nil || verdict != 2 {
			t.Fatalf("unresolved membership opened ingress: ids=%v verdict=%d err=%v", ids, verdict, err)
		}
	}
	if err := collection.Maps["sg_members"].Put(membership, overlaySgMember{Groups: SGMembershipBitmap([]int32{0, 2})}); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["sg_rules"].Put(overlaySgRuleKey{Net: 101, SrcNet: 101, Group: 2, Port: 0xbb01, Proto: 6}, uint64(1)<<SGWorldGroup); err != nil {
		t.Fatal(err)
	}
	verdict, err = toPod.Run(&ebpf.RunOptions{Data: probe, Context: hostContext})
	if err != nil || verdict != 0 {
		t.Fatalf("pending group suppressed another resolved group's grant: %d %v", verdict, err)
	}
	forged := append([]byte(nil), packet...)
	forged[23] = 17
	binary.BigEndian.PutUint16(forged[34:36], 50000)
	binary.BigEndian.PutUint16(forged[36:38], 443)
	for _, reserved := range [][]byte{{169, 254, 1, 1}, {169, 254, 42, 1}} {
		copy(forged[26:30], reserved)
		reservedIP, err := addr128(reserved)
		if err != nil {
			t.Fatal(err)
		}
		// Both an explicit source record and a forwarding grant must fail:
		// these addresses are proof only when assigned by host NAT.
		for _, forwarding := range []bool{false, true} {
			rawNet := uint32(0)
			if forwarding {
				rawNet |= PortForwardFlag
			}
			if err := collection.Maps["ports"].Put(uint32(1), rawNet); err != nil {
				t.Fatal(err)
			}
			if forwarding {
				if err := collection.Maps["locals"].Delete(overlayLocalKey{Net: 0, Ip: reservedIP}); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := collection.Maps["locals"].Put(overlayLocalKey{Net: 0, Ip: reservedIP}, overlayEndpoint{Ifindex: 1}); err != nil {
					t.Fatal(err)
				}
			}
			verdict, err = fromPod.Run(&ebpf.RunOptions{Data: forged, Context: context})
			if err != nil || verdict != 2 {
				t.Fatalf("host NAT source impersonation admitted: source=%v forwarding=%v verdict=%d err=%v", reserved, forwarding, verdict, err)
			}
		}
	}
}

// Populate real skb tunnel metadata and tail-call the production overlay hook.
// No live links or pinned state are used.
func testOverlayTunnelAuthorization(t *testing.T, collection *ebpf.Collection, packet, context []byte) {
	t.Helper()
	callee, err := ebpf.NewMap(&ebpf.MapSpec{Name: "test_overlay", Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer callee.Close()
	if err := callee.Put(uint32(0), uint32(collection.Programs["cozyplane_from_overlay"].FD())); err != nil {
		t.Fatal(err)
	}
	const node = uint32(0xc0000209) // 192.0.2.9 in tunnel helper host order
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	for offset := int16(-48); offset < 0; offset += 4 {
		ins = append(ins, asm.StoreImm(asm.RFP, offset, 0, asm.Word))
	}
	ins = append(ins,
		asm.StoreImm(asm.RFP, -44, int64(node), asm.Word),
		// set_tunnel_key writes local_ipv4 into metadata's source; the receive
		// helper reads that source back as remote_ipv4.
		asm.StoreImm(asm.RFP, -20, int64(node), asm.Word),
		asm.StoreImm(asm.RFP, -27, 64, asm.Byte),
		asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -48), asm.Mov.Imm(asm.R3, 44), asm.Mov.Imm(asm.R4, 0), asm.FnSkbSetTunnelKey.Call(),
		asm.JSLT.Imm(asm.R0, 0, "failed"),
		asm.Mov.Reg(asm.R1, asm.R6), asm.LoadMapPtr(asm.R2, callee.FD()), asm.Mov.Imm(asm.R3, 0), asm.FnTailCall.Call(),
		asm.Mov.Imm(asm.R0, 99).WithSymbol("failed"), asm.Return(),
	)
	shim, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "test_tunnel", Type: ebpf.SchedCLS, License: "GPL", Instructions: ins})
	if err != nil {
		t.Fatal(err)
	}
	defer shim.Close()
	check := func(want uint32) {
		t.Helper()
		verdict, err := shim.Run(&ebpf.RunOptions{Data: packet, Context: context})
		if err != nil || verdict != want {
			t.Fatalf("tunnel provenance verdict=%d want=%d err=%v", verdict, want, err)
		}
	}
	check(2)
	if err := collection.Maps["overlay_nodes"].Put(node, uint8(1)); err != nil {
		t.Fatal(err)
	}
	check(0)
	if err := collection.Maps["overlay_nodes"].Delete(node); err != nil {
		t.Fatal(err)
	}
	check(2)
}
