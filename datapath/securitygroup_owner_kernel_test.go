package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestKernelLocalSecurityGroupAddressReuse(t *testing.T) {
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
		if name != "cozyplane_to_pod" && name != "cozyplane_from_pod" {
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
	for _, name := range []string{"ports", "locals", "fwd_cidrs"} {
		if err := c.Maps[name].Pin(filepath.Join(PinRoot, name)); err != nil {
			t.Fatal(err)
		}
		defer c.Maps[name].Unpin()
	}
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Networks: c.Maps["networks"], Gateways: c.Maps["gateways"],
		Params: c.Maps["params"], SgMembers: c.Maps["sg_members"], SgRules: c.Maps["sg_rules"],
		SgCidr: c.Maps["sg_cidr"], SgEgress: c.Maps["sg_egress"], SgEgressCidr: c.Maps["sg_egress_cidr"],
	}}}
	ip := net.ParseIP("10.0.0.2")
	a, _ := addr128(ip)
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	create := func(name, uid, cid string, staged ...bool) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(l) })
		if err := ConfigureEndpoint(l, 100, []net.IP{ip}, mac, cid, "eth0", PortVethIdentity{UID: uid, Staged: len(staged) > 0 && staged[0]}, nil); err != nil {
			t.Fatal(err)
		}
		return l
	}
	if err := c.Maps["bridges"].Put(a, overlayBridgeEp{Net: 100, VpcIp: a}); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 54)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[16:18], 40)
	copy(packet[26:30], []byte{198, 51, 100, 10})
	copy(packet[30:34], ip.To4())
	binary.BigEndian.PutUint16(packet[34:36], 40000)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46], packet[47] = 0x50, 2
	check := func(link netlink.Link, want uint32) {
		t.Helper()
		ctx := make([]byte, 192)
		binary.LittleEndian.PutUint32(ctx[40:44], uint32(link.Attrs().Index))
		binary.LittleEndian.PutUint32(ctx[8:12], 0x400000)
		got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: packet, Context: ctx})
		if err != nil || got != want {
			t.Fatalf("verdict=%d want=%d err=%v", got, want, err)
		}
	}
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	old := create("cphsgold", "old-port", "old-sandbox")
	oldMember := SGMember{Net: 100, IP: ip, Groups: 2, Owner: SGEndpointOwner("old-port", "old-sandbox", "eth0")}
	apply := func(mem SGMember) {
		t.Helper()
		if err := m.ApplySecurityGroups([]SGMember{mem}, nil, []SGCidr{{Net: 100, Proto: 6, Port: 443, CIDR: all, AllowedGroups: 2}}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	apply(oldMember)
	check(old, 0)
	replacement := create("cphsgnew", "new-port", "new-sandbox")
	check(replacement, 2)
	apply(oldMember) // a stale informer pass must not reopen predecessor rights
	check(replacement, 2)
	newMember := SGMember{Net: 100, IP: ip, Groups: 2, Owner: SGEndpointOwner("new-port", "new-sandbox", "eth0")}
	apply(newMember)
	check(replacement, 0)
	check(old, 2) // retired receiving veth cannot borrow the replacement's bitmap
	// A public projection must resolve to the same current receiving interface.
	public := net.ParseIP("203.0.113.20")
	publicKey, _ := addr128(public)
	if err := c.Maps["floating"].Put(publicKey, overlayBridgeEp{Net: 100, VpcIp: a}); err != nil {
		t.Fatal(err)
	}
	copy(packet[30:34], public.To4())
	check(replacement, 0)
	check(old, 2)
	copy(packet[30:34], ip.To4())
	if err := c.Maps["floating"].Delete(publicKey); err != nil {
		t.Fatal(err)
	}
	// Reusing a fabric address on the default network must not consume a stale
	// VPC bridge, even when that bridge's current SG membership would allow it.
	defaultLink := func(name, cid string) netlink.Link {
		t.Helper()
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}); err != nil {
			t.Fatal(err)
		}
		l, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(l) })
		if err := ConfigureEndpoint(l, 0, []net.IP{ip}, mac, cid, "eth0", PortVethIdentity{}, nil); err != nil {
			t.Fatal(err)
		}
		return l
	}
	defaultOld := defaultLink("cphdefold", "default-old")
	defaultNew := defaultLink("cphdefnew", "default-new")
	check(defaultNew, 2)
	if err := c.Maps["bridges"].Delete(a); err != nil {
		t.Fatal(err)
	}
	check(defaultNew, 0)
	check(defaultOld, 2)
	if err := c.Maps["bridges"].Put(a, overlayBridgeEp{Net: 100, VpcIp: a}); err != nil {
		t.Fatal(err)
	}
	// Identical private addresses in a different VNI do not displace this owner.
	otherKey, _ := localKey(200, ip)
	if err := c.Maps["locals"].Put(otherKey, overlayEndpoint{Ifindex: uint32(defaultOld.Attrs().Index)}); err != nil {
		t.Fatal(err)
	}
	check(replacement, 0)
	check(old, 2)
	if err := ConfigureEndpoint(replacement, 100, []net.IP{ip}, mac, "new-sandbox", "eth0", PortVethIdentity{UID: "new-port"}, nil); err != nil {
		t.Fatal(err)
	}
	check(replacement, 0) // idempotent ADD cannot reset an already resolved policy
	// A persistent Port keeps its UID/IP/MAC when its sandbox changes.
	newSandbox := create("cphsgnext", "new-port", "next-sandbox")
	check(newSandbox, 2)
	apply(newMember)
	check(newSandbox, 2)
	nextMember := newMember
	nextMember.Owner = SGEndpointOwner("new-port", "next-sandbox", "eth0")
	apply(nextMember)
	check(newSandbox, 0)
	nextMember.Owner = SGEndpointOwner("new-port", "next-sandbox", "net1")
	apply(nextMember)
	check(newSandbox, 2)
	// Membership received before the physical ADD must work on publication.
	prepublished := SGMember{Net: 100, IP: ip, Groups: 0, Owner: SGEndpointOwner("future-port", "future-sandbox", "eth0")}
	apply(prepublished)
	check(newSandbox, 2)
	future := create("cphsgfuture", "future-port", "future-sandbox")
	check(future, 0)
	if err := rebuildVeth(future, future.Attrs().Index, 100, []net.IP{ip}, mac); err != nil {
		t.Fatal(err)
	}
	check(future, 0)
	// North-south egress must use the same witness, including CIDR fallback.
	if err := m.SetNetwork(100, "10.0.0.0/24", 100); err != nil {
		t.Fatal(err)
	}
	gw := net.ParseIP("10.0.0.1")
	if err := m.SetGateway(100, gw, nil); err != nil {
		t.Fatal(err)
	}
	gk, _ := localKey(100, gw)
	if err := c.Maps["locals"].Put(gk, overlayEndpoint{Ifindex: 1}); err != nil {
		t.Fatal(err)
	}
	egressPacket := append([]byte(nil), packet...)
	copy(egressPacket[26:30], ip.To4())
	copy(egressPacket[30:34], []byte{198, 51, 100, 20})
	copy(egressPacket[6:12], mac)
	checkEgress := func(want uint32) {
		t.Helper()
		ctx := make([]byte, 192)
		binary.LittleEndian.PutUint32(ctx[40:44], uint32(future.Attrs().Index))
		got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: egressPacket, Context: ctx})
		if err != nil || got != want {
			t.Fatalf("egress verdict=%d want=%d err=%v", got, want, err)
		}
	}
	checkEgress(7) // current resolved zero can route through its gateway
	for _, owner := range [][4]uint64{oldMember.Owner, prepublished.Owner} {
		if err := m.ApplySecurityGroups([]SGMember{{Net: 100, IP: ip, Groups: 2, Owner: owner}}, nil, nil, nil,
			[]SGEgressCidr{{SrcNet: 100, Proto: 6, Port: 443, CIDR: all, AllowedGroups: 2}}); err != nil {
			t.Fatal(err)
		}
		if owner == oldMember.Owner {
			checkEgress(2)
		} else {
			checkEgress(7)
		}
	}
	apply(prepublished)
	staged := create("cphsgstage", "future-port", "target-sandbox", true)
	check(future, 0) // staging must preserve the active source's local witness
	if ok, err := EnsureLocalFromVeth(100, ip, "target-sandbox", "eth0", "future-port"); err != nil || !ok {
		t.Fatal("cutover failed", ok, err)
	}
	check(staged, 2)
	current := prepublished
	current.Owner = SGEndpointOwner("future-port", "target-sandbox", "eth0")
	apply(current)
	check(staged, 0)
	legacy := create("cphsglegacy", "", "legacy-sandbox")
	current.Owner = SGEndpointOwner("legacy-port", "legacy-sandbox", "eth0")
	apply(current)
	check(legacy, 2)
	if _, err := AdoptVethPortIdentity(legacy.Attrs().Index, legacy.Attrs().Alias, PortVethIdentity{UID: "legacy-port"}); err != nil {
		t.Fatal(err)
	}
	check(legacy, 0)
	if err := DelLocal(100, ip); err != nil {
		t.Fatal(err)
	}
	fresh, err := netlink.LinkByIndex(legacy.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AdoptVethPortIdentity(fresh.Attrs().Index, fresh.Attrs().Alias, PortVethIdentity{UID: "legacy-port"}); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := GetLocal(100, ip); err != nil || found {
		t.Fatal("ownership adoption created missing delivery", found, err)
	}
}
