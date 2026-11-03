package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestKernelPolicyFailedIdentitySyncDeniesMissingEndpoint(t *testing.T) {
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
		if name != "cozyplane_to_pod" && name != "cozyplane_from_pod" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	spec.Maps["np_ident"].MaxEntries = 1
	spec.Maps["sg_members"].MaxEntries = 1
	spec.Maps["np_cidr"].MaxEntries = 1
	spec.Maps["np_allow"].MaxEntries = 2
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{
		Params: c.Maps["params"], NpIdent: c.Maps["np_ident"],
		Networks: c.Maps["networks"],
		NpAllow:  c.Maps["np_allow"], NpCidr: c.Maps["np_cidr"],
		SgMembers: c.Maps["sg_members"], SgRules: c.Maps["sg_rules"],
		SgCidr: c.Maps["sg_cidr"], SgEgress: c.Maps["sg_egress"],
		SgEgressCidr: c.Maps["sg_egress_cidr"],
	}}}
	ctx := make([]byte, 192)
	binary.LittleEndian.PutUint32(ctx[40:44], 1)
	protocol := uint8(6)
	packet := func(dst net.IP) []byte {
		size := 54
		if protocol == 132 {
			size = 66
		}
		p := make([]byte, size)
		binary.BigEndian.PutUint16(p[12:14], 0x0800)
		p[14], p[22], p[23] = 0x45, 64, protocol
		binary.BigEndian.PutUint16(p[16:18], uint16(size-14))
		copy(p[26:30], []byte{198, 51, 100, 10})
		copy(p[30:34], dst.To4())
		binary.BigEndian.PutUint16(p[34:36], 40000)
		binary.BigEndian.PutUint16(p[36:38], 443)
		p[46], p[47] = 0x50, 2
		if protocol == 132 {
			p[46], p[47] = 1, 0 // SCTP INIT chunk
			binary.BigEndian.PutUint16(p[48:50], 20)
			binary.BigEndian.PutUint32(p[50:54], 1)
			binary.BigEndian.PutUint32(p[54:58], 65535)
			binary.BigEndian.PutUint16(p[58:60], 1)
			binary.BigEndian.PutUint16(p[60:62], 1)
			binary.BigEndian.PutUint32(p[62:66], 1)
		}
		return p
	}
	check := func(t *testing.T, ip net.IP, want uint32) {
		t.Helper()
		got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: packet(ip), Context: ctx})
		if err != nil || got != want {
			t.Fatalf("endpoint %s verdict=%d want=%d err=%v", ip, got, want, err)
		}
	}
	ips := []net.IP{net.ParseIP("10.0.0.10"), net.ParseIP("10.0.0.11")}
	t.Run("IPv6 ipBlock cannot authorize IPv4 packets", func(t *testing.T) {
		if err := m.ApplyNetworkPolicy([]NPIdent{{IP: ips[0], ID: 10, Flags: NPIngIsolated}}, nil, []NPCidr{{ID: 10, Dir: NPDirIn, Proto: 6, Port: 443, CIDR: cidr("::/0"), Allow: true}}); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
	})
	t.Run("uninitialized or recreated policy pins stay guarded", func(t *testing.T) {
		if err := m.armPolicyBootstrap(nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.armPolicyBootstrap(nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 0)
		if err := m.armPolicyBootstrap(map[string]bool{"np_ident": true}); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := m.armPolicyBootstrap(map[string]bool{"sg_members": true}); err != nil {
			t.Fatal(err)
		}
		var guard uint32
		if err := c.Maps["params"].Lookup(cfgSGUpdating, &guard); err != nil || guard != 1 {
			t.Fatal("SG bootstrap guard missing", guard, err)
		}
		if err := m.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("SCTP cannot bypass isolated or guarded NetworkPolicy", func(t *testing.T) {
		protocol = 132
		defer func() { protocol = 6 }()
		if err := m.ApplyNetworkPolicy([]NPIdent{{IP: ips[0], ID: 10, Flags: NPIngIsolated}}, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		check(t, ips[1], 0)
		sourceIP := net.ParseIP("198.51.100.10")
		sourceKey, _ := localKey(0, sourceIP)
		if err := c.Maps["ports"].Put(uint32(1), uint32(0)); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["locals"].Put(sourceKey, overlayEndpoint{Ifindex: 1}); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplyNetworkPolicy([]NPIdent{{IP: sourceIP, ID: 10, Flags: NPEgIsolated}}, nil, nil); err != nil {
			t.Fatal(err)
		}
		got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet(ips[1]), Context: ctx})
		if err != nil || got != 2 {
			t.Fatalf("SCTP source egress verdict=%d want=2 err=%v", got, err)
		}
		if err := m.BlockNetworkPolicy(); err != nil {
			t.Fatal(err)
		}
		check(t, ips[1], 2)
		source, _ := addr128(sourceIP)
		if err := c.Maps["np_nodes"].Put(source, NPNodeLocal); err != nil {
			t.Fatal(err)
		}
		check(t, ips[1], 0) // local-node plumbing remains exempt for SCTP too
		if err := c.Maps["np_nodes"].Delete(source); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 0)
		got, err = c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet(ips[1]), Context: ctx})
		if err != nil || got != 0 {
			t.Fatalf("unisolated SCTP source verdict=%d want=0 err=%v", got, err)
		}
	})
	t.Run("networkpolicy", func(t *testing.T) {
		defer func() { protocol = 6 }()
		if err := m.BlockNetworkPolicy(); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 0)
		oneRule := NPAllow{DstID: 10, SrcID: NPSrcAny, Dir: NPDirIn, Proto: 6, Port: 443}
		if err := m.SyncNPAllows([]NPAllow{oneRule}); err != nil {
			t.Fatal(err)
		}
		if err := m.SyncNPAllows([]NPAllow{{DstID: 10, SrcID: NPSrcAny, Proto: 6, Port: 1, EndPort: 65534}}); err == nil {
			t.Fatal("port prefix expansion exceeded map budget")
		}
		key := overlayNpAllowKey{Prefixlen: 176, DstId: 10, SrcId: NPSrcAny, Proto: 6, Port: htons(443)}
		var allowed uint8
		if err := c.Maps["np_allow"].Lookup(key, &allowed); err != nil || allowed != 1 {
			t.Fatal("oversized desired map mutated existing snapshot", allowed, err)
		}
		ids := []NPIdent{{IP: ips[0], ID: 10, Flags: NPIngIsolated}, {IP: ips[1], ID: 11, Flags: NPIngIsolated}}
		if err := m.ApplyNetworkPolicy(ids, nil, nil); err == nil {
			t.Fatal("identities unexpectedly fit")
		}
		for _, ip := range ips {
			check(t, ip, 2)
		}
		// Local kubelet probes remain admitted despite an incomplete identity map.
		a, _ := addr128(net.ParseIP("198.51.100.10"))
		if err := c.Maps["np_nodes"].Put(a, NPNodeLocal); err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			check(t, ip, 0)
		}
		if err := c.Maps["np_nodes"].Delete(a); err != nil {
			t.Fatal(err)
		}
		// A complete smaller snapshot removes the guard; only its selected pod
		// is isolated. The other endpoint resumes normal unisolated behavior.
		if err := m.ApplyNetworkPolicy(ids[:1], nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		check(t, ips[1], 0)
		protocol = 132
		check(t, ips[0], 2)
		check(t, ips[1], 0)
		protocol = 6
		if err := m.ApplyNetworkPolicy(ids, nil, nil); err == nil {
			t.Fatal("replacement unexpectedly fit")
		}
		for _, ip := range ips {
			check(t, ip, 2)
		}
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		_, excluded, _ := net.ParseCIDR("198.51.100.10/32")
		cidrs := []NPCidr{{ID: 10, Dir: NPDirIn, Proto: 6, Port: 443, CIDR: all, Allow: true},
			{ID: 10, Dir: NPDirIn, Proto: 6, Port: 443, CIDR: excluded, Allow: false}}
		if err := m.ApplyNetworkPolicy(ids[:1], nil, cidrs[:1]); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 0)
		if err := m.ApplyNetworkPolicy(ids[:1], nil, cidrs); err == nil {
			t.Fatal("CIDR exceptions unexpectedly fit")
		}
		check(t, ips[0], 2)
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("securitygroup", func(t *testing.T) {
		defer func() { protocol = 6 }()
		// Fabric bridge forwards to the corresponding tenant endpoint; NS_MARK
		// requests actual north-south SG enforcement instead of probe exemption.
		if err := c.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint32(ctx[8:12], 0x400000)
		if err := m.BlockSecurityGroups(); err != nil {
			t.Fatal(err)
		}
		var guard uint32
		if err := c.Maps["params"].Lookup(cfgSGUpdating, &guard); err != nil || guard != 1 {
			t.Fatal("compiler rejection failed to arm SG guard", guard, err)
		}
		members := []SGMember{}
		for _, ip := range ips {
			a, _ := addr128(ip)
			if err := c.Maps["bridges"].Put(a, overlayBridgeEp{Net: 101, VpcIp: a}); err != nil {
				t.Fatal(err)
			}
			members = append(members, SGMember{Net: 101, IP: ip, Groups: 2})
		}
		if err := m.ApplySecurityGroups(members, nil, nil, nil, nil); err == nil {
			t.Fatal("memberships unexpectedly fit")
		}
		for _, ip := range ips {
			check(t, ip, 2)
		}
		if err := m.ApplySecurityGroups(members[:1], nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		check(t, ips[1], 0)
		if err := m.ApplySecurityGroups(members, nil, nil, nil, nil); err == nil {
			t.Fatal("replacement unexpectedly fit")
		}
		for _, ip := range ips {
			check(t, ip, 2)
		}
		// Source enforcement also stops a missing group bitmap from escaping
		// to a remote node as an ungrouped source during a failed sync.
		if err := m.SetNetwork(101, "0.0.0.0/0", 101); err != nil {
			t.Fatal(err)
		}
		source, _ := addr128(net.ParseIP("198.51.100.10"))
		if err := c.Maps["locals"].Put(overlayLocalKey{Net: 101, Ip: source}, overlayEndpoint{Ifindex: 1}); err != nil {
			t.Fatal(err)
		}
		checkSource := func(want uint32) {
			t.Helper()
			got, err := c.Programs["cozyplane_from_pod"].Run(&ebpf.RunOptions{Data: packet(ips[1]), Context: ctx})
			if err != nil || got != want {
				t.Fatalf("source verdict=%d want=%d err=%v", got, want, err)
			}
		}
		checkSource(2)
		// Even an existing CIDR grant cannot override the guarded fallback.
		_, all, _ := net.ParseCIDR("0.0.0.0/0")
		if err := m.SyncSGCidr([]SGCidr{{Net: 101, Proto: 6, Port: 443, CIDR: all, AllowedGroups: 2}}); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		if err := m.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		for _, ip := range ips {
			check(t, ip, 0)
		}
		checkSource(0)
	})
	t.Run("SCTP cannot bypass selected east-west SecurityGroups", func(t *testing.T) {
		protocol = 132
		defer func() { protocol = 6 }()
		if err := c.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
			t.Fatal(err)
		}
		if err := m.SetNetwork(101, "0.0.0.0/0", 101); err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint32(ctx[8:12], 0)
		for _, ip := range ips {
			a, _ := addr128(ip)
			if err := c.Maps["bridges"].Delete(a); err != nil && !isNotExist(err) {
				t.Fatal(err)
			}
		}
		source, _ := localKey(101, net.ParseIP("198.51.100.10"))
		if err := c.Maps["locals"].Delete(source); err != nil && !isNotExist(err) {
			t.Fatal(err)
		}
		if err := m.ApplySecurityGroups([]SGMember{{Net: 101, IP: ips[0], Groups: 2}}, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
		check(t, ips[1], 0)
	})
	t.Run("IPv6 SecurityGroup CIDR cannot authorize IPv4", func(t *testing.T) {
		if err := m.ApplyNetworkPolicy(nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["ports"].Put(uint32(1), uint32(101)); err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint32(ctx[8:12], 0x400000)
		a, _ := addr128(ips[0])
		if err := c.Maps["bridges"].Put(a, overlayBridgeEp{Net: 101, VpcIp: a}); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplySecurityGroups([]SGMember{{Net: 101, IP: ips[0], Groups: 2}}, nil, []SGCidr{{Net: 101, Proto: 6, Port: 443, CIDR: cidr("64:ff9b::/96"), AllowedGroups: 2}}, nil, nil); err != nil {
			t.Fatal(err)
		}
		check(t, ips[0], 2)
	})
}
