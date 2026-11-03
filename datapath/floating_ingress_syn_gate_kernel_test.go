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

// A grouped VM with a public IP whose SecurityGroup opens only TCP 22 must still
// receive the replies of the connections it opens itself (admitted by its egress
// rules): the floating ingress gate checks a NEW TCP connection (SYN, no ACK)
// like every other SG gate, in both families. Lab, 09/10/2026: `apt update` timed
// out because the SYN-ACK to the VM's ephemeral port was dropped at floating_forward.
func TestKernelFloatingIngressGatesOnlyNewTCP(t *testing.T) {
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
	for _, cidr := range []string{"10.244.4.0/24", "fd07::/64"} {
		if err := m.SetNetwork(107, cidr, 107); err != nil {
			t.Fatal(err)
		}
	}
	vm4, vm6 := net.ParseIP("10.244.4.3"), net.ParseIP("fd07::3")
	pub4, pub6 := net.ParseIP("192.0.2.10"), net.ParseIP("2001:db8::10")
	client4, client6 := net.ParseIP("203.0.113.5"), net.ParseIP("2001:db8:5::5")
	vmMAC, _ := net.ParseMAC("02:00:00:00:0a:03")
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphfloatsyn"}, PeerName: "cphfloatsynp"}); err != nil {
		t.Fatal(err)
	}
	vm, err := netlink.LinkByName("cphfloatsyn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(vm) })
	if err := netlink.LinkSetUp(vm); err != nil {
		t.Fatal(err)
	}
	if err := ConfigureEndpoint(vm, 107, []net.IP{vm4, vm6}, vmMAC, "vm-sandbox", "eth0", PortVethIdentity{UID: "vm-port"}, nil); err != nil {
		t.Fatal(err)
	}
	for pub, priv := range map[string]net.IP{pub4.String(): vm4, pub6.String(): vm6} {
		if err := m.SetFloating(pub, priv.String(), 107); err != nil {
			t.Fatal(err)
		}
	}
	_, clients4, _ := net.ParseCIDR("203.0.113.0/24")
	_, clients6, _ := net.ParseCIDR("2001:db8:5::/64")
	owner := SGEndpointOwner("vm-port", "vm-sandbox", "eth0")
	if err := m.ApplySecurityGroups(
		[]SGMember{{Net: 107, IP: vm4, Groups: 2, Owner: owner}, {Net: 107, IP: vm6, Groups: 2, Owner: owner}},
		nil, []SGCidr{{Net: 107, Proto: 6, Port: 22, CIDR: clients4, AllowedGroups: 2}, {Net: 107, Proto: 6, Port: 22, CIDR: clients6, AllowedGroups: 2}},
		nil, nil); err != nil {
		t.Fatal(err)
	}
	inbound := func(client, public net.IP, proto byte, dport uint16, flags byte) []byte {
		p := policyFamilyPacket(client, public)
		copy(p[:6], vmMAC)
		l4 := 34
		if client.To4() == nil {
			l4, p[20] = 54, proto
		} else {
			p[23] = proto
		}
		binary.BigEndian.PutUint16(p[l4:l4+2], 80)
		binary.BigEndian.PutUint16(p[l4+2:l4+4], dport)
		if proto == 17 {
			binary.BigEndian.PutUint16(p[l4+4:l4+6], uint16(len(p)-l4))
			p[l4+6], p[l4+7] = 0, 0
		} else {
			p[l4+13] = flags
		}
		return p
	}
	for _, fam := range []struct {
		name               string
		client, public, vm net.IP
		dstStart, dstEnd   int
	}{
		{"v4", client4, pub4, vm4, 30, 34},
		{"v6", client6, pub6, vm6, 38, 54},
	} {
		for _, tc := range []struct {
			name  string
			proto byte
			dport uint16
			flags byte
			want  uint32
		}{
			{"new TCP to the opened port", 6, 22, 0x02, 0},
			{"new TCP to a closed port", 6, 8080, 0x02, 2},
			{"reply to the VM's own connection", 6, 45410, 0x12, 0},
			{"established data of that connection", 6, 45410, 0x10, 0},
			{"UDP stays gated per packet", 17, 45410, 0, 2},
		} {
			t.Run(fam.name+"/"+tc.name, func(t *testing.T) {
				p := inbound(fam.client, fam.public, tc.proto, tc.dport, tc.flags)
				ctx, out := make([]byte, 192), make([]byte, len(p))
				binary.LittleEndian.PutUint32(ctx[40:44], uint32(vm.Attrs().Index))
				got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: p, DataOut: out, Context: ctx})
				if err != nil || got != tc.want {
					t.Fatalf("verdict=%d want=%d err=%v", got, tc.want, err)
				}
				if tc.want == 0 && !net.IP(out[fam.dstStart:fam.dstEnd]).Equal(fam.vm) {
					t.Fatalf("admitted packet not delivered to the VM: dst %v", net.IP(out[fam.dstStart:fam.dstEnd]))
				}
			})
		}
	}
}
