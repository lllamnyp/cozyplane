package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/sgidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKernelRecycledSecurityGroupIdentity(t *testing.T) {
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
		if name != "cozyplane_to_pod" {
			delete(spec.Programs, name)
		}
	}
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}
	c, err := newKernelPacketCollection(t, spec)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Params: c.Maps["params"], SgMembers: c.Maps["sg_members"], SgRules: c.Maps["sg_rules"], SgCidr: c.Maps["sg_cidr"], SgEgress: c.Maps["sg_egress"], SgEgressCidr: c.Maps["sg_egress_cidr"]}}}
	dst := net.ParseIP("10.0.0.2")
	owner := SGEndpointOwner("port", "sandbox", "eth0")
	a, _ := addr128(dst)
	if err := c.Maps["ports"].Put(uint32(1), uint32(100)); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["bridges"].Put(a, overlayBridgeEp{Net: 100, VpcIp: a}); err != nil {
		t.Fatal(err)
	}
	context := make([]byte, 192)
	binary.LittleEndian.PutUint32(context[40:44], 1)
	binary.LittleEndian.PutUint32(context[8:12], 0x400000)
	packet := make([]byte, 54)
	binary.BigEndian.PutUint16(packet[12:14], 0x0800)
	packet[14], packet[22], packet[23] = 0x45, 64, 6
	binary.BigEndian.PutUint16(packet[16:18], 40)
	copy(packet[26:30], []byte{198, 51, 100, 10})
	copy(packet[30:34], dst.To4())
	binary.BigEndian.PutUint16(packet[34:36], 40000)
	binary.BigEndian.PutUint16(packet[36:38], 443)
	packet[46], packet[47] = 0x50, 2
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	check := func(bitmap uint64, want uint32) {
		t.Helper()
		if err := m.ApplySecurityGroups([]SGMember{{Net: 100, IP: dst, Groups: bitmap, Owner: owner}}, nil, []SGCidr{{Net: 100, Proto: 6, Port: 443, CIDR: all, AllowedGroups: 2}}, nil, nil); err != nil {
			t.Fatal(err)
		}
		got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: packet, Context: context})
		if err != nil || got != want {
			t.Fatalf("bitmap=%b verdict=%d want=%d err=%v", bitmap, got, want, err)
		}
	}
	t.Run("initial missing local membership", func(t *testing.T) {
		if err := c.Maps["locals"].Put(overlayLocalKey{Net: 100, Ip: a}, overlayEndpoint{Ifindex: 1, SgOwner: owner}); err != nil {
			t.Fatal(err)
		}
		if err := m.ApplySecurityGroups(nil, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		got, err := c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: packet, Context: context})
		if err != nil || got != 2 {
			t.Fatalf("missing local membership verdict=%d want=2 err=%v", got, err)
		}
		if err := m.ApplySecurityGroups([]SGMember{{Net: 100, IP: dst, Groups: 0, Owner: owner}}, nil, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		got, err = c.Programs["cozyplane_to_pod"].Run(&ebpf.RunOptions{Data: packet, Context: context})
		if err != nil || got != 0 {
			t.Fatalf("resolved unselected membership verdict=%d want=0 err=%v", got, err)
		}
	})
	ref := sdn.VPCRef{Namespace: "tenant", Name: "net"}
	group := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: "group", UID: "replacement"}, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: ref.Name}}, Status: sdn.SecurityGroupStatus{ID: 1}}
	port := &sdn.Port{Spec: sdn.PortSpec{VPCRef: ref}, Status: sdn.PortStatus{Groups: []int32{1}, GroupRefs: []sdn.SecurityGroupMembership{{ID: 1, UID: "predecessor"}}}}
	index := sgidentity.NewIndex([]*sdn.SecurityGroup{group})
	check(SGMembershipBitmap(port.Status.Groups), 0) // old numeric projection admits
	check(index.Bitmap(port), 2)
	port.Status.GroupRefs[0].UID = group.UID
	check(index.Bitmap(port), 0)
}
