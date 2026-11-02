package datapath

import (
	"net"
	"testing"
)

// Between two bounded VPCs the boundary is the CEILING and the security groups
// NARROW it: the real to_pod continuation (lb_prog slot 5) runs after the
// boundary gate, so a flow must be admitted by both. Before this change the
// continuation skipped the SG check for a managed pair and the boundary alone
// decided.
func TestKernelBoundedPairSecurityGroupsNarrowTheBoundary(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "IPv4"
		if ipv6 {
			name = "IPv6"
		}
		t.Run(name, func(t *testing.T) {
			f := newBoundaryPacketFixture(t, ipv6)
			boundaryPacketPut(t, f.objects.LbProg, uint32(5), uint32(f.objects.CozyplaneToPodContinue.FD()))
			// The pair is peered (a VPCPeering on each side), as every agreement's transport is: without it isolation
			// drops the flow before any policy is consulted.
			for _, pair := range [][2]uint32{{1, 2}, {2, 1}} {
				boundaryPacketPut(t, f.objects.Peers, overlayPeerKey{SrcNet: pair[0], DstNet: pair[1]}, uint8(1))
			}
			owner := [4]uint64{1}
			for _, endpoint := range []struct {
				net uint32
				ip  net.IP
			}{{1, f.a}, {2, f.b}, {1, f.secondary}} {
				boundaryPacketPut(t, f.objects.Locals, overlayLocalKey{Net: endpoint.net, Ip: boundaryPacketAddress(t, endpoint.ip)},
					overlayEndpoint{Ifindex: f.ifindex, SgOwner: owner})
			}
			m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Params: f.objects.Params, Networks: f.objects.Networks,
				SgMembers: f.objects.SgMembers, SgRules: f.objects.SgRules, SgCidr: f.objects.SgCidr,
				SgEgress: f.objects.SgEgress, SgEgressCidr: f.objects.SgEgressCidr}}}
			// Groups: a = group 1 of net 1, b = group 1 of net 2, secondary = group 2 of net 1.
			members := []SGMember{
				{Net: 1, IP: f.a, Groups: 1 << 1, Owner: owner},
				{Net: 2, IP: f.b, Groups: 1 << 1, Owner: owner},
				{Net: 1, IP: f.secondary, Groups: 1 << 2, Owner: owner},
			}
			// a -> b on TCP 443 and UDP 8443 (and the {UDP, 0} reply pair, added below).
			rules := []SGRule{
				{Net: 2, SrcNet: 1, Group: 1, Proto: 6, Port: 443, Allowed: 1 << 1},
				{Net: 2, SrcNet: 1, Group: 1, Proto: 17, Port: 8443, Allowed: 1 << 1},
			}
			egress := []SGEgress{
				{SrcNet: 1, DstNet: 2, Group: 1, Proto: 6, Port: 443, Allowed: 1 << 1},
				{SrcNet: 1, DstNet: 2, Group: 1, Proto: 17, Port: 8443, Allowed: 1 << 1},
			}
			if err := m.ApplySecurityGroups(members, rules, nil, egress, nil); err != nil {
				t.Fatal(err)
			}
			f.allow(t, 6, 443)
			f.allow(t, 6, 444)
			f.allow(t, 17, 8443)

			// Admitted by the boundary AND the groups.
			f.notDropped(t, 2, boundaryPacket(f.a, f.b, 6, 42000, 443, 0x02))
			// The boundary admits secondary -> b on 443, the groups do not: dropped.
			f.verdict(t, true, 2, boundaryPacket(f.secondary, f.b, 6, 42001, 443, 0x02), 2)
			// The boundary admits 444, no group rule does: dropped.
			f.verdict(t, true, 2, boundaryPacket(f.a, f.b, 6, 42002, 444, 0x02), 2)
			// A group rule never widens past the ceiling: 445 is not in the boundary.
			if err := m.ApplySecurityGroups(members, append(rules, SGRule{Net: 2, SrcNet: 1, Group: 1, Proto: 6, Port: 445, Allowed: 1 << 1}),
				nil, append(egress, SGEgress{SrcNet: 1, DstNet: 2, Group: 1, Proto: 6, Port: 445, Allowed: 1 << 1}), nil); err != nil {
				t.Fatal(err)
			}
			f.verdict(t, true, 2, boundaryPacket(f.a, f.b, 6, 42003, 445, 0x02), 2)

			// UDP is checked on every packet: the reply b -> a needs the {UDP, 0} pair. The request crosses the
			// source side first (from_pod records the boundary flow the reply is admitted by), then the destination.
			request := boundaryPacket(f.a, f.b, 17, 42100, 8443, 0)
			f.verdict(t, false, 1, request, 0)
			f.notDropped(t, 2, request)
			reply := boundaryPacket(f.b, f.a, 17, 8443, 42100, 0)
			f.verdict(t, true, 1, reply, 2)
			if err := m.ApplySecurityGroups(members,
				append(rules, SGRule{Net: 1, SrcNet: 2, Group: 1, Proto: 17, Port: 0, Allowed: 1 << 1}), nil,
				append(egress, SGEgress{SrcNet: 2, DstNet: 1, Group: 1, Proto: 17, Port: 0, Allowed: 1 << 1}), nil); err != nil {
				t.Fatal(err)
			}
			f.notDropped(t, 1, reply)
		})
	}
}

// notDropped runs to_pod for a packet delivered into `network` and requires any verdict but TC_ACT_SHOT: the real
// continuation redirects to the endpoint once both the boundary and the groups admit the flow.
func (f *boundaryPacketFixture) notDropped(t *testing.T, network uint32, packet []byte) {
	t.Helper()
	boundaryPacketPut(t, f.objects.Ports, f.ifindex, network)
	got, _, err := f.objects.CozyplaneToPod.Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got == 2 {
		t.Fatalf("network=%d: packet dropped, want admitted", network)
	}
}
