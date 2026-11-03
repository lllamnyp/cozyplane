package datapath

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
)

// The organisation Gateway path through the real wrapper AND continuations
// (docs/services-in-vpc.md § "Organisation gateway"): a VPC pod's TCP 80/443 to
// its organisation's Gateway leaves re-sourced to its fabric IP with
// TC_ACT_NEXT, for Cilium to serve; anything else is left alone, and only a
// recorded flow's reply comes back to the pod.

const tcActNext = ^uint32(0) // TC_ACT_NEXT (-1) as the test-run return value

// IPv4 header field offsets in a boundaryPacket frame.
const ipv4SrcOff, ipv4DstOff = 26, 30

type orgGatewayFixture struct {
	*boundaryPacketFixture
	gw, fabric net.IP
}

// Bounded VPCs 1 and 2 without an Internet grant (the boundary fixture's
// default); pod a of VPC 1 holds a fabric handle and org_gw grants it gw. Pod a
// is a resolved, ungrouped SecurityGroup identity (owner witness, no groups).
func newOrgGatewayFixture(t *testing.T) *orgGatewayFixture {
	f := newBoundaryPacketFixture(t, false)
	o := &orgGatewayFixture{boundaryPacketFixture: f, gw: net.ParseIP("10.240.0.5").To4(), fabric: net.ParseIP("10.244.2.10").To4()}
	o.member(t, 0)
	boundaryPacketPut(t, f.objects.FabricOf, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, f.a)}, boundaryPacketAddress(t, o.fabric))
	boundaryPacketPut(t, f.objects.Bridges, boundaryPacketAddress(t, o.fabric), overlayBridgeEp{Net: 1, VpcIp: boundaryPacketAddress(t, f.a)})
	boundaryPacketPut(t, f.objects.OrgGw, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, o.gw)}, uint8(1))
	boundaryPacketPut(t, f.objects.LbProg, uint32(4), uint32(f.objects.CozyplaneFromPodContinue.FD()))
	boundaryPacketPut(t, f.objects.LbProg, uint32(5), uint32(f.objects.CozyplaneToPodContinue.FD()))
	return o
}

// member sets pod a's SecurityGroup bitmap under a matching owner witness.
func (o *orgGatewayFixture) member(t *testing.T, groups uint64) {
	t.Helper()
	owner := [4]uint64{1, 2, 3, 4}
	key := overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, o.a)}
	boundaryPacketPut(t, o.objects.Locals, key, overlayEndpoint{Ifindex: o.ifindex, SgOwner: owner})
	boundaryPacketPut(t, o.objects.SgMembers, key, overlaySgMember{Groups: groups, Owner: owner})
}

func (o *orgGatewayFixture) run(t *testing.T, ingress bool, network uint32, packet []byte) (uint32, []byte) {
	t.Helper()
	boundaryPacketPut(t, o.objects.Ports, o.ifindex, network)
	program := o.objects.CozyplaneFromPod
	if ingress {
		program = o.objects.CozyplaneToPod
	}
	action, out, err := program.Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	return action, out
}

// unchanged asserts the packet was not steered: no TC_ACT_NEXT, source intact.
func (o *orgGatewayFixture) unchanged(t *testing.T, network uint32, packet []byte) {
	t.Helper()
	action, out := o.run(t, false, network, packet)
	if action == tcActNext || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], packet[ipv4SrcOff:ipv4SrcOff+4]) {
		t.Fatalf("packet was steered: action=%d source=%v", action, net.IP(out[ipv4SrcOff:ipv4SrcOff+4]))
	}
}

func TestOrgGatewaySteer(t *testing.T) {
	o := newOrgGatewayFixture(t)
	for _, port := range []uint16{80, 443} {
		action, out := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, port, 0x02))
		if action != tcActNext || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.fabric) || !bytes.Equal(out[ipv4DstOff:ipv4DstOff+4], o.gw) {
			t.Fatalf("port %d: action=%d src=%v dst=%v, want NEXT from the fabric IP", port, action,
				net.IP(out[ipv4SrcOff:ipv4SrcOff+4]), net.IP(out[ipv4DstOff:ipv4DstOff+4]))
		}
		if boundaryPacketChecksum(out[14:34]) != 0 {
			t.Fatalf("port %d: IPv4 header checksum broken by the rewrite", port)
		}
		var vpc uint32
		key := overlayOrgGwCtKey{Fabric: boundaryPacketAddress(t, o.fabric), Gw: boundaryPacketAddress(t, o.gw), Sport: htons(42000), Dport: htons(port)}
		if err := o.objects.OrgGwCt.Lookup(key, &vpc); err != nil || vpc != 1 {
			t.Fatalf("port %d: no flow record (%v, net %d)", port, err, vpc)
		}
	}

	t.Run("other port", func(t *testing.T) { o.unchanged(t, 1, boundaryPacket(o.a, o.gw, 6, 42000, 22, 0x02)) })
	t.Run("UDP", func(t *testing.T) { o.unchanged(t, 1, boundaryPacket(o.a, o.gw, 17, 42000, 443, 0)) })
	t.Run("other VPC", func(t *testing.T) { o.unchanged(t, 2, boundaryPacket(o.b, o.gw, 6, 42000, 443, 0x02)) })
	t.Run("other organisation's gateway", func(t *testing.T) {
		o.unchanged(t, 1, boundaryPacket(o.a, net.ParseIP("10.240.0.6").To4(), 6, 42000, 443, 0x02))
	})
	t.Run("tenant CIDR covering the address shadows it", func(t *testing.T) {
		key := overlayLpmKey{Prefixlen: 160, ScopeNet: 1, Addr: boundaryPacketAddress(t, o.gw)}
		boundaryPacketPut(t, o.objects.Networks, key, uint32(1))
		defer func() { _ = o.objects.Networks.Delete(key) }()
		o.unchanged(t, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02))
	})
	t.Run("without a fabric handle the flow is dropped", func(t *testing.T) {
		key := overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, o.a)}
		if err := o.objects.FabricOf.Delete(key); err != nil {
			t.Fatal(err)
		}
		defer boundaryPacketPut(t, o.objects.FabricOf, key, boundaryPacketAddress(t, o.fabric))
		if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != 2 {
			t.Fatalf("action=%d, want SHOT", action)
		}
	})
	t.Run("unbounded VPC", func(t *testing.T) {
		for _, n := range []uint32{1, 2} {
			if err := o.objects.BoundaryPolicy.Delete(n); err != nil {
				t.Fatal(err)
			}
		}
		defer o.policies(t)
		if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42001, 443, 0x02)); action != tcActNext {
			t.Fatalf("action=%d, want NEXT", action)
		}
	})
}

// Without the grant the bounded VPC (no Internet permission) cannot reach the
// address at all: the wrapper's plumbing exception is the org_gw entry.
func TestOrgGatewayBoundaryWithoutGrant(t *testing.T) {
	o := newOrgGatewayFixture(t)
	if err := o.objects.OrgGw.Delete(overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, o.gw)}); err != nil {
		t.Fatal(err)
	}
	if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != 2 {
		t.Fatalf("action=%d, want SHOT", action)
	}
}

func TestOrgGatewayIPv6Unchanged(t *testing.T) {
	f := newBoundaryPacketFixture(t, true)
	gw := net.ParseIP("fd40::5")
	boundaryPacketPut(t, f.objects.FabricOf, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, f.a)}, boundaryPacketAddress(t, net.ParseIP("fd24:2::10")))
	boundaryPacketPut(t, f.objects.OrgGw, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, gw)}, uint8(1))
	boundaryPacketPut(t, f.objects.LbProg, uint32(4), uint32(f.objects.CozyplaneFromPodContinue.FD()))
	boundaryPacketPut(t, f.objects.Ports, f.ifindex, uint32(1))
	packet := boundaryPacket(f.a, gw, 6, 42000, 443, 0x02)
	action, out, err := f.objects.CozyplaneFromPod.Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	if action == tcActNext || !bytes.Equal(out[22:38], packet[22:38]) {
		t.Fatalf("IPv6 flow was steered: action=%d", action)
	}
}

func TestOrgGatewayReturn(t *testing.T) {
	o := newOrgGatewayFixture(t)
	if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != tcActNext {
		t.Fatalf("forward flow not steered: action=%d", action)
	}
	action, out := o.run(t, true, 1, boundaryPacket(o.gw, o.fabric, 6, 443, 42000, 0x12))
	if action != 0 || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.gw) || !bytes.Equal(out[ipv4DstOff:ipv4DstOff+4], o.a.To4()) {
		t.Fatalf("recorded reply: action=%d src=%v dst=%v, want gw -> VPC IP", action,
			net.IP(out[ipv4SrcOff:ipv4SrcOff+4]), net.IP(out[ipv4DstOff:ipv4DstOff+4]))
	}
	if boundaryPacketChecksum(out[14:34]) != 0 {
		t.Fatal("IPv4 header checksum broken by the reverse rewrite")
	}
	gatewayReply := func(out []byte) bool {
		return bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.gw) && bytes.Equal(out[ipv4DstOff:ipv4DstOff+4], o.a.To4())
	}
	// An unrecorded port, or a record from another VPC, is never delivered as
	// the Gateway's reply (at most the ordinary bridge path sees it).
	if _, out := o.run(t, true, 1, boundaryPacket(o.gw, o.fabric, 6, 443, 42001, 0x12)); gatewayReply(out) {
		t.Fatal("reply without a flow record was delivered from the Gateway address")
	}
	key := overlayOrgGwCtKey{Fabric: boundaryPacketAddress(t, o.fabric), Gw: boundaryPacketAddress(t, o.gw), Sport: htons(42002), Dport: htons(443)}
	boundaryPacketPut(t, o.objects.OrgGwCt, key, uint32(2))
	if _, out := o.run(t, true, 1, boundaryPacket(o.gw, o.fabric, 6, 443, 42002, 0x12)); gatewayReply(out) {
		t.Fatal("a flow record from another VPC admitted the reply")
	}
}

// A proxy on another node answers before Cilium's reverse NAT: its endpoint
// address and target port must come back as the Gateway's, and only onto a
// recorded flow.
func TestOrgGatewayReturnFromRemoteProxy(t *testing.T) {
	o := newOrgGatewayFixture(t)
	proxy, foreign, stray := net.ParseIP("10.244.3.7").To4(), net.ParseIP("10.244.3.8").To4(), net.ParseIP("10.244.3.9").To4()
	boundaryPacketPut(t, o.objects.OrgGwBe, overlayOrgGwAddr{Addr: boundaryPacketAddress(t, proxy), Port: htons(10443)},
		overlayOrgGwAddr{Addr: boundaryPacketAddress(t, o.gw), Port: htons(443)})
	// A proxy of another organisation's Gateway.
	boundaryPacketPut(t, o.objects.OrgGwBe, overlayOrgGwAddr{Addr: boundaryPacketAddress(t, foreign), Port: htons(10443)},
		overlayOrgGwAddr{Addr: boundaryPacketAddress(t, net.ParseIP("10.240.0.6")), Port: htons(443)})
	if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != tcActNext {
		t.Fatalf("forward flow not steered: action=%d", action)
	}
	action, out := o.run(t, true, 1, boundaryPacket(proxy, o.fabric, 6, 10443, 42000, 0x12))
	if action != 0 || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.gw) || !bytes.Equal(out[ipv4DstOff:ipv4DstOff+4], o.a.To4()) ||
		binary.BigEndian.Uint16(out[34:36]) != 443 {
		t.Fatalf("proxy reply: action=%d src=%v:%d dst=%v, want gw:443 -> VPC IP", action,
			net.IP(out[ipv4SrcOff:ipv4SrcOff+4]), binary.BigEndian.Uint16(out[34:36]), net.IP(out[ipv4DstOff:ipv4DstOff+4]))
	}
	if boundaryPacketChecksum(out[14:34]) != 0 || !tcpChecksumValid(out) {
		t.Fatal("checksums broken by the proxy reply translation")
	}
	for _, source := range []net.IP{foreign, stray} {
		_, out := o.run(t, true, 1, boundaryPacket(source, o.fabric, 6, 10443, 42000, 0x12))
		if bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.gw) {
			t.Fatalf("reply from %v was delivered as the Gateway's", source)
		}
	}
}

func tcpChecksumValid(frame []byte) bool {
	ip, l4 := frame[14:34], frame[34:]
	pseudo := make([]byte, 12, 12+len(l4))
	copy(pseudo[:8], ip[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
	return boundaryPacketChecksum(append(pseudo, l4...)) == 0
}

// No org_gw_be entry can redirect a reply that already carries the Gateway
// address of a recorded flow, even one keyed on that very address.
func TestOrgGatewayDirectReplyWinsOverProxyEntries(t *testing.T) {
	o := newOrgGatewayFixture(t)
	boundaryPacketPut(t, o.objects.OrgGwBe, overlayOrgGwAddr{Addr: boundaryPacketAddress(t, o.gw), Port: htons(443)},
		overlayOrgGwAddr{Addr: boundaryPacketAddress(t, net.ParseIP("10.240.0.6")), Port: htons(443)})
	if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != tcActNext {
		t.Fatalf("forward flow not steered: action=%d", action)
	}
	action, out := o.run(t, true, 1, boundaryPacket(o.gw, o.fabric, 6, 443, 42000, 0x12))
	if action != 0 || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.gw) || !bytes.Equal(out[ipv4DstOff:ipv4DstOff+4], o.a.To4()) {
		t.Fatalf("legitimate reply redirected: action=%d src=%v dst=%v", action,
			net.IP(out[ipv4SrcOff:ipv4SrcOff+4]), net.IP(out[ipv4DstOff:ipv4DstOff+4]))
	}
}

// A forwarding leg relaying a co-VPC pod's address (legacy, unbounded VPC:
// the continuation's anti-spoof admits foreign sources there) never steers
// with that pod's fabric handle.
func TestOrgGatewayForeignSourceDropped(t *testing.T) {
	o := newOrgGatewayFixture(t)
	for _, n := range []uint32{1, 2} {
		if err := o.objects.BoundaryPolicy.Delete(n); err != nil {
			t.Fatal(err)
		}
	}
	victim := net.ParseIP("10.60.0.99").To4()
	boundaryPacketPut(t, o.objects.Locals, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, victim)}, overlayEndpoint{Ifindex: o.ifindex + 100})
	boundaryPacketPut(t, o.objects.FabricOf, overlayLocalKey{Net: 1, Ip: boundaryPacketAddress(t, victim)}, boundaryPacketAddress(t, net.ParseIP("10.244.2.99")))
	const portForward = 1 << 30 // PORT_F_FORWARD
	if action, out := o.run(t, false, 1|portForward, boundaryPacket(victim, o.gw, 6, 42000, 443, 0x02)); action != 2 {
		t.Fatalf("foreign source steered: action=%d src=%v", action, net.IP(out[ipv4SrcOff:ipv4SrcOff+4]))
	}
	// The leg's own address still reaches the Gateway.
	if action, _ := o.run(t, false, 1|portForward, boundaryPacket(o.a, o.gw, 6, 42001, 443, 0x02)); action != tcActNext {
		t.Fatalf("forwarding leg's own flow: action=%d, want NEXT", action)
	}
}

// The Gateway precedes explicit routes: even a route covering its address
// (which the controllers refuse to publish) cannot divert the flow.
func TestOrgGatewayPrecedesExplicitRoutes(t *testing.T) {
	o := newOrgGatewayFixture(t)
	route := overlayRouteEntry{Count: 1}
	route.NextHops[0] = overlayGwEntry{GwIp: boundaryPacketAddress(t, o.secondary)}
	boundaryPacketPut(t, o.objects.VpcRoutes, overlayLpmKey{Prefixlen: 160, ScopeNet: 1, Addr: boundaryPacketAddress(t, o.gw)}, route)
	action, out := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02))
	if action != tcActNext || !bytes.Equal(out[ipv4SrcOff:ipv4SrcOff+4], o.fabric) {
		t.Fatalf("route diverted the Gateway flow: action=%d", action)
	}
}

// A full revocation also forgets the recorded flows; an ordinary resync keeps
// them, and grants and proxy endpoints follow the desired state exactly.
func TestSyncOrgGatewaysRevocationClearsFlows(t *testing.T) {
	o := newOrgGatewayFixture(t)
	m := &Manager{objs: o.objects}
	gw := netip.MustParseAddr("10.240.0.5")
	proxies := map[netip.AddrPort]netip.AddrPort{netip.MustParseAddrPort("10.244.3.7:10443"): netip.AddrPortFrom(gw, 443)}
	if err := m.SyncOrgGateways(map[uint32][]netip.Addr{1: {gw}}, proxies); err != nil {
		t.Fatal(err)
	}
	if action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000, 443, 0x02)); action != tcActNext {
		t.Fatalf("granted flow not steered: action=%d", action)
	}
	count := func(mp *ebpf.Map) int {
		n := 0
		it := mp.Iterate()
		var k, v []byte
		for it.Next(&k, &v) {
			n++
		}
		return n
	}
	if err := m.SyncOrgGateways(map[uint32][]netip.Addr{1: {gw}}, proxies); err != nil || count(o.objects.OrgGwCt) != 1 ||
		count(o.objects.OrgGw) != 1 || count(o.objects.OrgGwBe) != 1 {
		t.Fatalf("resync changed state: %v", err)
	}
	if err := m.SyncOrgGateways(nil, nil); err != nil {
		t.Fatal(err)
	}
	if count(o.objects.OrgGw) != 0 || count(o.objects.OrgGwBe) != 0 || count(o.objects.OrgGwCt) != 0 {
		t.Fatal("revocation left organisation gateway state behind")
	}
}

// The pod's SecurityGroup egress gates the Gateway like any north-south path:
// a grouped pod is default-denied until a `to: {cidr}` rule covers the address.
func TestOrgGatewayHonoursSecurityGroupEgress(t *testing.T) {
	o := newOrgGatewayFixture(t)
	m := &Manager{objs: o.objects}
	const web = uint64(1) << 3
	o.member(t, web)
	syn := func(port uint16) uint32 {
		action, _ := o.run(t, false, 1, boundaryPacket(o.a, o.gw, 6, 42000+port, port, 0x02))
		return action
	}
	if got := syn(443); got != 2 {
		t.Fatalf("grouped pod without an egress rule: action=%d, want SHOT", got)
	}
	_, world, _ := net.ParseCIDR("0.0.0.0/0") // the portal-managed sg-<vpc> shape
	if err := m.SyncSGEgressCidr([]SGEgressCidr{{SrcNet: 1, Proto: 6, CIDR: world, AllowedGroups: web}}); err != nil {
		t.Fatal(err)
	}
	if got := syn(443); got != tcActNext {
		t.Fatalf("0.0.0.0/0 egress rule: action=%d, want NEXT", got)
	}
	_, host, _ := net.ParseCIDR("10.240.0.5/32")
	if err := m.SyncSGEgressCidr([]SGEgressCidr{{SrcNet: 1, Proto: 6, Port: 443, CIDR: host, AllowedGroups: web}}); err != nil {
		t.Fatal(err)
	}
	if got := syn(443); got != tcActNext {
		t.Fatalf("Gateway /32 on 443: action=%d, want NEXT", got)
	}
	if got := syn(80); got != 2 {
		t.Fatalf("Gateway /32 rule on 443 must not open 80: action=%d", got)
	}
	o.member(t, 0)
	if got := syn(80); got != tcActNext {
		t.Fatalf("ungrouped pod: action=%d, want NEXT", got)
	}
}
