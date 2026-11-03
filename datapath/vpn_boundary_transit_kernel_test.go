package datapath

import (
	"encoding/binary"
	"net"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

// A workstation behind a VPNGateway reaches the VMs of a VPC with a managed
// boundary, and nothing else rides on that exception. Lab, 29/10/2026: the
// handshake came up, then every packet the appliance relayed (source 10.250.0.1)
// died at the boundary — at the source RPF check on the appliance's veth, and at
// the FWD_MARK drop in front of the VM.
func TestKernelVPNTransitThroughManagedBoundary(t *testing.T) {
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
		if name != "cozyplane_from_pod" && name != "cozyplane_to_pod" {
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

	// Test runs resolve the context ifindex to a real device.
	links := map[string]int{}
	for _, name := range []string{"cpvpnapp", "cpvpnvm", "cpvpnrtr"} {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			t.Fatal(err)
		}
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		links[name] = link.Attrs().Index
	}
	appliance, vm, router := links["cpvpnapp"], links["cpvpnvm"], links["cpvpnrtr"]

	const vni = 101
	m := &Manager{objs: overlayObjects{overlayMaps: overlayMaps{Networks: c.Maps["networks"]}}}
	if err := m.SetNetwork(vni, "172.16.0.0/24", vni); err != nil {
		t.Fatal(err)
	}
	applianceIP, vmIP, routerIP := net.ParseIP("172.16.0.5"), net.ParseIP("172.16.0.2"), net.ParseIP("172.16.0.9")
	// Each endpoint carries its ownership witness and a resolved, empty group
	// membership: ungrouped, so SecurityGroups stay out of what is tested here.
	for ip, ifindex := range map[string]int{applianceIP.String(): appliance, vmIP.String(): vm, routerIP.String(): router} {
		key, err := localKey(vni, net.ParseIP(ip))
		if err != nil {
			t.Fatal(err)
		}
		owner := SGEndpointOwner("port-"+ip, "sandbox-"+ip, "eth0")
		if err := c.Maps["locals"].Put(key, overlayEndpoint{Ifindex: uint32(ifindex), SgOwner: owner}); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["sg_members"].Put(key, overlaySgMember{Owner: owner}); err != nil {
			t.Fatal(err)
		}
	}
	// The appliance holds its production grant (the client /32); the tenant
	// router holds a blanket one — neither may carry a VPN prefix it is not the
	// route's next hop for.
	for ifindex, value := range map[int]uint32{
		appliance: vni | PortForwardFlag | PortForwardScopedFlag,
		vm:        vni,
		router:    vni | PortForwardFlag,
	} {
		if err := c.Maps["ports"].Put(uint32(ifindex), value); err != nil {
			t.Fatal(err)
		}
	}
	grant, err := fwdCIDRKey(uint32(appliance), "10.250.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["fwd_cidrs"].Put(grant, uint8(1)); err != nil {
		t.Fatal(err)
	}
	// Managed boundary WITHOUT Internet: VPN transit must not depend on it.
	if err := c.Maps["boundary_policy"].Put(uint32(vni), overlayBoundaryPolicy{Revision: 1, Identity: 1}); err != nil {
		t.Fatal(err)
	}
	setRoute := func(vpn bool) {
		t.Helper()
		key, value, err := routeMapEntry(RouteEntry{
			Scope: vni, CIDR: "10.250.0.1/32", NextHops: []RouteNextHop{{GwIP: applianceIP}}, VPN: vpn,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["vpc_routes"].Put(key, value); err != nil {
			t.Fatal(err)
		}
	}

	const (
		accept   = 0
		shot     = 2
		redirect = 7
		fwdMark  = 0x080000
	)
	run := func(t *testing.T, program string, ifindex int, mark uint32, src, dst string) uint32 {
		t.Helper()
		ctx := make([]byte, 192)
		binary.LittleEndian.PutUint32(ctx[8:12], mark)
		binary.LittleEndian.PutUint32(ctx[40:44], uint32(ifindex))
		p := policyFamilyPacket(net.ParseIP(src), net.ParseIP(dst))
		got, err := c.Programs[program].Run(&ebpf.RunOptions{Data: p, DataOut: make([]byte, len(p)+64), Context: ctx})
		if err != nil {
			t.Fatalf("%s: %v", program, err)
		}
		return got
	}
	for _, tc := range []struct {
		name     string
		vpnRoute bool
		program  string
		ifindex  int
		mark     uint32
		src, dst string
		want     uint32
	}{
		{"appliance relays its workstation to a VM", true, "cozyplane_from_pod", appliance, 0, "10.250.0.1", "172.16.0.2", redirect},
		{"a gateway route is no VPN route", false, "cozyplane_from_pod", appliance, 0, "10.250.0.1", "172.16.0.2", shot},
		{"another forwarding leg cannot source the VPN prefix", true, "cozyplane_from_pod", router, 0, "10.250.0.1", "172.16.0.2", shot},
		{"the appliance cannot source an unrouted prefix", true, "cozyplane_from_pod", appliance, 0, "10.99.0.1", "172.16.0.2", shot},
		{"a VM spoofing the workstation is refused", true, "cozyplane_from_pod", vm, 0, "10.250.0.1", "172.16.0.3", shot},
		{"the VM answers its workstation without Internet", true, "cozyplane_from_pod", vm, 0, "172.16.0.2", "10.250.0.1", redirect},
		{"the VM still has no Internet", true, "cozyplane_from_pod", vm, 0, "172.16.0.2", "198.51.100.7", shot},
		{"relayed workstation traffic enters the VM", true, "cozyplane_to_pod", vm, fwdMark, "10.250.0.1", "172.16.0.2", accept},
		{"relayed traffic from an unrouted prefix stays out", true, "cozyplane_to_pod", vm, fwdMark, "10.99.0.1", "172.16.0.2", shot},
		{"relayed traffic under a gateway route stays out", false, "cozyplane_to_pod", vm, fwdMark, "10.250.0.1", "172.16.0.2", shot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setRoute(tc.vpnRoute)
			if got := run(t, tc.program, tc.ifindex, tc.mark, tc.src, tc.dst); got != tc.want {
				t.Fatalf("verdict=%d want=%d", got, tc.want)
			}
		})
	}
}
