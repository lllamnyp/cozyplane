package vpnclientfilter

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Each fixture owns three anonymous network namespaces: client, VPN appliance,
// and workload. No host routes, existing WireGuard interfaces or tunnels change.
func TestKernelWireGuardClientTraffic(t *testing.T) {
	if os.Getenv("COZYPLANE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netns.Set(original); _ = original.Close(); runtime.UnlockOSThread() }()
	var spaces []netns.NsHandle
	for range 3 {
		ns, err := netns.New()
		if err != nil {
			t.Fatal(err)
		}
		spaces = append(spaces, ns)
		if err := netns.Set(original); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, ns := range spaces {
			_ = ns.Close()
		}
	}()
	server, client, workload := spaces[0], spaces[1], spaces[2]
	enter := func(ns netns.NsHandle) {
		t.Helper()
		if err := netns.Set(ns); err != nil {
			t.Fatal(err)
		}
	}
	addAddress := func(name, cidr string) {
		t.Helper()
		dev, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		address, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.AddrAdd(dev, address); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(dev); err != nil {
			t.Fatal(err)
		}
	}
	addRoute := func(name, cidr, gateway string) {
		t.Helper()
		dev, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		_, prefix, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		route := &netlink.Route{LinkIndex: dev.Attrs().Index, Dst: prefix}
		if gateway != "" {
			route.Gw = net.ParseIP(gateway)
		}
		if err := netlink.RouteAdd(route); err != nil {
			t.Fatal(err)
		}
	}
	// Underlay and VPC veth pairs start inside the appliance namespace.
	enter(server)
	for _, pair := range []struct {
		name, remote string
		ns           netns.NsHandle
	}{{"underlay", "clientwan", client}, {"vpc", "workload", workload}} {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: pair.name}, PeerName: pair.remote}); err != nil {
			t.Fatal(err)
		}
		peer, err := netlink.LinkByName(pair.remote)
		if err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(peer, int(pair.ns)); err != nil {
			t.Fatal(err)
		}
	}
	addAddress("underlay", "192.0.2.1/30")
	addAddress("vpc", "10.1.0.1/24")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	addRoute("vpc", "10.2.0.0/24", "")
	enter(client)
	addAddress("clientwan", "192.0.2.2/30")
	enter(workload)
	addAddress("workload", "10.1.0.2/24")
	addAddress("workload", "10.2.0.2/32")
	addRoute("workload", "10.200.0.2/32", "10.1.0.1")
	listener, err := net.ListenPacket("udp4", "0.0.0.0:42300")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	configure := func(ns netns.NsHandle, key wgtypes.Key, peer wgtypes.PeerConfig, port int) netlink.Link {
		t.Helper()
		enter(ns)
		if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: "wgtest"}}); err != nil {
			t.Fatal(err)
		}
		dev, err := netlink.LinkByName("wgtest")
		if err != nil {
			t.Fatal(err)
		}
		wg, err := wgctrl.New()
		if err != nil {
			t.Fatal(err)
		}
		defer wg.Close()
		if err := wg.ConfigureDevice("wgtest", wgtypes.Config{PrivateKey: &key, ListenPort: &port, ReplacePeers: true, Peers: []wgtypes.PeerConfig{peer}}); err != nil {
			t.Fatal(err)
		}
		return dev
	}
	_, host, _ := net.ParseCIDR("10.200.0.2/32")
	serverDev := configure(server, serverKey, wgtypes.PeerConfig{PublicKey: clientKey.PublicKey(), ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*host}}, 51820)
	if err := Install(serverDev, []Peer{{Addresses: []string{"10.200.0.2/32"}, Destinations: []string{"10.1.0.0/24"}}}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(serverDev); err != nil {
		t.Fatal(err)
	}
	addRoute("wgtest", "10.200.0.2/32", "")
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	configure(client, clientKey, wgtypes.PeerConfig{PublicKey: serverKey.PublicKey(), ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*all}, Endpoint: &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 51820}}, 51821)
	addAddress("wgtest", "10.200.0.2/32")
	addRoute("wgtest", "10.1.0.0/24", "")
	addRoute("wgtest", "10.2.0.0/24", "")
	for _, test := range []struct {
		name, dst string
		allow     bool
	}{{"authorized VPC", "10.1.0.2", true}, {"unauthorized VPC", "10.2.0.2", false}} {
		t.Run(test.name, func(t *testing.T) {
			runtime.LockOSThread()
			defer func() { _ = netns.Set(original); runtime.UnlockOSThread() }()
			enter(client)
			socket, err := net.Dial("udp4", net.JoinHostPort(test.dst, "42300"))
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			if _, err := socket.Write([]byte("client-test")); err != nil {
				t.Fatal(err)
			}
			if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 64)
			n, remote, err := listener.ReadFrom(buffer)
			if !test.allow {
				if err == nil {
					t.Fatalf("unauthorized packet reached workload: %s", buffer[:n])
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if remote.(*net.UDPAddr).IP.String() != "10.200.0.2" {
				t.Fatalf("client source changed: %s", remote)
			}
			if _, err := listener.WriteTo([]byte("reply"), remote); err != nil {
				t.Fatal(err)
			}
			if err := socket.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := socket.Read(buffer); err != nil {
				t.Fatal(err)
			}
		})
	}
	enter(original)
}
