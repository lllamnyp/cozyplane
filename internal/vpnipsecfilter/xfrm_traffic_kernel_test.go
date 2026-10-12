package vpnipsecfilter

import (
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Three anonymous namespaces model a hostile encrypted peer, the appliance and
// a VPC workload. Kernel SAs avoid depending on IKE credentials in this focused
// test: the full strongSwan handshake is exercised by the external tunnel suite.
func TestKernelXfrmDecryptedTraffic(t *testing.T) {
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
	defer func() {
		for _, ns := range spaces {
			_ = ns.Close()
		}
	}()
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
	server, client, workload := spaces[0], spaces[1], spaces[2]
	enter := func(ns netns.NsHandle) {
		t.Helper()
		if err := netns.Set(ns); err != nil {
			t.Fatal(err)
		}
	}
	device := func(name string) netlink.Link {
		t.Helper()
		dev, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		return dev
	}
	addAddress := func(name, cidr string) {
		t.Helper()
		addr, err := netlink.ParseAddr(cidr)
		if err != nil {
			t.Fatal(err)
		}
		if addr.IP.To4() == nil {
			addr.Flags |= unix.IFA_F_NODAD
		}
		if err := netlink.AddrAdd(device(name), addr); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(device(name)); err != nil {
			t.Fatal(err)
		}
	}
	prefix := func(raw string) *net.IPNet {
		_, p, err := net.ParseCIDR(raw)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	addRoute := func(name, cidr, gateway string) {
		t.Helper()
		r := netlink.Route{LinkIndex: device(name).Attrs().Index, Dst: prefix(cidr)}
		if gateway != "" {
			r.Gw = net.ParseIP(gateway)
		}
		if err := netlink.RouteAdd(&r); err != nil {
			t.Fatal(err)
		}
	}
	enter(server)
	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "ipsec-test"}, Ifid: 7}); err != nil {
		t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
	}
	for _, pair := range []struct {
		name, remote string
		ns           netns.NsHandle
	}{{"underlay", "clientwan", client}, {"vpc", "workload", workload}} {
		if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: pair.name}, PeerName: pair.remote}); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetNsFd(device(pair.remote), int(pair.ns)); err != nil {
			t.Fatal(err)
		}
	}
	addAddress("underlay", "192.0.2.1/30")
	addAddress("vpc", "10.1.0.1/24")
	addAddress("vpc", "fd00:1::1/64")
	if err := netlink.LinkSetUp(device("ipsec-test")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	addRoute("vpc", "10.2.0.0/24", "")
	addRoute("ipsec-test", "10.200.0.0/24", "")
	addRoute("vpc", "fd00:2::/64", "")
	addRoute("ipsec-test", "fd00:200::/64", "")
	enter(client)
	addAddress("clientwan", "192.0.2.2/30")
	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "ipsec-test"}, Ifid: 7}); err != nil {
		t.Fatal(err)
	}
	addAddress("ipsec-test", "10.200.0.2/32")
	addAddress("ipsec-test", "10.200.0.3/32")
	addAddress("ipsec-test", "fd00:200::2/128")
	addAddress("ipsec-test", "fd00:200::3/128")
	addRoute("ipsec-test", "10.1.0.0/24", "")
	addRoute("ipsec-test", "10.2.0.0/24", "")
	addRoute("ipsec-test", "fd00:1::/64", "")
	addRoute("ipsec-test", "fd00:2::/64", "")
	// Both endpoints carry reciprocal tunnel SAs. The hostile peer is allowed
	// to encrypt a /24; the appliance's inbound policy authorizes only its /32.
	for _, ns := range []netns.NsHandle{server, client} {
		enter(ns)
		for _, sa := range []struct {
			src, dst string
			spi      int
		}{{"192.0.2.2", "192.0.2.1", 101}, {"192.0.2.1", "192.0.2.2", 102}} {
			state := netlink.XfrmState{Src: net.ParseIP(sa.src).To4(), Dst: net.ParseIP(sa.dst).To4(), Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL, Spi: sa.spi, Reqid: 7, Ifid: 7, ReplayWindow: 32,
				Auth: &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: []byte("01234567890123456789012345678901"), TruncateLen: 128}, Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: []byte("01234567890123456789012345678901")}}
			if err := netlink.XfrmStateAdd(&state); err != nil {
				t.Fatal(err)
			}
			// netlink's XfrmState does not expose XFRM_STATE_AF_UNSPEC, so
			// use a second SA pair with explicit IPv6 inner selectors.
			state.Spi += 100
			state.Reqid = 8
			state.Selector = &netlink.XfrmPolicy{Src: prefix("::/0"), Dst: prefix("::/0")}
			if err := netlink.XfrmStateAdd(&state); err != nil {
				t.Fatal(err)
			}
		}
		for _, inner := range []struct{ remote, authorized, any string }{{"10.200.0.0/24", "10.200.0.2/32", "0.0.0.0/0"}, {"fd00:200::/64", "fd00:200::2/128", "::/0"}} {
			reqid := 7
			if inner.any == "::/0" {
				reqid = 8
			}
			for _, dir := range []netlink.Dir{netlink.XFRM_DIR_IN, netlink.XFRM_DIR_OUT, netlink.XFRM_DIR_FWD} {
				src, dst, outerSrc, outerDst := inner.remote, inner.any, "192.0.2.2", "192.0.2.1"
				if ns == server && dir != netlink.XFRM_DIR_OUT {
					src = inner.authorized
				}
				if (ns == client && dir != netlink.XFRM_DIR_OUT) || (ns == server && dir == netlink.XFRM_DIR_OUT) {
					src, dst, outerSrc, outerDst = inner.any, inner.remote, "192.0.2.1", "192.0.2.2"
				}
				policy := netlink.XfrmPolicy{Src: prefix(src), Dst: prefix(dst), Dir: dir, Ifid: 7, Tmpls: []netlink.XfrmPolicyTmpl{{Src: net.ParseIP(outerSrc).To4(), Dst: net.ParseIP(outerDst).To4(), Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL, Reqid: reqid}}}
				if err := netlink.XfrmPolicyAdd(&policy); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	enter(workload)
	addAddress("workload", "10.1.0.2/24")
	addAddress("workload", "10.2.0.2/32")
	addAddress("workload", "fd00:1::2/64")
	addAddress("workload", "fd00:2::2/128")
	addRoute("workload", "10.200.0.0/24", "10.1.0.1")
	addRoute("workload", "fd00:200::/64", "fd00:1::1")
	var listeners []*net.UDPConn
	defer func() {
		for _, conn := range listeners {
			_ = conn.Close()
		}
	}()
	listen := func(ip string) {
		t.Helper()
		protocol := "udp4"
		if net.ParseIP(ip).To4() == nil {
			protocol = "udp6"
		}
		conn, err := net.ListenUDP(protocol, &net.UDPAddr{IP: net.ParseIP(ip), Port: 42301})
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, conn)
		go func() {
			var b [64]byte
			for {
				_, src, err := conn.ReadFromUDP(b[:])
				if err != nil {
					return
				}
				_, _ = conn.WriteToUDP([]byte(src.IP.String()), src)
			}
		}()
	}
	listen("10.1.0.2")
	listen("10.2.0.2")
	listen("fd00:1::2")
	listen("fd00:2::2")
	enter(server)
	listen("10.1.0.1")
	listen("fd00:1::1")
	probe := func(src, dst string, allow bool) {
		t.Helper()
		enter(client)
		protocol := "udp4"
		if net.ParseIP(src).To4() == nil {
			protocol = "udp6"
		}
		conn, err := net.DialUDP(protocol, &net.UDPAddr{IP: net.ParseIP(src)}, &net.UDPAddr{IP: net.ParseIP(dst), Port: 42301})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		timeout := 600 * time.Millisecond
		if allow {
			timeout = 3 * time.Second
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("probe")); err != nil {
			t.Fatal(err)
		}
		var b [64]byte
		n, err := conn.Read(b[:])
		if allow {
			if err != nil || string(b[:n]) != src {
				t.Fatalf("authorized probe %s -> %s: source=%q err=%v", src, dst, b[:n], err)
			}
		} else if err == nil {
			t.Fatalf("forbidden probe %s -> %s reached destination", src, dst)
		}
	}
	// Reproduce the original wildcard-local_ts exposure before installing TC.
	probe("10.200.0.2", "10.1.0.1", true)
	probe("10.200.0.2", "10.1.0.2", true)
	probe("fd00:200::2", "fd00:1::1", true)
	probe("fd00:200::2", "fd00:1::2", true)
	enter(server)
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted uint64
	for _, state := range states {
		encrypted += state.Statistics.Packets
	}
	if encrypted == 0 {
		t.Fatal("baseline bypassed encryption")
	}
	dev := device("ipsec-test")
	if err := netlink.LinkSetDown(dev); err != nil {
		t.Fatal(err)
	}
	if err := Install(device("ipsec-test"), []string{"10.1.0.0/24", "fd00:1::/64"}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	// Administrative down removed this unicast route; restore it before
	// checking replies so a routing failure cannot masquerade as a TC verdict.
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: prefix("10.200.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: prefix("fd00:200::/64")}); err != nil {
		t.Fatal(err)
	}
	probe("10.200.0.2", "10.1.0.2", true)
	probe("10.200.0.2", "10.1.0.1", false)
	probe("10.200.0.2", "10.2.0.2", false)
	probe("10.200.0.3", "10.1.0.2", false)
	probe("fd00:200::2", "fd00:1::2", true)
	probe("fd00:200::2", "fd00:1::1", false)
	probe("fd00:200::2", "fd00:2::2", false)
	probe("fd00:200::3", "fd00:1::2", false)
}
