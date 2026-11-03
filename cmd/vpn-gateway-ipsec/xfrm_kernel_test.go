package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

func isolatedXfrmNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("COZYPLANE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	ns, err := netns.New()
	if err != nil {
		_ = original.Close()
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netns.Set(original); _ = ns.Close(); _ = original.Close(); runtime.UnlockOSThread() })
}

func TestKernelXfrmCleanupPreventsDefaultFallbackAndRecovers(t *testing.T) {
	isolatedXfrmNamespace(t)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "underlay"}}); err != nil {
		t.Fatal(err)
	}
	wan, err := netlink.LinkByName("underlay")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(wan); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.1/24", "fd02::1/64"} {
		addr, err := netlink.ParseAddr(raw)
		if err != nil {
			t.Fatal(err)
		}
		addr.Flags |= unix.IFA_F_NODAD
		if err := netlink.AddrAdd(wan, addr); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"0.0.0.0/0", "::/0"} {
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: wan.Attrs().Index, Dst: mustIPNet(raw)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "ipsec7"}, Ifid: 7}); err != nil {
		t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
	}
	dev, err := netlink.LinkByName("ipsec7")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	remote := []string{"10.9.0.0/16", "fd00:9::/64"}
	for _, raw := range remote {
		if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: mustIPNet(raw)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{"10.9.0.2", "fd00:9::2"} {
		routes, err := netlink.RouteGet(net.ParseIP(raw))
		if err != nil || len(routes) != 1 || routes[0].LinkIndex != dev.Attrs().Index {
			t.Fatal("fixture missed tunnel route", routes, err)
		}
	}
	if err := run(filepath.Join(t.TempDir(), "missing.json"), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("missing config accepted")
	}
	for _, raw := range []string{"10.9.0.2", "fd00:9::2"} {
		if routes, err := netlink.RouteGet(net.ParseIP(raw)); err == nil {
			t.Fatal("retired tunnel prefix fell through to cleartext default route", raw, routes)
		}
	}
	if err := ensureXfrm(7, remote, []string{"10.1.0.0/24", "fd00:1::/64"}, 1280); err != nil {
		t.Fatal(err)
	}
	current, err := netlink.LinkByName("ipsec7")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"10.9.0.2", "fd00:9::2"} {
		routes, err := netlink.RouteGet(net.ParseIP(raw))
		if err != nil || len(routes) != 1 || routes[0].LinkIndex != current.Attrs().Index {
			t.Fatal("current tunnel did not replace blackhole", routes, err)
		}
	}
}

func TestKernelXfrmFreshPrefixesProtectedBeforeStartup(t *testing.T) {
	isolatedXfrmNamespace(t)
	peers := []peer{{RemoteCIDRs: []string{"10.9.0.0/16", "fd00:9::/64"}}}
	if err := protectRemotePrefixes(peers); err != nil {
		t.Fatal(err)
	}
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range peers[0].RemoteCIDRs {
		found := false
		for _, route := range routes {
			if route.Dst != nil && route.Dst.String() == prefix && route.Type == unix.RTN_BLACKHOLE {
				found = true
			}
		}
		if !found {
			t.Fatal("fresh prefix did not install a kernel blackhole", prefix, routes)
		}
	}
	for _, raw := range []string{"10.9.0.2", "fd00:9::2"} {
		if routes, err := netlink.RouteGet(net.ParseIP(raw)); err == nil {
			t.Fatal("fresh prefix routable before tunnel startup", routes)
		}
	}
	if err := protectRemotePrefixes(peers); err != nil {
		t.Fatal("repeated protection failed", err)
	}
}

func TestKernelXfrmCleanupPreservesForeignAlias(t *testing.T) {
	isolatedXfrmNamespace(t)
	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "ipsec7"}, Ifid: 7}); err != nil {
		t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
	}
	dev, err := netlink.LinkByName("ipsec7")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetAlias(dev, "foreign-device"); err != nil {
		t.Fatal(err)
	}
	if err := closePreviousXfrm(); err != nil {
		t.Fatal(err)
	}
	if _, err := netlink.LinkByName("ipsec7"); err != nil {
		t.Fatal("foreign alias deleted", err)
	}
}

func TestKernelXfrmRestartRevokesOrphanStateBeforeInvalidConfig(t *testing.T) {
	for _, mode := range []string{"missing", "malformed", "stale"} {
		t.Run(mode, func(t *testing.T) { testXfrmRestartInvalidConfig(t, mode) })
	}
}

func testXfrmRestartInvalidConfig(t *testing.T, mode string) {
	isolatedXfrmNamespace(t)
	state := netlink.XfrmState{Src: net.ParseIP("192.0.2.1").To4(), Dst: net.ParseIP("192.0.2.2").To4(), Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL, Spi: 7, Ifid: 7,
		Auth: &netlink.XfrmStateAlgo{Name: "hmac(sha256)", Key: []byte("01234567890123456789012345678901")}, Crypt: &netlink.XfrmStateAlgo{Name: "cbc(aes)", Key: []byte("01234567890123456789012345678901")}}
	if err := netlink.XfrmStateAdd(&state); err != nil {
		t.Fatal(err)
	}
	policy := netlink.XfrmPolicy{Src: mustIPNet("10.1.0.0/24"), Dst: mustIPNet("10.2.0.0/24"), Dir: netlink.XFRM_DIR_OUT, Ifid: 7, Tmpls: []netlink.XfrmPolicyTmpl{{Src: state.Src, Dst: state.Dst, Proto: state.Proto, Mode: state.Mode, Spi: state.Spi}}}
	if err := netlink.XfrmPolicyAdd(&policy); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if mode != "missing" {
		raw := []byte("{")
		if mode == "stale" {
			raw = []byte(`{"peers":[]}`)
			t.Setenv("VPN_CONFIG_CHECKSUM", configChecksum([]byte(`{"peers":[{}]}`)))
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(path, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("invalid config accepted")
	}
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(states) != 0 {
		t.Fatal("old SA survived failed restart", len(states), err)
	}
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil || len(policies) != 0 {
		t.Fatal("old policy survived failed restart", len(policies), err)
	}
}

func TestKernelXfrmRefusesOtherDeviceType(t *testing.T) {
	isolatedXfrmNamespace(t)
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "ipsec7"}}); err != nil {
		t.Fatal(err)
	}
	if err := ensureXfrm(7, []string{"10.2.0.0/24"}, []string{"10.1.0.0/24"}, 1340); err == nil {
		t.Fatal("non-XFRM device adopted")
	}
	dev, err := netlink.LinkByName("ipsec7")
	if err != nil {
		t.Fatal(err)
	}
	if dev.Attrs().Flags&net.FlagUp != 0 {
		t.Fatal("unrelated device activated")
	}
	routes, err := netlink.RouteList(dev, netlink.FAMILY_ALL)
	if err != nil || len(routes) != 0 {
		t.Fatal("cleartext routes installed", routes, err)
	}
}

func TestKernelXfrmInterfaceRestartClosesOldDevice(t *testing.T) {
	isolatedXfrmNamespace(t)
	if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "ipsec7"}, Ifid: 7}); err != nil {
		t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
	}
	dev, err := netlink.LinkByName("ipsec7")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: dev.Attrs().Index, Dst: mustIPNet("10.2.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(t.TempDir(), "missing.json"), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("missing config accepted")
	}
	if _, err := netlink.LinkByName("ipsec7"); err == nil {
		t.Fatal("old XFRM interface survived")
	}
}

func mustIPNet(raw string) *net.IPNet {
	_, prefix, err := net.ParseCIDR(raw)
	if err != nil {
		panic(err)
	}
	return prefix
}

func TestKernelXfrmProbeRecoversInterruptedPreflight(t *testing.T) {
	for _, alias := range []string{"", "cozyplane-vpn-ipsec-probe"} {
		t.Run(alias, func(t *testing.T) {
			isolatedXfrmNamespace(t)
			if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "cpxfrmprobe"}, Ifid: 0xcb1}); err != nil {
				t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
			}
			dev, err := netlink.LinkByName("cpxfrmprobe")
			if err != nil {
				t.Fatal(err)
			}
			if alias != "" {
				if err := netlink.LinkSetAlias(dev, alias); err != nil {
					t.Fatal(err)
				}
			}
			if err := probeXfrmSupport(); err != nil {
				t.Fatal("stale probe blocked restart", err)
			}
			if _, err := netlink.LinkByName("cpxfrmprobe"); err == nil {
				t.Fatal("preflight leaked its probe")
			}
		})
	}
}

func TestKernelXfrmProbePreservesForeignDevice(t *testing.T) {
	for _, tc := range []struct {
		id    uint32
		alias string
	}{{0xcb2, ""}, {0xcb1, "foreign-probe"}} {
		t.Run(tc.alias, func(t *testing.T) {
			isolatedXfrmNamespace(t)
			if err := netlink.LinkAdd(&netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: "cpxfrmprobe"}, Ifid: tc.id}); err != nil {
				t.Skipf("kernel lacks CONFIG_XFRM_INTERFACE: %v", err)
			}
			dev, err := netlink.LinkByName("cpxfrmprobe")
			if err != nil {
				t.Fatal(err)
			}
			if tc.alias != "" {
				if err := netlink.LinkSetAlias(dev, tc.alias); err != nil {
					t.Fatal(err)
				}
			}
			if err := probeXfrmSupport(); err == nil {
				t.Fatal("foreign device accepted")
			}
			if _, err := netlink.LinkByName("cpxfrmprobe"); err != nil {
				t.Fatal("foreign device removed", err)
			}
		})
	}
}
