package datapath

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestKernelFabricSnapshotRequiresCurrentRouteOwnerAndLiveAlias(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("isolated privileged network namespace required")
	}
	makeVeth := func(name, sandbox string) netlink.Link {
		t.Helper()
		link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		current, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(current) })
		if err := netlink.LinkSetUp(current); err != nil {
			t.Fatal(err)
		}
		mac, _ := net.ParseMAC("02:00:00:00:00:01")
		alias := aliasWithSandbox(FormatVethAlias(0, []net.IP{net.ParseIP("192.0.2.77")}, mac), sandbox, "eth0")
		if err := netlink.LinkSetAlias(current, alias); err != nil {
			t.Fatal(err)
		}
		return current
	}
	old := makeVeth("cphhealold", "old-sandbox")
	current := makeVeth("cphhealnew", "current-sandbox")
	ip := net.ParseIP("192.0.2.77")
	if err := EnsureFabricHostRoute(current.Attrs().Index, ip); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		rows, err := SnapshotLocalFabricIPs()
		if err != nil {
			t.Fatal(err)
		}
		matches := 0
		for _, row := range rows {
			if row.Address == ip.String() {
				matches++
				if row.ContainerID != want {
					t.Fatalf("stale route owner repaired: %+v", row)
				}
			}
		}
		if want == "" && matches != 0 || want != "" && matches != 1 {
			t.Fatalf("inventory matches=%d want sandbox %q", matches, want)
		}
	}
	check("current-sandbox")
	if err := EnsureFabricHostRoute(old.Attrs().Index, ip); err != nil {
		t.Fatal(err)
	}
	check("old-sandbox")
	if err := netlink.LinkSetAlias(old, FormatVethAlias(QuarantineNet, nil, nil)); err != nil {
		t.Fatal(err)
	}
	check("")
}
