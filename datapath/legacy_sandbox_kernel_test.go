package datapath

import (
	"os"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestKernelRecordLegacyVethSandbox(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("isolated privileged network namespace required")
	}
	// The alias format written by releases that predate sandbox witnesses.
	const legacy = "cozyplane:1;net=100;gw=0;fwd=0;mac=02:00:00:00:00:01;ips=172.16.0.2"
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphlegacysb"}, PeerName: "cphlegacysbp"}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	current, err := netlink.LinkByName("cphlegacysb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(current) })
	if err := netlink.LinkSetAlias(current, legacy); err != nil {
		t.Fatal(err)
	}
	if err := RecordLegacyVethSandbox(current.Attrs().Index, legacy+";x", "sandbox", "eth0"); err == nil {
		t.Fatal("a changed record must not be rewritten")
	}
	if err := RecordLegacyVethSandbox(current.Attrs().Index, legacy, "sandbox", ""); err == nil {
		t.Fatal("an incomplete witness must be refused")
	}
	if err := RecordLegacyVethSandbox(current.Attrs().Index, legacy, "sandbox", "eth0"); err != nil {
		t.Fatal(err)
	}
	updated, err := netlink.LinkByIndex(current.Attrs().Index)
	if err != nil {
		t.Fatal(err)
	}
	alias := updated.Attrs().Alias
	if cid, iface := VethSandbox(alias); cid != "sandbox" || iface != "eth0" {
		t.Fatalf("sandbox not recorded: %q", alias)
	}
	if raw, ips, _, ok := parseVethAlias(alias); !ok || raw != 100 || len(ips) != 1 || ips[0].String() != "172.16.0.2" {
		t.Fatalf("endpoint record altered: %q", alias)
	}
	if VethPortIdentity(alias).UID != "" || VethPortIdentity(alias).Staged {
		t.Fatal("recovery must not invent a Port identity or staging")
	}
	if err := RecordLegacyVethSandbox(current.Attrs().Index, alias, "other", "eth0"); err == nil {
		t.Fatal("a recorded sandbox must never be replaced")
	}
}
