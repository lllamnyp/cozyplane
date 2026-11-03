package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestClientRestartClosesTunnelBeforeReadingConfig(t *testing.T) {
	if os.Getenv("COZYPLANE_KERNEL_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	runtime.LockOSThread()
	original, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = netns.Set(original); _ = original.Close(); runtime.UnlockOSThread() }()
	ns, err := netns.New()
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: wgDev, Alias: clientDeviceAlias}}); err != nil {
		t.Fatal(err)
	}
	dev, err := netlink.LinkByName(wgDev)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetAlias(dev, clientDeviceAlias); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dev); err != nil {
		t.Fatal(err)
	}
	if err := run(filepath.Join(t.TempDir(), "missing.json"), slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("missing config accepted")
	}
	if _, err := netlink.LinkByName(wgDev); err == nil {
		t.Fatal("old client tunnel survived failed startup")
	}
}
