package datapath

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

type raReadyHandler struct {
	slog.Handler
	ready chan struct{}
}

func (h raReadyHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "RA responder serving" {
		select {
		case h.ready <- struct{}{}:
		default:
		}
	}
	return h.Handler.Handle(ctx, r)
}

func TestKernelRARepeatedCancellationDrainsSocketsAndWorkers(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("isolated privileged Linux container required")
	}
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphracancel"}, PeerName: "cphracancelp"}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatal(err)
	}
	defer netlink.LinkDel(veth)
	link, err := netlink.LinkByName(veth.Attrs().Name)
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	ip := net.ParseIP("fd00:70::60")
	if err := SetVethAlias(link, 101, []net.IP{ip}, mac); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	fdCount := func() int {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(files)
	}
	var beforeFD, beforeGo int
	// Initialize netpoll deterministically before measuring retained descriptors.
	warm, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	warm.Close()
	for i := 0; i < 6; i++ {
		ready := make(chan struct{}, 1)
		log := slog.New(raReadyHandler{Handler: slog.NewTextHandler(io.Discard, nil), ready: ready})
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			serveRA(ctx, link.Attrs().Name, link.Attrs().Index, link.Attrs().HardwareAddr, ip, 1400, nil, log)
		}()
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			cancel()
			t.Fatal("RA did not open socket")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("RA cancellation did not drain workers")
		}
		// First pass warms the Go network poller; subsequent passes must release
		// all responder-owned descriptors and goroutines before returning.
		if i == 0 {
			beforeFD = fdCount()
			beforeGo = runtime.NumGoroutine()
			continue
		}
		if got := fdCount(); got > beforeFD {
			t.Fatalf("socket leak after cancellation: before=%d after=%d", beforeFD, got)
		}
		if got := runtime.NumGoroutine(); got > beforeGo+1 {
			t.Fatalf("worker leak: before=%d after=%d", beforeGo, got)
		}
	}
}
