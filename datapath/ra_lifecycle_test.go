package datapath

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestRAWorkersReplaceChangedIdentityAtSameIfindex(t *testing.T) {
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "cphra", Index: 123, HardwareAddr: mac, Alias: FormatVethAlias(101, []net.IP{net.ParseIP("fd00:70::2")}, mac)}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	workers := map[int]*raWorker{}
	started := make(chan string, 5)
	start := func(child context.Context, l netlink.Link) { started <- raIdentity(l); <-child.Done() }
	wait := func() string {
		t.Helper()
		select {
		case id := <-started:
			return id
		case <-time.After(time.Second):
			t.Fatal("worker not started")
			return ""
		}
	}
	reconcileRAWorkers(ctx, workers, []netlink.Link{link}, start)
	first := wait()
	old := workers[123]
	reconcileRAWorkers(ctx, workers, []netlink.Link{link}, start)
	if workers[123] != old {
		t.Fatal("unchanged identity replaced")
	}
	replacement := &netlink.Veth{LinkAttrs: link.LinkAttrs}
	replacement.Alias = FormatVethAlias(202, []net.IP{net.ParseIP("fd00:80::2")}, mac)
	reconcileRAWorkers(ctx, workers, []netlink.Link{replacement}, start)
	if second := wait(); second == first {
		t.Fatal("reused ifindex kept old tenant")
	}
	select {
	case <-old.done:
	default:
		t.Fatal("replacement started before old worker drained")
	}
	current := workers[123]
	reconcileRAWorkers(ctx, workers, nil, start)
	if len(workers) != 0 {
		t.Fatal("dead link retained worker")
	}
	select {
	case <-current.done:
	default:
		t.Fatal("removed worker not drained")
	}
	if raEligible(&netlink.Dummy{LinkAttrs: link.LinkAttrs}) != nil {
		t.Fatal("non-veth accepted")
	}
}

func TestRARescansCoalesceLinkBurstAndClosedSubscription(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	updates := make(chan netlink.LinkUpdate, 10000)
	for range 10000 {
		updates <- netlink.LinkUpdate{}
	}
	close(updates)
	var scans atomic.Int32
	done := make(chan struct{})
	go func() { defer close(done); raRescanLoop(ctx, updates, func() { scans.Add(1) }) }()
	timer := time.NewTimer(250 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	cancel()
	<-done
	if count := scans.Load(); count != 1 {
		t.Fatal("link burst or closed subscription caused repeated scans", count)
	}
}
