package datapath

import (
	"context"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKernelGuestAnnouncementIdleWaitDoesNotBusySpin(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var before, after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_THREAD, &before); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	err := WatchGuestAnnounce(ctx, 1, mac, net.ParseIP("192.0.2.99"))
	if err != context.DeadlineExceeded {
		t.Fatalf("idle listener did not cancel: %v", err)
	}
	if err := unix.Getrusage(unix.RUSAGE_THREAD, &after); err != nil {
		t.Fatal(err)
	}
	cpu := time.Duration(unix.TimevalToNsec(after.Utime) + unix.TimevalToNsec(after.Stime) - unix.TimevalToNsec(before.Utime) - unix.TimevalToNsec(before.Stime))
	if cpu > 50*time.Millisecond {
		t.Fatalf("idle listener consumed %s CPU while waiting", cpu)
	}
	if time.Since(started) > 1500*time.Millisecond {
		t.Fatal("cancellation exceeded poll bound")
	}
}
