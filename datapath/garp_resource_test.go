package datapath

import (
	"context"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestGuestAnnouncementIdleCPUAndCancellation(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = watchGuestAnnounceSocket(ctx, fds[0], 1, net.HardwareAddr{2, 0, 0, 0, 0, 1}, net.ParseIP("10.210.0.20"), true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("watch: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancellation took %s", elapsed)
	}
	if err := unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &after); err != nil {
		t.Fatal(err)
	}
	if cpu := time.Duration(after.Nano() - before.Nano()); cpu > 100*time.Millisecond {
		t.Fatalf("idle listener consumed %s of CPU", cpu)
	}
}

func TestGuestAnnouncementWaitReceivesValidFrame(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	ip := net.ParseIP("10.210.0.20")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := unix.Sendto(fds[1], garpFrame(mac, net.ParseIP("10.210.0.21").To4()), 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(fds[1], garpFrame(mac, ip.To4()), 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := watchGuestAnnounceSocket(ctx, fds[0], 1, mac, ip, true); err != nil {
		t.Fatal(err)
	}
}
