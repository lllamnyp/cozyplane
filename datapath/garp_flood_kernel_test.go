package datapath

import (
	"context"
	"encoding/binary"
	"net"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func guestAnnouncementTestVeth(t *testing.T, name string) (netlink.Link, netlink.Link) {
	t.Helper()
	l := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: name}, PeerName: name + "p"}
	if err := netlink.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(l) })
	peer, err := netlink.LinkByName(l.PeerName)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range []netlink.Link{l, peer} {
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	return l, peer
}

func TestKernelGuestAnnouncementNoiseDoesNotConsumeCPU(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	l, peer := guestAnnouncementTestVeth(t, "cphgnflood")
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons16(unix.ETH_P_ARP)))
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	frame := make([]byte, 60)
	for i := range 6 {
		frame[i] = 0xff
	}
	copy(frame[6:12], []byte{2, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(frame[12:14], unix.ETH_P_ARP)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], unix.ETH_P_IP)
	frame[18], frame[19] = 6, 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], frame[6:12])
	copy(frame[28:32], []byte{192, 0, 2, 10})
	dst := &unix.SockaddrLinklayer{Ifindex: peer.Attrs().Index, Halen: 6}
	copy(dst.Addr[:], frame[:6])
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	var sent atomic.Int64
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for ctx.Err() == nil {
			if err := unix.Sendto(fd, frame, 0, dst); err != nil {
				return
			}
			sent.Add(1)
		}
	}()
	defer func() { cancel(); <-stopped }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_THREAD, &before); err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	err = WatchGuestAnnounce(ctx, l.Attrs().Index, mac, net.ParseIP("192.0.2.99"))
	if err != context.DeadlineExceeded {
		t.Fatal("noise caused a cutover or prevented cancellation", err)
	}
	if err := unix.Getrusage(unix.RUSAGE_THREAD, &after); err != nil {
		t.Fatal(err)
	}
	cpu := time.Duration(unix.TimevalToNsec(after.Utime) + unix.TimevalToNsec(after.Stime) - unix.TimevalToNsec(before.Utime) - unix.TimevalToNsec(before.Stime))
	t.Logf("noise frames=%d listener CPU=%s", sent.Load(), cpu)
	if sent.Load() < 5000 {
		t.Fatal("flood did not exercise the listener")
	}
	if cpu > 100*time.Millisecond {
		t.Fatalf("unrelated announcement flood consumed %s listener CPU", cpu)
	}
}

func TestKernelGuestAnnouncementFilterAcceptsValidFrames(t *testing.T) {
	if os.Getenv("COZYPLANE_BPF_TEST") != "1" {
		t.Skip("requires isolated privileged Linux container")
	}
	l, peer := guestAnnouncementTestVeth(t, "cphgnvalid")
	mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
	for _, tc := range []struct {
		name, address string
		op            uint16
	}{{"ARP request", "192.0.2.99", 1}, {"ARP reply", "192.0.2.99", 2}, {"IPv6 NA", "fd00:100::99", 0}} {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.address)
			frame := unsolicitedNAFrame(mac, ip.To16())
			if ip.To4() != nil {
				frame = garpFrame(mac, ip.To4())
				binary.BigEndian.PutUint16(frame[20:22], tc.op)
			}
			fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons16(unix.ETH_P_ALL)))
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			dst := &unix.SockaddrLinklayer{Ifindex: peer.Attrs().Index, Halen: 6}
			copy(dst.Addr[:], frame[:6])
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			stopped := make(chan struct{})
			go func() {
				defer close(stopped)
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-tick.C:
						if unix.Sendto(fd, frame, 0, dst) != nil {
							return
						}
					}
				}
			}()
			defer func() { cancel(); <-stopped }()
			if err := WatchGuestAnnounce(ctx, l.Attrs().Index, mac, ip); err != nil {
				t.Fatal("kernel filter rejected valid announcement", err)
			}
		})
	}
}
