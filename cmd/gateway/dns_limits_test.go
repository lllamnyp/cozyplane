package main

import (
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestKernelDNSProxyConcurrencyBound(t *testing.T) {
	if os.Getenv("COZYPLANE_CNI_NETLINK_TEST") != "1" {
		t.Skip("isolated Linux container required for port 53")
	}
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 64)
	go func() {
		for {
			conn, err := upstream.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	proxy, err := runDNSProxy(upstream.Addr().String(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	var clients, peers []net.Conn
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
		for _, conn := range peers {
			_ = conn.Close()
		}
	}()
	for range 64 {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:53", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
		select {
		case peer := <-accepted:
			peers = append(peers, peer)
		case <-time.After(2 * time.Second):
			t.Fatal("admitted connection did not reach upstream")
		}
	}
	excess, err := net.DialTimeout("tcp", "127.0.0.1:53", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	_ = excess.SetReadDeadline(time.Now().Add(time.Second))
	var data [1]byte
	if _, err := excess.Read(data[:]); err == nil {
		t.Fatal("excess connection remained open")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess connection was not promptly closed")
	}
	select {
	case extra := <-accepted:
		extra.Close()
		t.Fatal("excess work reached upstream")
	default:
	}
	_ = peers[0].Close()
	_ = clients[0].SetReadDeadline(time.Now().Add(time.Second))
	_, _ = clients[0].Read(data[:])
	// Retry until the closing handler has executed its deferred slot release.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		retry, err := net.DialTimeout("tcp", "127.0.0.1:53", time.Second)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case peer := <-accepted:
			retry.Close()
			peer.Close()
			return
		case <-time.After(10 * time.Millisecond):
			retry.Close()
		}
	}
	t.Fatal("slot did not become available after completed relay")
}
