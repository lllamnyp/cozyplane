package main

import (
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSUDPWorkersBoundedBeforeHandlerAcrossListeners(t *testing.T) {
	slots := make(chan struct{}, 2)
	gate := make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	var active atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		active.Add(1)
		defer active.Add(-1)
		<-gate
		response := new(dns.Msg)
		response.SetReply(req)
		_ = w.WriteMsg(response)
	})
	start := func() string {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		started, stopped := make(chan struct{}), make(chan error, 1)
		server := &dns.Server{PacketConn: conn, Handler: handler, NotifyStartedFunc: func() { close(started) }}
		installDNSUDPAdmission(server, slots)
		go func() { stopped <- server.ActivateAndServe() }()
		<-started
		t.Cleanup(func() {
			release.Do(func() { close(gate) })
			_ = server.Shutdown()
			if err := <-stopped; err != nil {
				t.Error(err)
			}
		})
		return conn.LocalAddr().String()
	}
	addresses := []string{start(), start()}
	request := new(dns.Msg)
	request.SetQuestion("example.invalid.", dns.TypeA)
	packet, err := request.Pack()
	if err != nil {
		t.Fatal(err)
	}
	malformed, err := net.Dial("udp", addresses[0])
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.Close()
	ignored := append([]byte(nil), packet...)
	ignored[2] |= 0x80
	badHeader := append([]byte(nil), packet...)
	badHeader[4], badHeader[5] = 0, 0
	badName := append([]byte(nil), packet...)
	badName[12], badName[13] = 0xc0, 12
	for i := 0; i < 20; i++ {
		for _, bad := range [][]byte{[]byte{0, 1, 2}, packet[:12], ignored, badHeader, badName} {
			_, _ = malformed.Write(bad)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if active.Load() != 0 || len(slots) != 0 {
		t.Fatal("malformed/ignored input retained a slot", active.Load(), len(slots))
	}
	var clients []net.Conn
	for _, address := range addresses {
		conn, err := net.Dial("udp", address)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
		defer conn.Close()
		if _, err := conn.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for active.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if active.Load() != 2 {
		t.Fatal("initial workers", active.Load())
	}
	baseline := runtime.NumGoroutine()
	for i := 0; i < 300; i++ {
		_, _ = clients[i%2].Write(packet)
		_, _ = clients[i%2].Write([]byte{0, 1, 2})
		bad := append([]byte(nil), packet...)
		bad[4], bad[5] = 0, 0
		_, _ = clients[i%2].Write(bad)
	}
	time.Sleep(100 * time.Millisecond)
	if active.Load() != 2 {
		t.Fatalf("UDP worker flood admitted %d handlers; limit 2", active.Load())
	}
	if growth := runtime.NumGoroutine() - baseline; growth > 16 {
		t.Fatalf("pre-handler worker growth %d", growth)
	}
	if len(slots) != 2 {
		t.Fatal("transport slots", len(slots))
	}
	release.Do(func() { close(gate) })
	deadline = time.Now().Add(time.Second)
	for len(slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(slots) != 0 {
		t.Fatal("worker slots retained", len(slots))
	}
	for i := 0; i < 100; i++ {
		response, _, err := (&dns.Client{Timeout: time.Second}).Exchange(request, addresses[i%2])
		if err != nil || response.Rcode != dns.RcodeSuccess {
			t.Fatal("UDP recovery", response, err)
		}
	}
	deadline = time.Now().Add(time.Second)
	for len(slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(slots) != 0 {
		t.Fatal("slots leaked over request churn", len(slots))
	}
}
