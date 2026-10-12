package main

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func startLimitedDNSTCP(t *testing.T, slots chan struct{}) string {
	t.Helper()
	listener, err := listenDNSTCP("127.0.0.1:0", slots)
	if err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan error, 1)
	server := &dns.Server{Listener: listener, ReadTimeout: time.Second, NotifyStartedFunc: func() { close(started) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(req)
		_ = w.WriteMsg(response)
	})}
	go func() { stopped <- server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown(); <-stopped })
	return listener.Addr().String()
}

func waitDNSTCPSlots(t *testing.T, slots chan struct{}, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(slots) == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("TCP connection slots: got %d want %d", len(slots), count)
}

func TestIdleDNSTCPConnectionsAreBoundedAcrossListeners(t *testing.T) {
	slots := make(chan struct{}, 2)
	firstAddress := startLimitedDNSTCP(t, slots)
	secondAddress := startLimitedDNSTCP(t, slots)
	var clients []net.Conn
	defer func() {
		for _, client := range clients {
			_ = client.Close()
		}
	}()
	for _, address := range []string{firstAddress, secondAddress} {
		client, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
	}
	waitDNSTCPSlots(t, slots, 2)
	excess, err := net.DialTimeout("tcp", firstAddress, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer excess.Close()
	_ = excess.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	if _, err := excess.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess idle connection retained")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("excess socket waited instead of closing")
	}
	_ = clients[0].Close()
	waitDNSTCPSlots(t, slots, 1)
	req := new(dns.Msg)
	req.SetQuestion("example.invalid.", dns.TypeA)
	response, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(req, firstAddress)
	if err != nil || response.Rcode != dns.RcodeSuccess {
		t.Fatal("released slot did not admit a DNS query", response, err)
	}
	waitDNSTCPSlots(t, slots, 1)
	_ = clients[1].Close()
	waitDNSTCPSlots(t, slots, 0)
	for range 100 {
		if _, _, err := (&dns.Client{Net: "tcp", Timeout: time.Second}).Exchange(req, firstAddress); err != nil {
			t.Fatal("slot leaked over connection churn", err)
		}
		waitDNSTCPSlots(t, slots, 0)
	}
}
