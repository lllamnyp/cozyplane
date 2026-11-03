/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

type failedDNSListener struct{}

func (failedDNSListener) Accept() (net.Conn, error) {
	return nil, errors.New("test permanent accept failure")
}
func (failedDNSListener) Close() error   { return nil }
func (failedDNSListener) Addr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1")} }
func TestDNSProxyReportsPermanentListenerFailure(t *testing.T) {
	u, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if e != nil {
		t.Fatal(e)
	}
	p := serveDNSProxy(context.Background(), u, failedDNSListener{}, "127.0.0.1:1", time.Second, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer p.Close()
	select {
	case e := <-p.errors:
		if e == nil {
			t.Fatal("empty terminal error")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failure was not reported")
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed proxy retained workers")
	}
	if len(p.slots) != 0 {
		t.Fatal("failed proxy retained slots")
	}
}

func TestDNSProxyBudgetTimeoutAndRecovery(t *testing.T) {
	upstream, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	p := serveDNSProxy(context.Background(), u, l, upstream.LocalAddr().String(), 300*time.Millisecond, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer p.Close()
	client, err := net.Dial("udp", u.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	buf := make([]byte, 64)
	for i := 0; i < 2; i++ {
		if _, err := client.Write([]byte("query")); err != nil {
			t.Fatal(err)
		}
		upstream.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := upstream.ReadFromUDP(buf); err != nil {
			t.Fatal(err)
		}
	}
	// The same budget applies to TCP, which must be closed before dialing upstream.
	tcp, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tcp.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := tcp.Read(buf); n != 0 || err == nil {
		t.Fatalf("overloaded TCP remains open: %d %v", n, err)
	}
	tcp.Close()
	if _, err := client.Write([]byte("overload")); err != nil {
		t.Fatal(err)
	}
	upstream.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := upstream.ReadFromUDP(buf); err == nil {
		t.Fatal("overloaded UDP reached upstream")
	}
	deadline := time.Now().Add(time.Second)
	for len(p.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(p.slots) != 0 {
		t.Fatal("silent upstream retained request slots")
	}
	client.Write([]byte("recovered"))
	upstream.SetReadDeadline(time.Now().Add(time.Second))
	n, addr, err := upstream.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := upstream.WriteToUDP(buf[:n], addr); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	n, err = client.Read(buf)
	if err != nil || string(buf[:n]) != "recovered" {
		t.Fatalf("proxy did not recover: %q %v", buf[:n], err)
	}
}

func TestDNSProxyCancellationJoinsTCP(t *testing.T) {
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		u.Close()
		t.Fatal(err)
	}
	p := serveDNSProxy(context.Background(), u, l, upstream.Addr().String(), time.Hour, 2, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer p.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	silent, err := upstream.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation retained TCP copies")
	}
	if len(p.slots) != 0 {
		t.Fatal("cancellation retained request budget")
	}
}

type jumpFixture struct{ rules [][]string }

func (f *jumpFixture) Exists(table, chain string, spec ...string) (bool, error) {
	for _, r := range f.rules {
		if len(r) == 2 && r[0] == spec[0] && r[1] == spec[1] {
			return true, nil
		}
	}
	return false, nil
}
func (f *jumpFixture) Delete(table, chain string, spec ...string) error {
	for i, r := range f.rules {
		if len(r) == 2 && r[0] == spec[0] && r[1] == spec[1] {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			break
		}
	}
	return nil
}
func (f *jumpFixture) Insert(table, chain string, pos int, spec ...string) error {
	f.rules = append([][]string{spec}, f.rules...)
	return nil
}
func TestInputJumpMovedBeforeHistoricalAccept(t *testing.T) {
	f := &jumpFixture{rules: [][]string{{"-j", "ACCEPT"}, {"-j", "COZYPLANE-INPUT"}, {"-j", "COZYPLANE-INPUT"}}}
	if err := inputJumpFirst(f, "COZYPLANE-INPUT"); err != nil {
		t.Fatal(err)
	}
	assertRules(t, f.rules, []string{"-j COZYPLANE-INPUT", "-j ACCEPT"})
	if err := inputJumpFirst(f, "COZYPLANE-INPUT"); err != nil {
		t.Fatal(err)
	}
	assertRules(t, f.rules, []string{"-j COZYPLANE-INPUT", "-j ACCEPT"})
}
