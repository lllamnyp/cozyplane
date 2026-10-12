package main

import (
	"context"
	"fmt"
	"github.com/lllamnyp/cozyplane/internal/httpserver"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFlowStreamAdmissionAndCanceledSlotRelease(t *testing.T) {
	fp := &flowPipeline{subs: map[chan flowRecord]struct{}{}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var handlers sync.WaitGroup
	for range 32 {
		handlers.Go(func() {
			fp.handleStream(httptest.NewRecorder(), httptest.NewRequest("GET", "/flows/stream", nil).WithContext(ctx))
		})
	}
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
waiting:
	for {
		fp.mu.Lock()
		n := len(fp.subs)
		fp.mu.Unlock()
		if n == 32 {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("streams not admitted")
		case <-tick.C:
			continue waiting
		}
	}
	extraCtx, extraCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer extraCancel()
	response := httptest.NewRecorder()
	fp.handleStream(response, httptest.NewRequest("GET", "/flows/stream", nil).WithContext(extraCtx))
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("excess stream retained a worker: HTTP %d", response.Code)
	}
	cancel()
	handlers.Wait()
	fp.mu.Lock()
	n := len(fp.subs)
	fp.mu.Unlock()
	if n != 0 {
		t.Fatal("canceled streams leaked subscribers", n)
	}
	resume, resumeCancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer resumeCancel()
	response = httptest.NewRecorder()
	fp.handleStream(response, httptest.NewRequest("GET", "/flows/stream", nil).WithContext(resume))
	if response.Code == http.StatusServiceUnavailable {
		t.Fatal("canceled stream did not release admission slot")
	}
}

type smallSendBufferListener struct{ net.Listener }

func (l smallSendBufferListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetWriteBuffer(1024); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func TestFlowStreamBlockedTCPReaderReleasesSubscriber(t *testing.T) {
	fp := &flowPipeline{subs: map[chan flowRecord]struct{}{}}
	done := make(chan struct{})
	srv := httpserver.New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fp.handleStream(w, r); close(done) }))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	// Tune the raw TCP socket before the admission listener wraps it.
	go srv.Serve(smallSendBufferListener{listener})
	defer srv.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if tcp, ok := conn.(*net.TCPConn); ok {
		if err := tcp.SetReadBuffer(1024); err != nil {
			t.Fatal(err)
		}
	}
	_, err = fmt.Fprint(conn, "GET /flows/stream HTTP/1.1\r\nHost: localhost\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	var subscriber chan flowRecord
	deadline := time.Now().Add(time.Second)
	for subscriber == nil {
		fp.mu.Lock()
		for ch := range fp.subs {
			subscriber = ch
		}
		fp.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("stream not admitted")
		}
		if subscriber == nil {
			time.Sleep(time.Millisecond)
		}
	}
	start := time.Now()
	record := flowRecord{Time: time.Now(), Verdict: "allow", Reason: strings.Repeat("r", 64), Node: strings.Repeat("n", 63), Proto: "tcp", Direction: "ingress"}
	for range flowSubBuffer {
		subscriber <- record
	}
	// Do not read any response bytes. Kernel receive/send buffers are small
	// enough to exercise the real per-message write deadline.
	select {
	case <-done:
	case <-time.After(13 * time.Second):
		t.Fatal("blocked reader retained stream beyond write budget")
	}
	if time.Since(start) < 8*time.Second {
		t.Fatal("stream stopped before exercising ten-second write deadline")
	}
	fp.mu.Lock()
	n := len(fp.subs)
	fp.mu.Unlock()
	if n != 0 {
		t.Fatal("blocked reader leaked subscriber", n)
	}
}
