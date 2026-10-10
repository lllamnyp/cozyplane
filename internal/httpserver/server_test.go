package httpserver

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSlowGETBodyConnectionReaped(t *testing.T) {
	closed := make(chan struct{}, 1)
	srv := New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("metrics\n")) }))
	srv.ReadTimeout /= 100
	srv.ReadHeaderTimeout = 50 * time.Millisecond
	srv.WriteTimeout = 100 * time.Millisecond
	srv.IdleTimeout = 50 * time.Millisecond
	srv.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateClosed {
			select {
			case closed <- struct{}{}:
			default:
			}
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go srv.Serve(listener)
	defer srv.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("slow GET body kept server connection alive beyond request budget")
	}
}

func TestResponseStreamOutlivesRequestReadBudget(t *testing.T) {
	srv := New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		for i := 0; i < 8; i++ {
			if err := rc.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
				return
			}
			if _, err := fmt.Fprintf(w, "event %d\n", i); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}))
	srv.ReadTimeout = 30 * time.Millisecond
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go srv.Serve(listener)
	defer srv.Close()
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get("http://" + listener.Addr().String() + "/flows/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	scanner := bufio.NewScanner(resp.Body)
	count := 0
	for scanner.Scan() {
		count++
	}
	if scanner.Err() != nil || count != 8 {
		t.Fatal("read budget interrupted response stream", count, scanner.Err())
	}
}
