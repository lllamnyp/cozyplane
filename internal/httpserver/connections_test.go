package httpserver

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func TestAuxiliaryServerBoundsConnectionsAndRecovers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := New("", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	server.ReadTimeout, server.ReadHeaderTimeout = time.Minute, time.Minute
	accepted := make(chan net.Conn, 256)
	server.ConnState = func(conn net.Conn, state http.ConnState) {
		if state == http.StateNew {
			accepted <- conn
		}
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Serve(listener) }()
	defer server.Close()
	var clients []net.Conn
	defer func() {
		for _, conn := range clients {
			_ = conn.Close()
		}
	}()
	for range 128 {
		conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, conn)
		select {
		case <-accepted:
		case <-time.After(time.Second):
			t.Fatal("budgeted connection not admitted")
		}
	}
	excess, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clients = append(clients, excess)
	select {
	case conn := <-accepted:
		conn.Close()
		t.Error("excess connection allocated an HTTP worker")
	case <-time.After(100 * time.Millisecond):
	}
	_ = clients[0].Close()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("connection budget did not recover after close")
	}
	// Close must interrupt an Accept waiting on the exhausted admission budget.
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-stopped:
		if err != http.ErrServerClosed {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("server Close leaked the waiting listener")
	}
}
