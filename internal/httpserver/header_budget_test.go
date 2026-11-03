package httpserver

import (
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func headerBudgetServer(tb testing.TB) (string, *http.Client, *atomic.Int64) {
	tb.Helper()
	var calls atomic.Int64
	srv := New("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	transport := &http.Transport{DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	tb.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = srv.Close()
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				tb.Error(err)
			}
		case <-time.After(time.Second):
			tb.Error("HTTP server did not stop")
		}
	})
	return "http://" + listener.Addr().String() + "/metrics", client, &calls
}

func headerBudgetRequest(tb testing.TB, client *http.Client, url, value string) int {
	tb.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		tb.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+value)
	response, err := client.Do(req)
	if err != nil {
		tb.Fatal(err)
	}
	defer response.Body.Close()
	// Go writes431 then closes with unread oversized input; the close can reset
	// a body read. The parsed431 and zero handler calls are the rejection proof.
	if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		if _, err := io.Copy(io.Discard, response.Body); err != nil {
			tb.Fatal(err)
		}
	}
	return response.StatusCode
}

func TestAuxiliaryHeaderBudgetRejectsBeforeHandlerAndRecovers(t *testing.T) {
	url, client, calls := headerBudgetServer(t)
	if got := headerBudgetRequest(t, client, url, strings.Repeat("a", 128<<10)); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("128KiB request header status=%d; want431", got)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("oversized header reached handler%d times", got)
	}
	if got := headerBudgetRequest(t, client, url, strings.Repeat("a", 16<<10)); got != http.StatusNoContent {
		t.Fatalf("valid16KiB bearer header rejected: %d", got)
	}
	if got := headerBudgetRequest(t, client, url, "token"); got != http.StatusNoContent {
		t.Fatalf("normal request did not recover: %d", got)
	}
}

func BenchmarkAuxiliaryHeaderBudget(b *testing.B) {
	url, client, _ := headerBudgetServer(b)
	value := strings.Repeat("a", 128<<10)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = headerBudgetRequest(b, client, url, value)
	}
}
