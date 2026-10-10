package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func localFlowTestTransport(t *testing.T, server *httptest.Server) *http.Transport {
	t.Helper()
	transport := flowLocalTransport()
	if transport.Proxy != nil {
		t.Fatal("loopback transport must ignore environment proxies")
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "127.0.0.1:9412" {
			t.Errorf("dial escaped loopback: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(transport.CloseIdleConnections)
	return transport
}

func TestFetchLocalFlowsSnapshotAndRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "127.0.0.1:9412" || r.URL.Path != "/flows" {
			t.Errorf("unexpected destination: %s %s", r.Host, r.URL)
		}
		if r.URL.Query().Get("verdict") == "deny" {
			http.Redirect(w, r, "http://external.invalid/secret", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "[]")
	}))
	defer server.Close()
	transport := localFlowTestTransport(t, server)
	var out bytes.Buffer
	if err := fetchLocalFlows(context.Background(), "/flows?verdict=allow", &out, transport); err != nil || out.String() != "[]" {
		t.Fatalf("snapshot: %q, %v", out.String(), err)
	}
	out.Reset()
	if err := fetchLocalFlows(context.Background(), "/flows?verdict=deny", &out, transport); err == nil || out.Len() != 0 {
		t.Fatalf("redirect must fail without copying or following: %q, %v", out.String(), err)
	}
}

func TestFetchLocalFlowsRejectsTargetsBeforeDial(t *testing.T) {
	for _, target := range []string{"http://external.invalid/flows", "//external.invalid/flows", "/metrics", "/%66lows", "/flows#fragment", "/flows?x=" + strings.Repeat("x", 16<<10)} {
		if err := fetchLocalFlows(context.Background(), target, io.Discard, nil); err == nil {
			t.Errorf("accepted %q", target)
		}
	}
}

func TestFetchLocalFlowsSnapshotBound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", maxFlowSnapshotBytes+2)), maxFlowSnapshotBytes+2)
	}))
	defer server.Close()
	if err := fetchLocalFlows(context.Background(), "/flows", io.Discard, localFlowTestTransport(t, server)); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
}

func TestFetchLocalFlowsStreamCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "{}\n")
		w.(http.Flusher).Flush()
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	transport := localFlowTestTransport(t, server)
	go func() { done <- fetchLocalFlows(ctx, "/flows/stream", io.Discard, transport) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("stream did not stop")
	}
}
