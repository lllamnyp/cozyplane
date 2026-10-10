package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

func TestIPsecPoolNameBudgetBeforeVICIAndKernel(t *testing.T) {
	bad := "input-canary-" + strings.Repeat("a", 128<<10)
	sess := &recordingVICI{}
	p := peer{Name: "peer", RemoteID: "peer.example.invalid", PSK: "test-key", AddressPool: bad}
	for _, err := range []error{loadAddressPool(sess, addressPool{Name: bad, CIDR: "192.0.2.0/24"}), loadPeer(sess, p)} {
		if err == nil || len(err.Error()) > 128 || strings.Contains(err.Error(), "input-canary") {
			t.Fatal("unbounded or absent pool name rejection", err)
		}
	}
	if len(sess.commands) != 0 {
		t.Fatal("oversized name reached VICI")
	}
	requireStartupCleanupCapability(t)
	for _, cfg := range []config{{Pools: []addressPool{{Name: bad, CIDR: "192.0.2.0/24"}}}, {Peers: []peer{p}}} {
		raw, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := run(path, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil || !strings.Contains(err.Error(), "255 bytes") {
			t.Fatal("mounted invalid pool name reached kernel startup", err)
		}
	}
}

// The real govici encoder is exercised through an in-memory wire, rather than
// relying on recordingVICI, which intentionally does not encode messages.
func TestIPsecPoolNameFitsActualVICIWire(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	sess, err := vici.NewSession(vici.WithDialContext(func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }))
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	defer sess.Close()
	want := strings.Repeat("a", 255)
	done := make(chan error, 1)
	release := make(chan struct{})
	go func() {
		defer serverConn.Close()
		var header [4]byte
		if _, err := io.ReadFull(serverConn, header[:]); err != nil {
			done <- err
			return
		}
		size := binary.BigEndian.Uint32(header[:])
		if size > 1024 {
			done <- fmt.Errorf("unexpected %d-byte wire packet", size)
			return
		}
		packet := make([]byte, size)
		if _, err := io.ReadFull(serverConn, packet); err != nil {
			done <- err
			return
		}
		const offset = 2 + len("load-pool")
		if len(packet) < offset+2+255 || packet[0] != 0 || packet[1] != byte(len("load-pool")) || string(packet[2:offset]) != "load-pool" || packet[offset] != 1 || packet[offset+1] != 255 || string(packet[offset+2:offset+2+255]) != want {
			done <- fmt.Errorf("pool section was not encoded with its exact 255-byte name")
			return
		}
		_, err := serverConn.Write([]byte{0, 0, 0, 15, 1, 3, 7, 's', 'u', 'c', 'c', 'e', 's', 's', 0, 3, 'y', 'e', 's'}) // CMD_RESPONSE success=yes
		if err == nil {
			// A real daemon keeps the transport open after replying. Closing
			// here would race queued response delivery against an unrelated EOF.
			<-release
		}
		done <- err
	}()
	loadErr := loadAddressPool(sess, addressPool{Name: want, CIDR: "192.0.2.0/24"})
	close(release)
	sess.Close()
	serverConn.Close()
	if wireErr := <-done; wireErr != nil {
		t.Fatal(wireErr)
	}
	if loadErr != nil {
		t.Fatal(loadErr)
	}
}

func TestActualVICIRejectsOversizedPoolSection(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	sess, err := vici.NewSession(vici.WithDialContext(func(context.Context, string, string) (net.Conn, error) { return clientConn, nil }))
	if err != nil {
		clientConn.Close()
		t.Fatal(err)
	}
	defer sess.Close()
	req := vici.NewMessage()
	entry := vici.NewMessage()
	if err := entry.Set("addrs", "192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := req.Set(strings.Repeat("a", 256), entry); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := sess.Call(ctx, "load-pool", req); err == nil || !strings.Contains(err.Error(), "256 > 255") {
		t.Fatal("actual encoder did not enforce the one-byte section length", err)
	}
}
