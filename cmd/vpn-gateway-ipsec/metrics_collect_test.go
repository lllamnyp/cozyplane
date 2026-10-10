package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

func TestIPsecStalledVICICancelAndAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.vici")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	closed := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		_, _ = io.Copy(io.Discard, conn) // VICI daemon accepts but never answers.
		close(closed)
	}()
	c := &ipsecCollector{slot: make(chan struct{}, 1), open: func(ctx context.Context) (ipsecStream, error) { return openMetricsVICI(ctx, path) }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := c.collect(ctx, nil); done <- err }()
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("VICI was not connected")
	}
	for i := 0; i < 1000; i++ {
		if _, _, err := c.collect(context.Background(), nil); !errors.Is(err, errIPsecCollectionBusy) {
			t.Fatal("concurrent request queued", err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancel not propagated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("collector did not stop")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("VICI socket leaked after cancel")
	}
	if len(c.slot) != 0 {
		t.Fatal("admission slot leaked")
	}
}

func TestVICIFrameRejectedBeforeLengthReachesDecoder(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, maxVICIFrame+1)
		_, _ = server.Write(header)
	}()
	conn := &boundedVICIConn{Conn: client}
	header := make([]byte, 4)
	if n, err := io.ReadFull(conn, header); err == nil || n != 0 {
		t.Fatal("oversized length reached allocating decoder", n, err)
	}
	<-done
}

type metricStream struct {
	events int
	closed atomic.Bool
}

func (s *metricStream) Close() error { s.closed.Store(true); return nil }
func (s *metricStream) CallStreaming(ctx context.Context, _, _ string, _ *vici.Message) iter.Seq2[*vici.Message, error] {
	return func(yield func(*vici.Message, error) bool) {
		for i := 0; i < s.events; i++ {
			if !yield(vici.NewMessage(), nil) {
				return
			}
		}
	}
}

func TestIPsecEventBudgetAndRecovery(t *testing.T) {
	s := &metricStream{events: maxIPsecEvents + 1}
	c := &ipsecCollector{slot: make(chan struct{}, 1), open: func(context.Context) (ipsecStream, error) { return s, nil }}
	if _, _, err := c.collect(context.Background(), nil); err == nil {
		t.Fatal("oversized stream accepted")
	}
	if !s.closed.Load() || len(c.slot) != 0 {
		t.Fatal("oversized collection leaked")
	}
	s = &metricStream{events: 1}
	if _, _, err := c.collect(context.Background(), []peer{{Name: "peer-a"}}); err != nil {
		t.Fatal("bounded collection did not recover", err)
	}
	if !s.closed.Load() {
		t.Fatal("completed session leaked")
	}
}

func TestVICICollectionCumulativeByteBudget(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, maxVICIFrame)
		payload := make([]byte, maxVICIFrame)
		for i := 0; i < 9; i++ {
			if _, err := server.Write(header); err != nil {
				return
			}
			if _, err := server.Write(payload); err != nil {
				return
			}
		}
	}()
	conn := &boundedVICIConn{Conn: client}
	n, err := io.Copy(io.Discard, conn)
	if err == nil || n > maxVICICollection {
		t.Fatal("cumulative byte budget exceeded", n, err)
	}
	_ = client.Close()
	<-done
}
