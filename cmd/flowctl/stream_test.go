package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestFlowStreamScannerFailureJoinsBlockedProducer(t *testing.T) {
	finished := make(chan struct{})
	writer := make(chan io.Closer, 1)
	err := readFlowStream(t.Context(), make(chan flowRecord), func(_ context.Context, w io.Writer) error {
		defer close(finished)
		writer <- w.(io.Closer)
		_, err := io.WriteString(w, strings.Repeat("a", (1<<20)+1))
		return err
	})
	// Clean up the reproduction even when the old scanner path leaked the exec.
	closer := <-writer
	defer func() {
		closer.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("producer did not stop after fixture cleanup")
		}
	}()
	if !errors.Is(err, bufio.ErrTooLong) {
		t.Fatal("oversized stream record was not rejected", err)
	}
	select {
	case <-finished:
	default:
		t.Fatal("scanner returned while producer retained an unread pipe")
	}
}

func TestFlowStreamCancellationJoinsProducer(t *testing.T) {
	for _, blockedOutput := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		finished := make(chan struct{})
		result := make(chan error, 1)
		out := make(chan flowRecord, 1)
		go func() {
			result <- readFlowStream(ctx, out, func(ctx context.Context, w io.Writer) error {
				defer close(finished)
				if blockedOutput {
					_, err := io.WriteString(w, "{\"node\":\"node-a\"}\n")
					if err == nil {
						_, err = io.WriteString(w, "{\"node\":\"node-b\"}\n")
					}
					close(started)
					if err == nil {
						_, err = io.WriteString(w, "{\"node\":\"node-c\"}\n")
					}
					return err
				}
				close(started)
				<-ctx.Done()
				return ctx.Err()
			})
		}()
		<-started
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation not propagated", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("stream cancellation retained worker")
		}
		select {
		case <-finished:
		default:
			t.Fatal("stream returned before producer stopped")
		}
		if blockedOutput && len(out) != 1 {
			t.Fatal("fixture did not establish output backpressure")
		}
	}
}

func TestFlowStreamValidRecoveryAndProducerError(t *testing.T) {
	out := make(chan flowRecord, 2)
	finished := false
	err := readFlowStream(t.Context(), out, func(_ context.Context, w io.Writer) error {
		defer func() { finished = true }()
		_, err := io.WriteString(w, "invalid-json\n{\"node\":\"node-a\"}\n{\"node\":\"node-b\"}")
		return err
	})
	if err != nil || !finished || len(out) != 2 || (<-out).Node != "node-a" || (<-out).Node != "node-b" {
		t.Fatal("valid records/recovery or producer join lost", err)
	}
	want := errors.New("producer stopped")
	if err := readFlowStream(t.Context(), out, func(context.Context, io.Writer) error { return want }); !errors.Is(err, want) {
		t.Fatal("producer failure lost", err)
	}
}
