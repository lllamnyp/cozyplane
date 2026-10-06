package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundaryWorkerCoalescesWhileAcknowledgementBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	work := make(boundarySyncNotifications, 1)
	started, release, completed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	go func() {
		defer close(completed)
		runBoundarySyncWorker(ctx, work, func(ctx context.Context) {
			if calls.Add(1) == 1 {
				close(started)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
		})
	}()
	work.notify()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	for i := 0; i < 100000; i++ {
		work.notify()
	}
	if len(work) != 1 {
		t.Fatalf("queued %d notifications", len(work))
	}
	close(release)
	deadline := time.After(time.Second)
	for calls.Load() < 2 {
		select {
		case <-deadline:
			t.Fatal("latest state was not reconciled")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	select {
	case <-completed:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
	if calls.Load() != 2 {
		t.Fatalf("processed %d full synchronizations, want 2", calls.Load())
	}
}

func TestBoundaryWorkerAcknowledgementContextIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	work := make(boundarySyncNotifications, 1)
	seen := make(chan context.Context, 1)
	go runBoundarySyncWorker(ctx, work, func(ctx context.Context) { seen <- ctx })
	work.notify()
	select {
	case request := <-seen:
		deadline, ok := request.Deadline()
		if !ok || time.Until(deadline) > 15*time.Second {
			t.Fatal("unbounded acknowledgement request")
		}
		select {
		case <-request.Done():
		case <-time.After(time.Second):
			t.Fatal("completed synchronization retained its request context")
		}
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
}
