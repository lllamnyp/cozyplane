package main

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPeriodicReconcileWaitsForCacheAndRetriesWithoutNotifications(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var ready atomic.Bool
	var passes atomic.Int32
	applied := make(chan struct{}, 8)
	notify := periodicResyncAfterCacheSync(ctx, 20*time.Millisecond, func() { passes.Add(1); applied <- struct{}{} }, ready.Load)
	notify()
	select {
	case <-applied:
		t.Fatal("incomplete cache was applied")
	case <-time.After(60 * time.Millisecond):
	}
	ready.Store(true)
	for range 2 {
		select {
		case <-applied:
		case <-time.After(time.Second):
			t.Fatal("ready cache was not retried without a notification")
		}
	}
	cancel()
	time.Sleep(150 * time.Millisecond) // Longer than the fixed coalescing wait.
	before := passes.Load()
	for range 10000 {
		notify()
	}
	time.Sleep(150 * time.Millisecond)
	if after := passes.Load(); after != before {
		t.Fatal("canceled retry worker still applied snapshots", before, after)
	}
}

func TestPeriodicReconcileCoalescesTicksAndBurstDuringBlockedPass(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var passes, active, peak atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	applied := make(chan struct{}, 8)
	notify := periodicResyncAfterCacheSync(ctx, 10*time.Millisecond, func() {
		n := active.Add(1)
		defer active.Add(-1)
		if n > peak.Load() {
			peak.Store(n)
		}
		if passes.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return
			}
		}
		select {
		case applied <- struct{}{}:
		case <-ctx.Done():
		}
	}, func() bool { return true })
	t.Cleanup(func() { cancel(); once.Do(func() { close(release) }) })
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial pass did not start")
	}
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		for range 10000 {
			notify()
		}
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("notifications blocked on active work")
	}
	time.Sleep(50 * time.Millisecond) // Several ticks while the same pass is held.
	if passes.Load() != 1 || peak.Load() != 1 {
		t.Fatal("retry ticks multiplied active work", passes.Load(), peak.Load())
	}
	once.Do(func() { close(release) })
	for range 2 {
		select {
		case <-applied:
		case <-time.After(time.Second):
			t.Fatal("coalesced replay was lost")
		}
	}
	cancel()
	if n := passes.Load(); n != 2 || peak.Load() != 1 {
		t.Fatal("burst retained more than one pending replay", n, peak.Load())
	}
}

func TestPeriodicReconcileCancellationDoesNotRetainWorkers(t *testing.T) {
	before := runtime.NumGoroutine()
	for range 100 {
		ctx, cancel := context.WithCancel(t.Context())
		applied := make(chan struct{}, 1)
		periodicResyncAfterCacheSync(ctx, time.Second, func() { applied <- struct{}{} }, func() bool { return true })
		select {
		case <-applied:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("initial retry worker did not start")
		}
		cancel()
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatal("canceled retry workers retained goroutines", before, after)
	}
}
