package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPolicyNotificationBurstDoesNotBlockHandlersOrRetainEveryCompile(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var mu sync.Mutex
	var passes atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	applied := make(chan struct{}, 8)
	resync := resyncAfterCacheSync(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if passes.Add(1) == 1 {
			close(entered)
			<-release
		}
		applied <- struct{}{}
	}, func() bool { return true })
	select {
	case <-entered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("initial pass not started")
	}
	triggered := make(chan struct{})
	go func() {
		defer close(triggered)
		for range 10000 {
			resync()
		}
	}()
	defer func() { cancel(); releaseOnce.Do(func() { close(release) }); <-triggered }()
	select {
	case <-triggered:
	case <-time.After(100 * time.Millisecond):
		t.Error("informer handler blocked on full compilation")
	}
	if n := passes.Load(); n != 1 {
		t.Fatal("burst executed while first snapshot in progress", n)
	}
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		select {
		case <-applied:
		case <-time.After(time.Second):
			t.Fatal("update during compile was lost")
		}
	}
	if n := passes.Load(); n != 2 {
		t.Fatal("burst was not coalesced to one extra snapshot", n)
	}
}
