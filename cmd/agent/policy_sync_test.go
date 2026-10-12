package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"k8s.io/client-go/tools/cache"
)

func TestPolicyResyncPreservesEnforcementUntilEveryInitialListCompletes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var ready [3]atomic.Bool
	var writes atomic.Int32
	applied := make(chan struct{}, 10)
	pinnedDeny := atomic.Bool{}
	pinnedDeny.Store(true)
	inputs := []cache.InformerSynced{ready[0].Load, ready[1].Load, ready[2].Load}
	resync := resyncAfterCacheSync(ctx, func() {
		writes.Add(1)
		pinnedDeny.Store(false)
		applied <- struct{}{}
	}, inputs...)
	for i := range ready {
		// Each notification precedes completion of this informer's list.
		resync()
		if writes.Load() != 0 || !pinnedDeny.Load() {
			t.Fatal("incomplete snapshot changed pinned enforcement")
		}
		ready[i].Store(true)
	}
	// No further notification: the cache-ready replay must apply the snapshot.
	select {
	case <-applied:
	case <-time.After(3 * time.Second):
		t.Fatal("complete snapshot was not replayed")
	}
	resync()
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("ready update was not applied")
	}
	if writes.Load() != 2 {
		t.Fatalf("ready update lost: %d writes", writes.Load())
	}
	cancel()
	resync()
	if writes.Load() != 2 {
		t.Fatal("cancelled compiler changed enforcement")
	}
}
