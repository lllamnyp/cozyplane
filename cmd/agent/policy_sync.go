package main

import (
	"context"
	"time"

	"k8s.io/client-go/tools/cache"
)

const revocationRetryPeriod = 15 * time.Second

// resyncAfterCacheSync preserves pinned policy while any initial list is
// incomplete. Replay once ready: the final initial notification can arrive
// before HasSynced changes, so event handlers alone do not guarantee a replay.
func resyncAfterCacheSync(ctx context.Context, apply func(), synced ...cache.InformerSynced) func() {
	return periodicResyncAfterCacheSync(ctx, 0, apply, synced...)
}

// A worker-owned retry tick works even when the SDK factory disables resync.
// It shares the same single pending pass as ordinary cache notifications.
func periodicResyncAfterCacheSync(ctx context.Context, period time.Duration, apply func(), synced ...cache.InformerSynced) func() {
	pending := make(chan struct{}, 1)
	resync := func() {
		if ctx.Err() != nil {
			return
		}
		for _, ready := range synced {
			if !ready() {
				return
			}
		}
		select {
		case pending <- struct{}{}:
		default:
		}
	}
	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), synced...) || ctx.Err() != nil {
			return
		}
		var retry <-chan time.Time
		if period > 0 {
			tick := time.NewTicker(period)
			defer tick.Stop()
			retry = tick.C
		}
		apply()
		for {
			select {
			case <-ctx.Done():
				return
			case <-pending:
			case <-retry:
			}
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			// Fold notifications received during the fixed wait into this pass.
			select {
			case <-pending:
			default:
			}
			select {
			case <-retry:
			default:
			}
			if ctx.Err() != nil {
				return
			}
			apply()
		}
	}()
	return resync
}
