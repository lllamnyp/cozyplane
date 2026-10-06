package main

import (
	"context"
	"time"
)

// Notifications carry no objects; the worker always reads current informer state.
type boundarySyncNotifications chan struct{}

func (n boundarySyncNotifications) notify() {
	select {
	case n <- struct{}{}:
	default:
	}
}

func runBoundarySyncWorker(ctx context.Context, notifications boundarySyncNotifications, sync func(context.Context)) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-notifications:
		case <-ticker.C:
		}
		if ctx.Err() != nil {
			return
		}
		request, cancel := context.WithTimeout(ctx, 15*time.Second)
		sync(request)
		cancel()
	}
}
