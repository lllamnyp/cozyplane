package main

import (
	"context"
	"errors"
	"testing"
)

func TestGuestAnnouncementReleasesCompletedContexts(t *testing.T) {
	parent, stop := context.WithCancel(context.Background())
	defer stop()
	for _, failure := range []error{nil, errors.New("socket failed")} {
		for i := 0; i < 100; i++ {
			ctx, cancel := context.WithCancel(parent)
			listener := &guestAnnouncementListener{ctx: ctx, cancel: cancel}
			if got := listener.run(func(context.Context) error { return failure }); got != failure {
				t.Fatalf("watch: %v", got)
			}
			if ctx.Err() != context.Canceled {
				t.Fatalf("completed listener retained its child context at cycle %d", i)
			}
			if parent.Err() != nil {
				t.Fatal("listener canceled the shared parent")
			}
		}
	}
}

func TestGuestAnnouncementReplacedListenerCannotClaim(t *testing.T) {
	oldCtx, oldCancel := context.WithCancel(context.Background())
	newCtx, newCancel := context.WithCancel(context.Background())
	defer oldCancel()
	defer newCancel()
	old := &guestAnnouncementListener{ctx: oldCtx, cancel: oldCancel}
	replacement := &guestAnnouncementListener{ctx: newCtx, cancel: newCancel}
	running := map[string]*guestAnnouncementListener{"private-port": replacement}
	if old.finish(running, "private-port", nil) {
		t.Fatal("obsolete listener can claim the Port")
	}
	if running["private-port"] != replacement {
		t.Fatal("obsolete listener removed its replacement")
	}
	if !replacement.finish(running, "private-port", nil) {
		t.Fatal("current matching listener cannot claim")
	}
	if len(running) != 0 {
		t.Fatal("finished listener registration retained")
	}
}

func TestGuestAnnouncementCanceledMatchCannotClaim(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	listener := &guestAnnouncementListener{ctx: ctx, cancel: cancel}
	err := listener.run(func(context.Context) error { cancel(); return nil })
	running := map[string]*guestAnnouncementListener{"private-port": listener}
	if listener.finish(running, "private-port", err) {
		t.Fatal("canceled listener can claim the Port")
	}
}
