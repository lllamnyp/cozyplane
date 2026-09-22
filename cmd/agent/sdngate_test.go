/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

type proberFunc func(context.Context) (bool, error)

func (f proberFunc) Served(ctx context.Context) (bool, error) { return f(ctx) }

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// withPollInterval shortens the gate's poll interval for the duration of a test
// so the loop can be observed without waiting on the production interval.
func withPollInterval(t *testing.T, d time.Duration) {
	t.Helper()
	prev := sdnGatePollInterval
	sdnGatePollInterval = d
	t.Cleanup(func() { sdnGatePollInterval = prev })
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSDNGateDoesNotBlockStartup is the pod-ADD independence assertion.
//
// Agent startup installs the CNI configuration — the act that admits pod ADDs —
// after this gate is set up. Nothing about pod ADD may therefore wait on the
// sdn.cozystack.io informers: not on the group existing, not on their caches
// syncing. The plugin itself is a separate process (cmd/cni) that talks to the
// API directly and holds no informer, so the only way a dependency could creep
// in is here, by the agent blocking before it writes that configuration.
//
// With a group that is never served, startSDNGate must still hand control back
// at once and must not have registered anything.
func TestSDNGateDoesNotBlockStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var registered atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		startSDNGate(ctx, proberFunc(func(context.Context) (bool, error) {
			return false, nil // the bootstrap window: apiserver not up yet
		}), func(context.Context) error {
			registered.Add(1)
			return nil
		}, quietLogger())
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("startSDNGate blocked while the sdn group was absent; pod ADD admission must never wait on it")
	}

	// Give the gate's first poll room to happen; it still must not register.
	time.Sleep(50 * time.Millisecond)
	if n := registered.Load(); n != 0 {
		t.Fatalf("registered the sdn informers %d time(s) while the group was absent; want 0", n)
	}
}

// TestSDNGateRegistersOnceWhenServed covers the other half: once the group
// answers, the informers start, and they start exactly once however many times
// the gate polls afterwards ("controller was started more than once" is fatal).
func TestSDNGateRegistersOnceWhenServed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	withPollInterval(t, time.Millisecond)

	var polls, registered atomic.Int32
	startSDNGate(ctx, proberFunc(func(context.Context) (bool, error) {
		polls.Add(1)
		return true, nil
	}), func(context.Context) error {
		registered.Add(1)
		return nil
	}, quietLogger())

	// The gate keeps polling after it registers; those later polls must not
	// register a second time.
	waitFor(t, "the gate to poll repeatedly", func() bool { return polls.Load() >= 5 })

	if n := registered.Load(); n != 1 {
		t.Fatalf("registered %d times over %d polls, want exactly 1", n, polls.Load())
	}
}

// TestSDNGateProbeErrorIsNotFatal: a transport error or a proxied 503 from the
// aggregated apiserver means "not served right now", not "give up". The agent's
// datapath stays up through it and the gate keeps polling.
func TestSDNGateProbeErrorIsNotFatal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	withPollInterval(t, time.Millisecond)

	var polls atomic.Int32
	startSDNGate(ctx, proberFunc(func(context.Context) (bool, error) {
		polls.Add(1)
		return false, context.DeadlineExceeded
	}), func(context.Context) error {
		t.Error("must not register the sdn informers when the probe failed")
		return nil
	}, quietLogger())

	// It must keep retrying rather than give up after the first failure.
	waitFor(t, "the gate to keep probing after an error", func() bool { return polls.Load() >= 3 })
}
