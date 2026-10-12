package main

import (
	"context"
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

type migrationInstallFake struct{ installs atomic.Int32 }

func (m *migrationInstallFake) InstallMigrateFwd(uint32, net.IP, net.IP) (func() error, error) {
	m.installs.Add(1)
	return func() error { return nil }, nil
}

func TestMigrationBurstDoesNotSchedulePerEventGoroutines(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	m := &migrationInstallFake{}
	before := runtime.NumGoroutine()
	for range 2000 {
		if err := installMigrationForward(ctx, m, 100, net.ParseIP("10.0.0.2"), net.ParseIP("192.0.2.1")); err != nil {
			t.Fatal(err)
		}
	}
	after := runtime.NumGoroutine()
	cancel()
	// Drain any baseline scheduler workers before returning from the test.
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if m.installs.Load() != 2000 {
		t.Fatal("burst test lost forwarding installations")
	}
	if after > before+4 {
		t.Fatalf("2000 moves of one address retained %d additional goroutines", after-before)
	}
}

func TestCanceledMigrationDoesNotInstallForward(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	m := &migrationInstallFake{}
	if err := installMigrationForward(ctx, m, 100, net.ParseIP("10.0.0.2"), net.ParseIP("192.0.2.1")); err != context.Canceled || m.installs.Load() != 0 {
		t.Fatal("canceled event installed a forward", err, m.installs.Load())
	}
}
