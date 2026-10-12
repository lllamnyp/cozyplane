package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestIPsecChildHelper(t *testing.T) {
	switch os.Getenv("COZYPLANE_PROCESS_TEST") {
	case "exit":
		os.Exit(42)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
}

func childArgs(t *testing.T, mode string) []string {
	t.Helper()
	t.Setenv("COZYPLANE_PROCESS_TEST", mode)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{binary, "-test.run=^TestIPsecChildHelper$"}
}

func TestCharonDeathCancelsBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := superviseCharon(ctx, childArgs(t, "exit"), func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }, func(context.Context) { t.Error("metrics started before bootstrap") })
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatal("daemon death did not abort bootstrap", err)
	}
}

func TestCharonInitializationFailureReapsChild(t *testing.T) {
	want := errors.New("invalid tunnel configuration")
	start := time.Now()
	err := superviseCharon(context.Background(), childArgs(t, "sleep"), func(context.Context) error { return want }, func(context.Context) { t.Error("metrics started after init failure") })
	if !errors.Is(err, want) || time.Since(start) > 2*time.Second {
		t.Fatal("init failure did not stop/reap child", err)
	}
}

func TestCharonShutdownJoinsMetricsWorker(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started, stopped := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	args := childArgs(t, "sleep")
	go func() {
		done <- superviseCharon(ctx, args, func(context.Context) error { return nil }, func(ctx context.Context) { close(started); <-ctx.Done(); close(stopped) })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("metrics worker did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("signal shutdown returned error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not join child/workers")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("metrics worker not joined")
	}
}

func TestCharonDeathAfterBootstrap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := superviseCharon(ctx, childArgs(t, "exit"), func(context.Context) error { return nil }, func(ctx context.Context) { <-ctx.Done() })
	if err == nil || !strings.Contains(err.Error(), "charon exited unexpectedly") {
		t.Fatal("daemon crash treated as graceful shutdown", err)
	}
}
