package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestFRRChildHelper(t *testing.T) {
	if os.Getenv("COZYPLANE_FRR_PROCESS_TEST") == "" {
		return
	}
	if os.Getenv("COZYPLANE_FRR_PROCESS_TEST") == "exit" {
		os.Exit(42)
	}
	if err := os.WriteFile(os.Getenv("COZYPLANE_FRR_PID_FILE"), []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(43)
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

func frrChildArgs(t *testing.T, mode string) []string {
	t.Helper()
	t.Setenv("COZYPLANE_FRR_PROCESS_TEST", mode)
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []string{binary, "-test.run=^TestFRRChildHelper$"}
}

func TestFRRDeathAbortsSocketReadiness(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	child := frrChildArgs(t, "exit")
	err := superviseFRR(ctx, [][]string{child, child}, func(ctx context.Context) error {
		return waitForPath(ctx, filepath.Join(t.TempDir(), "absent.socket"))
	})
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatal("child death did not interrupt readiness", err)
	}
}

func TestFRRFailureAndShutdownReapChild(t *testing.T) {
	for _, mode := range []string{"readiness failure", "signal", "partial start failure"} {
		t.Run(mode, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "child.pid")
			t.Setenv("COZYPLANE_FRR_PID_FILE", pidFile)
			child := frrChildArgs(t, "sleep")
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			want := errors.New("socket readiness failed")
			commands := [][]string{child, child}
			if mode == "partial start failure" {
				commands[1] = []string{filepath.Join(t.TempDir(), "absent-binary")}
			}
			err := superviseFRR(ctx, commands, func(ctx context.Context) error {
				if err := waitForPath(ctx, pidFile); err != nil {
					return err
				}
				if mode == "signal" {
					cancel()
					return ctx.Err()
				}
				if mode == "readiness failure" {
					return want
				}
				return nil
			})
			if mode == "signal" && err != nil || mode == "readiness failure" && !errors.Is(err, want) || mode == "partial start failure" && err == nil {
				t.Fatalf("unexpected result: %v", err)
			}
			raw, readErr := os.ReadFile(pidFile)
			if readErr != nil {
				t.Fatal(readErr)
			}
			pid, parseErr := strconv.Atoi(string(raw))
			if parseErr != nil || syscall.Kill(pid, 0) != syscall.ESRCH {
				t.Fatal("child was not stopped and reaped", pid, parseErr)
			}
		})
	}
}
