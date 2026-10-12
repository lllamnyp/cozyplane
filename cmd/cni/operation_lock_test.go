package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rootLockFixture(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned host lock fixtures")
	}
	parent := filepath.Join(t.TempDir(), "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "locks")
}

func TestSandboxLockSerializesNICsAndCancelsWait(t *testing.T) {
	dir := rootLockFixture(t)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	go func() {
		done <- withSandboxLock(t.Context(), dir, "sandbox", "eth0", func() error { close(entered); <-release; return errors.New("ADD failed after rollback") })
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("initial lock acquisition failed", err)
	case <-time.After(time.Second):
		t.Fatal("initial lock acquisition did not complete")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	called := false
	err := withSandboxLock(ctx, dir, "sandbox", "net1", func() error { called = true; return nil })
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatal("secondary operation entered or wait not canceled", err, called)
	}
	close(release)
	if err = <-done; err == nil {
		t.Fatal("operation error lost")
	}
	if err = withSandboxLock(t.Context(), dir, "sandbox", "eth0", func() error { return nil }); err != nil {
		t.Fatal("error path retained lock", err)
	}
}

func TestSandboxLockRejectsUnsafePaths(t *testing.T) {
	for _, kind := range []string{"parent mode", "directory mode", "directory symlink", "file symlink", "file mode", "file owner", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := rootLockFixture(t)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			shard := sha256.Sum256([]byte("sandbox"))
			lock := filepath.Join(dir, fmt.Sprintf("sandbox-%02x.lock", shard[0]))
			target := filepath.Join(filepath.Dir(dir), "preserved")
			if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "parent mode":
				if err := os.Chmod(filepath.Dir(dir), 0777); err != nil {
					t.Fatal(err)
				}
			case "directory mode":
				if err := os.Chmod(dir, 0777); err != nil {
					t.Fatal(err)
				}
			case "directory symlink":
				if err := os.Rename(dir, dir+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+"-real", dir); err != nil {
					t.Fatal(err)
				}
			case "file symlink":
				if err := os.Symlink(target, lock); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(target, lock); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(lock, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(lock, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "file mode" {
					if err := os.Chmod(lock, 0666); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.Chown(lock, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			}
			called := false
			if err := withSandboxLock(t.Context(), dir, "sandbox", "eth0", func() error { called = true; return nil }); err == nil || called {
				t.Fatal("unsafe lock path admitted", kind, err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "preserve" {
				t.Fatal("target changed", err)
			}
		})
	}
}

func TestSandboxLockChurnBoundsFilesAndDescriptors(t *testing.T) {
	dir := rootLockFixture(t)
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2000 {
		if err = withSandboxLock(t.Context(), dir, fmt.Sprintf("sandbox-%d", i), "eth0", func() error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) > 256 || len(files) < 200 {
		t.Fatal("lock files follow pod history or fixtures do not cover shards", len(files))
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatal("lock descriptor leak", len(before), len(after))
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err = withSandboxLock(ctx, dir, "sandbox", "eth0", func() error { t.Fatal("canceled operation entered"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSandboxLockConcurrentCriticalSections(t *testing.T) {
	dir := rootLockFixture(t)
	var active atomic.Int64
	errorsOut := make(chan error, 64)
	for range 64 {
		go func() {
			errorsOut <- withSandboxLock(t.Context(), dir, "sandbox", "eth0", func() error {
				if active.Add(1) != 1 {
					return errors.New("overlapping operation")
				}
				active.Add(-1)
				return nil
			})
		}()
	}
	for range 64 {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSandboxLockProcessHelper(t *testing.T) {
	if os.Getenv("COZYPLANE_LOCK_TEST_HELPER") != "1" {
		return
	}
	err := withSandboxLock(t.Context(), os.Getenv("COZYPLANE_LOCK_TEST_DIR"), "sandbox", "eth0", func() error {
		fmt.Fprintln(os.Stdout, "locked")
		select {}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSandboxLockReleasedByProcessDeath(t *testing.T) {
	dir := rootLockFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSandboxLockProcessHelper$")
	child.Env = append(os.Environ(), "COZYPLANE_LOCK_TEST_HELPER=1", "COZYPLANE_LOCK_TEST_DIR="+dir)
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	line, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatal("child did not acquire lock", line, err)
	}
	wait, done := context.WithTimeout(ctx, 80*time.Millisecond)
	err = withSandboxLock(wait, dir, "sandbox", "eth0", func() error { t.Fatal("entered while other process held lock"); return nil })
	done()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cross-process lock not honored", err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	if err = withSandboxLock(ctx, dir, "sandbox", "eth0", func() error { return nil }); err != nil {
		t.Fatal("dead process retained flock", err)
	}
}
