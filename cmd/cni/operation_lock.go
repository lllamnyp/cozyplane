package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const sandboxLockDir = "/run/cozyplane/cni-locks"
const sandboxLockWait = 5 * time.Second

// Guard the whole operation, including its rollback. A fixed shard set avoids
// retaining a file for every historical sandbox. All NICs share the CID guard.
func withSandboxLock(ctx context.Context, dir, containerID, ifName string, fn func() error) error {
	if containerID == "" || ifName == "" {
		return fmt.Errorf("CNI operation requires container ID and interface")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	var info unix.Stat_t
	if err = unix.Fstat(parentFD, &info); err != nil {
		return err
	}
	if info.Uid != 0 || info.Mode&022 != 0 {
		return fmt.Errorf("unsafe CNI lock parent ownership or mode")
	}
	if err = unix.Mkdirat(parentFD, filepath.Base(dir), 0700); err != nil && err != unix.EEXIST {
		return err
	}
	directory, err := unix.Openat(parentFD, filepath.Base(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(directory)
	if err = unix.Fstat(directory, &info); err != nil {
		return err
	}
	if info.Uid != 0 || info.Mode&077 != 0 {
		return fmt.Errorf("unsafe CNI lock directory ownership or mode")
	}
	shard := sha256.Sum256([]byte(containerID))
	fd, err := unix.Openat(directory, fmt.Sprintf("sandbox-%02x.lock", shard[0]), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.Fstat(fd, &info); err != nil {
		return err
	}
	if info.Uid != 0 || info.Mode&077 != 0 || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 {
		return fmt.Errorf("unsafe CNI lock file ownership, type, mode or links")
	}
	lockCtx, cancel := context.WithTimeout(ctx, sandboxLockWait)
	defer cancel()
	for {
		if err = lockCtx.Err(); err != nil {
			return fmt.Errorf("CNI sandbox lock: %w", err)
		}
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EINTR {
			return err
		}
		timer := time.NewTimer(20 * time.Millisecond)
		select {
		case <-timer.C:
		case <-lockCtx.Done():
			timer.Stop()
			return fmt.Errorf("CNI sandbox lock: %w", lockCtx.Err())
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return fn()
}
