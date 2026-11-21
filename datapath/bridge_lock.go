package datapath

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// The CNI processes and node agent share this host-mounted directory. flock
// releases automatically on process exit and bounds the wait for a wedged writer.
func withBridgeLock(fn func() error) error {
	dir := filepath.Dir(AgentStateFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(dir, "bridge.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err != unix.EWOULDBLOCK && err != unix.EINTR {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("bridge writer lock timeout")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	return fn()
}
