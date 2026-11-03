package datapath

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

func sandboxWitness(containerID, ifName string) [32]byte {
	if containerID == "" || ifName == "" {
		return [32]byte{}
	}
	return sha256.Sum256([]byte(containerID + "\x00" + ifName))
}

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
