package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/strongswan/govici/vici"
)

// superviseCharon cancels initialization on child death and joins all workers
// before returning, including initialization failures and signal shutdown.
func superviseCharon(parent context.Context, argv []string, initialize func(context.Context) error, serve func(context.Context)) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(context.Canceled)
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// Give charon a bounded opportunity to delete its kernel SAs on shutdown.
	// Startup cleanup remains mandatory because SIGKILL/OOM bypass this path.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 3 * time.Second
	command.Stdout, command.Stderr = os.Stderr, os.Stderr
	if err := command.Start(); err != nil {
		return fmt.Errorf("start charon: %w", err)
	}
	stopped := make(chan struct{})
	go func() {
		err := command.Wait()
		if err == nil {
			err = errors.New("daemon exited without error")
		}
		cancel(fmt.Errorf("charon exited unexpectedly: %w", err))
		close(stopped)
	}()
	defer func() { cancel(context.Canceled); <-stopped }()
	if err := initialize(ctx); err != nil {
		if cause := context.Cause(ctx); parent.Err() == nil && cause != nil {
			return cause
		}
		return err
	}
	served := make(chan struct{})
	go func() { defer close(served); serve(ctx) }()
	defer func() { cancel(context.Canceled); <-served }()
	<-ctx.Done()
	if parent.Err() != nil {
		return nil
	}
	return context.Cause(ctx)
}

// Keep the small requester interface used by loadPeer tests while binding real
// startup requests to cancellation and a timeout.
type startupVICI struct {
	context context.Context
	session *vici.Session
}

func (s startupVICI) CommandRequest(command string, request *vici.Message) (*vici.Message, error) {
	ctx, cancel := context.WithTimeout(s.context, 5*time.Second)
	defer cancel()
	return s.session.Call(ctx, command, request)
}
