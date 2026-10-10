package main

import (
	"context"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

func listenDNSTCP(address string, slots chan struct{}) (net.Listener, error) {
	config := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		if err := raw.Control(func(fd uintptr) {
			socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
		}); err != nil {
			return err
		}
		return socketErr
	}}
	listener, err := config.Listen(context.Background(), "tcp", address)
	if err != nil {
		return nil, err
	}
	return &dnsTCPListener{Listener: listener, slots: slots}, nil
}

// Share slots across IPv4/IPv6 listeners, before miekg/dns starts reader
// goroutines. Excess sockets close instead of waiting in an application queue.
type dnsTCPListener struct {
	net.Listener
	slots chan struct{}
}

func (l *dnsTCPListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &dnsTCPConnection{Conn: connection, slots: l.slots}, nil
		default:
			_ = connection.Close()
		}
	}
}

type dnsTCPConnection struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
	err   error
}

func (c *dnsTCPConnection) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		<-c.slots
	})
	return c.err
}
