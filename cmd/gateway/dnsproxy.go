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
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// This chain belongs to the gateway's own netns. InsertUnique would leave an
// existing jump after a historical ACCEPT, so remove only our exact jumps.
func inputJumpFirst(ipt interface {
	Exists(string, string, ...string) (bool, error)
	Delete(string, string, ...string) error
	Insert(string, string, int, ...string) error
}, chain string) error {
	for {
		exists, err := ipt.Exists("filter", "INPUT", "-j", chain)
		if err != nil {
			return err
		}
		if !exists {
			break
		}
		if err := ipt.Delete("filter", "INPUT", "-j", chain); err != nil {
			return err
		}
	}
	return ipt.Insert("filter", "INPUT", 1, "-j", chain)
}

type dnsReply struct {
	data     []byte
	client   *net.UDPAddr
	deadline time.Time
}

type dnsProxy struct {
	cancel    context.CancelFunc
	uconn     *net.UDPConn
	tln       net.Listener
	slots     chan struct{}
	replies   chan dnsReply
	errors    chan error
	wg        sync.WaitGroup
	closeOnce sync.Once
}

func (p *dnsProxy) failed(err error) {
	select {
	case p.errors <- err:
	default:
	}
	p.cancel()
	_ = p.uconn.Close()
	_ = p.tln.Close()
}

// Close interrupts active reads, dials and both TCP copies, then joins every
// worker. The reply queue owns a slot after handoff and is drained on shutdown.
func (p *dnsProxy) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		_ = p.uconn.Close()
		_ = p.tln.Close()
		p.wg.Wait()
		for {
			select {
			case <-p.replies:
				<-p.slots
			default:
				return
			}
		}
	})
	return nil
}

func runDNSProxy(upstream string, log *slog.Logger) (*dnsProxy, error) {
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 53})
	if err != nil {
		return nil, fmt.Errorf("listen udp :53: %w", err)
	}
	// #nosec G102 -- INPUT rejects non-VPC TCP/UDP 53 before ACCEPT; REDIRECT requires wildcard binding.
	tln, err := net.Listen("tcp", ":53")
	if err != nil {
		_ = uconn.Close()
		return nil, fmt.Errorf("listen tcp :53: %w", err)
	}
	return serveDNSProxy(context.Background(), uconn, tln, upstream, 5*time.Second, 64, log), nil
}

func serveDNSProxy(parent context.Context, uconn *net.UDPConn, tln net.Listener, upstream string, timeout time.Duration, budget int, log *slog.Logger) *dnsProxy {
	ctx, cancel := context.WithCancel(parent)
	p := &dnsProxy{cancel: cancel, uconn: uconn, tln: tln, slots: make(chan struct{}, budget), replies: make(chan dnsReply, budget), errors: make(chan error, 1)}
	context.AfterFunc(ctx, func() { _ = uconn.Close(); _ = tln.Close() })
	p.wg.Add(3)
	go func() {
		defer p.wg.Done()
		// Only this writer modifies the shared socket's write deadline.
		for {
			select {
			case <-ctx.Done():
				return
			case reply := <-p.replies:
				if time.Now().Before(reply.deadline) && uconn.SetWriteDeadline(reply.deadline) == nil {
					_, _ = uconn.WriteToUDP(reply.data, reply.client)
				}
				<-p.slots
			}
		}
	}()
	go func() {
		defer p.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, client, err := uconn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() == nil {
					log.Error("dns udp read", "err", err)
					p.failed(fmt.Errorf("dns udp listener failed: %w", err))
				}
				return
			}
			select {
			case p.slots <- struct{}{}:
			default:
				continue
			}
			query := append([]byte(nil), buf[:n]...)
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				handedOff := false
				defer func() {
					if !handedOff {
						<-p.slots
					}
				}()
				reqCtx, done := context.WithTimeout(ctx, timeout)
				defer done()
				deadline, _ := reqCtx.Deadline()
				up, err := (&net.Dialer{}).DialContext(reqCtx, "udp", upstream)
				if err != nil {
					return
				}
				defer up.Close()
				stopClose := context.AfterFunc(reqCtx, func() { _ = up.Close() })
				defer stopClose()
				if up.SetDeadline(deadline) != nil {
					return
				}
				if _, err := up.Write(query); err != nil {
					return
				}
				resp := make([]byte, 65535)
				n, err := up.Read(resp)
				if err != nil {
					return
				}
				select {
				case p.replies <- dnsReply{data: resp[:n], client: client, deadline: deadline}:
					handedOff = true
				case <-reqCtx.Done():
				}
			}()
		}
	}()
	go func() {
		defer p.wg.Done()
		for {
			conn, err := tln.Accept()
			if err != nil {
				if ctx.Err() == nil {
					log.Error("dns tcp accept", "err", err)
					p.failed(fmt.Errorf("dns tcp listener failed: %w", err))
				}
				return
			}
			select {
			case p.slots <- struct{}{}:
			default:
				_ = conn.Close()
				continue
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer func() { <-p.slots }()
				defer conn.Close()
				reqCtx, done := context.WithTimeout(ctx, timeout)
				defer done()
				deadline, _ := reqCtx.Deadline()
				up, err := (&net.Dialer{}).DialContext(reqCtx, "tcp", upstream)
				if err != nil {
					return
				}
				defer up.Close()
				closeSockets := func() { _ = conn.Close(); _ = up.Close() }
				stopClose := context.AfterFunc(reqCtx, closeSockets)
				defer stopClose()
				if conn.SetDeadline(deadline) != nil || up.SetDeadline(deadline) != nil {
					return
				}
				copied := make(chan struct{})
				go func() { _, _ = io.Copy(up, conn); close(copied) }()
				_, _ = io.Copy(conn, up)
				closeSockets()
				<-copied
			}()
		}
	}()
	return p
}
