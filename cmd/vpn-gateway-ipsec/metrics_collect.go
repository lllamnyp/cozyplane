package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"iter"
	"net"
	"time"

	"github.com/strongswan/govici/vici"
)

const ipsecCollectionTimeout = 5 * time.Second
const maxIPsecEvents = 4096
const maxVICIFrame = 1 << 20
const maxVICICollection = 8 << 20

var errIPsecCollectionBusy = errors.New("IPsec collection already running")

type ipsecStream interface {
	CallStreaming(context.Context, string, string, *vici.Message) iter.Seq2[*vici.Message, error]
	Close() error
}

type ipsecCollector struct {
	slot chan struct{}
	open func(context.Context) (ipsecStream, error)
}

func (c *ipsecCollector) collect(ctx context.Context, peers []peer) (map[string]ipsecConnectionMetrics, time.Time, error) {
	select {
	case c.slot <- struct{}{}:
	default:
		return nil, time.Time{}, errIPsecCollectionBusy
	}
	defer func() { <-c.slot }()
	ctx, cancel := context.WithTimeout(ctx, ipsecCollectionTimeout)
	defer cancel()
	session, err := c.open(ctx)
	if err != nil {
		if cause := ctx.Err(); cause != nil {
			return nil, time.Time{}, cause
		}
		return nil, time.Time{}, err
	}
	defer session.Close()
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stop()
	var events []*vici.Message
	for event, err := range session.CallStreaming(ctx, "list-sas", "list-sa", vici.NewMessage()) {
		if err != nil {
			cause := ctx.Err()
			cancel()
			if cause != nil {
				return nil, time.Time{}, cause
			}
			return nil, time.Time{}, err
		}
		if len(events) >= maxIPsecEvents {
			cancel()
			return nil, time.Time{}, errors.New("IPsec status event budget exceeded")
		}
		events = append(events, event)
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	now := time.Now().UTC()
	return collectIPsecMetrics(events, peers, now), now, nil
}

func openMetricsVICI(ctx context.Context, socket string) (ipsecStream, error) {
	return dialVICI(ctx, socket)
}

func dialVICI(ctx context.Context, socket string) (*vici.Session, error) {
	return vici.NewSession(vici.WithSocketPath(socket), vici.WithDialContext(func(_ context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return &boundedVICIConn{Conn: conn}, nil
	}))
}

// Validate the length header before govici allocates its response payload.
// The connection has one reader (the govici listener).
type boundedVICIConn struct {
	net.Conn
	header    [4]byte
	pending   []byte
	remaining uint32
	total     uint64
}

func (c *boundedVICIConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.pending) != 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.remaining != 0 {
		if uint64(len(p)) > uint64(c.remaining) {
			p = p[:int(c.remaining)]
		}
		n, err := c.Conn.Read(p)
		c.remaining -= uint32(n)
		return n, err
	}
	if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(c.header[:])
	if size == 0 || size > maxVICIFrame || c.total+uint64(size)+4 > maxVICICollection {
		return 0, errors.New("VICI response exceeds collection budget")
	}
	c.total += uint64(size) + 4
	c.remaining = size
	c.pending = c.header[:]
	return c.Read(p)
}
