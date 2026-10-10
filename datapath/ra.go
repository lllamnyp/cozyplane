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

package datapath

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Router Advertisements for v6 VPC pods (#8, vm-provisioning.md Part 1,
// option C): cozyplane pins a /128, so Ethernet SLAAC's prefix+IID model can't
// reproduce the address. The Managed flag requests DHCPv6, which serves that
// exact binding. A KubeVirt bridge-bound guest learns its address, default route
// (fe80::1, which the host veth owns), and — when a v6 resolver path exists —
// its DNS server (RDNSS), with no console access or manual address assignment.
//
// This is control-plane traffic (a few packets per pod lifetime), so it lives
// in the agent, not the eBPF hooks: one AF_PACKET listener per v6 VPC veth
// (kernel-filtered to Router Solicitations), answering RS and emitting
// periodic unsolicited RAs. Veths are discovered from their alias records —
// the same source the rebuild trusts — via an initial scan plus a netlink
// link subscription, so a pod ADDed at any time is picked up immediately.

// raInterval is the unsolicited-RA period (also the fallback rescan cadence).
const raInterval = 200 * time.Second

const ipv6SolicitationInterval = 100 * time.Millisecond

type raWorker struct {
	identity string
	cancel   context.CancelFunc
	done     chan struct{}
}

func raIdentity(link netlink.Link) string {
	ip := raEligible(link)
	if ip == nil {
		return ""
	}
	raw, _, _, _ := parseVethAlias(link.Attrs().Alias)
	cid, iface := VethSandbox(link.Attrs().Alias)
	return fmt.Sprintf("%s|%d|%s|%s|%s|%s|%s", link.Attrs().Name, PortNet(raw), ip, link.Attrs().HardwareAddr, cid, iface, VethPortIdentity(link.Attrs().Alias).UID)
}

func reconcileRAWorkers(ctx context.Context, serving map[int]*raWorker, links []netlink.Link, start func(context.Context, netlink.Link)) {
	desired := map[int]netlink.Link{}
	for _, link := range links {
		if raIdentity(link) != "" {
			desired[link.Attrs().Index] = link
		}
	}
	for idx, worker := range serving {
		finished := false
		select {
		case <-worker.done:
			finished = true
		default:
		}
		link := desired[idx]
		if !finished && link != nil && worker.identity == raIdentity(link) {
			continue
		}
		worker.cancel()
		<-worker.done
		delete(serving, idx)
	}
	for idx, link := range desired {
		if serving[idx] != nil || ctx.Err() != nil {
			continue
		}
		child, cancel := context.WithCancel(ctx)
		worker := &raWorker{identity: raIdentity(link), cancel: cancel, done: make(chan struct{})}
		serving[idx] = worker
		go func() { defer close(worker.done); start(child, link) }()
	}
}

// RunRAResponder serves Router Advertisements on every v6 VPC pod veth until
// ctx ends. mtu is the pod MTU to advertise; rdnss (optional) is the v6
// resolver address to hand out.
func RunRAResponder(ctx context.Context, mtu int, rdnss net.IP, log *slog.Logger) {
	if mtu < 1280 || mtu > 65535 {
		log.Error("RA responder: invalid IPv6 MTU", "mtu", mtu)
		return
	}
	serving := map[int]*raWorker{}
	defer func() {
		for _, worker := range serving {
			worker.cancel()
		}
		for _, worker := range serving {
			<-worker.done
		}
	}()

	updates := make(chan netlink.LinkUpdate, 64)
	done := make(chan struct{})
	defer close(done)
	if err := netlink.LinkSubscribe(updates, done); err != nil {
		log.Warn("RA responder: link subscribe failed; falling back to rescans", "err", err)
	}

	scan := func() {
		links, err := netlink.LinkList()
		if err != nil {
			log.Warn("RA responder: list links", "err", err)
			return
		}
		reconcileRAWorkers(ctx, serving, links, func(child context.Context, l netlink.Link) {
			serveRA(child, l.Attrs().Name, l.Attrs().Index, l.Attrs().HardwareAddr, raEligible(l), mtu, rdnss, log)
		})
	}

	scan()
	raRescanLoop(ctx, updates, scan)
}

func raRescanLoop(ctx context.Context, updates <-chan netlink.LinkUpdate, scan func()) {
	tick := time.NewTicker(raInterval)
	defer tick.Stop()
	var timer *time.Timer
	var pending <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case _, open := <-updates:
			if !open {
				updates = nil
			} else {
				if pending == nil {
					timer = time.NewTimer(100 * time.Millisecond)
					pending = timer.C
				}
			}
		case <-pending:
			pending = nil
			scan()
		case <-tick.C:
			scan()
		}
	}
}

// raEligible returns the pod's v6 VPC address when the link is a plain (non-
// gateway) VPC pod veth carrying one, else nil.
func raEligible(l netlink.Link) net.IP {
	if l.Type() != "veth" {
		return nil
	}
	name := l.Attrs().Name
	if len(name) < 3 || name[:3] != podVethPrefix {
		return nil
	}
	rawNet, ips, _, ok := parseVethAlias(l.Attrs().Alias)
	if !ok || PortNet(rawNet) == 0 || rawNet&PortGatewayFlag != 0 {
		return nil
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			return ip.To16()
		}
	}
	return nil
}

// serveRA answers Router Solicitations on one veth and emits unsolicited RAs
// (one immediately — the guest may have solicited before we attached — then
// periodically).
func serveRA(ctx context.Context, veth string, ifindex int, mac net.HardwareAddr, podIP net.IP, mtu int, rdnss net.IP, log *slog.Logger) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons16(unix.ETH_P_IPV6)))
	if err != nil {
		log.Warn("RA responder: socket", "veth", veth, "err", err)
		return
	}
	defer unix.Close(fd)
	initial, err := netlink.LinkByIndex(ifindex)
	if err != nil || initial.Attrs().Name != veth || !raEligible(initial).Equal(podIP) {
		return
	}
	identity := raIdentity(initial)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_IPV6), Ifindex: ifindex}); err != nil {
		log.Warn("RA responder: bind", "veth", veth, "err", err)
		return
	}
	// Kernel-side filter: only Router Solicitations reach userspace
	// (ethertype v6 is already bound; check next-header and ICMPv6 type).
	filter := [...]unix.SockFilter{
		{Code: 0x30, K: 20},         // ldb ip6 next-header
		{Code: 0x15, Jf: 3, K: 58},  // jne ICMPv6 -> drop
		{Code: 0x30, K: 54},         // ldb icmp6 type
		{Code: 0x15, Jf: 1, K: 133}, // jne RS -> drop
		{Code: 0x06, K: 0x40000},    // accept
		{Code: 0x06, K: 0},          // drop
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		log.Warn("RA responder: attach filter", "veth", veth, "err", err)
		return
	}

	frame := raFrame(mac, podIP, mtu, rdnss)
	dst := &unix.SockaddrLinklayer{Ifindex: ifindex, Halen: 6}
	copy(dst.Addr[:], frame[0:6])
	send := func() {
		if ctx.Err() != nil {
			return
		}
		current, err := netlink.LinkByIndex(ifindex)
		if err != nil || raIdentity(current) != identity {
			cancel()
			return
		}
		if err := unix.Sendto(fd, frame, 0, dst); err != nil {
			log.Warn("RA responder: send", "veth", veth, "err", err)
		}
	}
	send()
	log.Info("RA responder serving", "veth", veth, "podIP", podIP, "rdnss", rdnss)

	// The RA's Managed flag points the guest at DHCPv6 for the address itself
	// (Linux ignores a /128 PIO — see dhcpv6.go); serve that exchange too.
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }() // registered after Close: drain first
	workers.Go(func() { serveDHCPv6(ctx, veth, ifindex, mac, podIP, rdnss, log) })

	workers.Go(func() {
		tick := time.NewTicker(raInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				send()
			}
		}
	})

	buf := make([]byte, 256)
	tick := time.NewTicker(ipv6SolicitationInterval)
	defer tick.Stop()
	tv := unix.Timeval{Sec: 2}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		log.Warn("RA receive timeout", "err", err)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		// A read deadline keeps the loop responsive to ctx cancellation.
		_, _, err := unix.Recvfrom(fd, buf, 0)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			log.Warn("RA responder: receive ended", "veth", veth, "err", err)
			return
		}
		send() // the filter admitted only RS: answer immediately
	}
}

// raFrame builds the Router Advertisement: src fe80::1 (the on-link gateway
// the host veth owns), dst all-nodes, with a /128 PIO (A=1, L=0) carrying the
// pod's exact address, an MTU option, the source link-layer option, and —
// when rdnss is set — an RDNSS option.
func raFrame(mac net.HardwareAddr, podIP net.IP, mtu int, rdnss net.IP) []byte {
	if mtu < 1280 || mtu > 65535 {
		return nil
	}
	icmpLen := 16 + 32 + 8 + 8 // RA header + PIO + MTU + SLLA
	if rdnss != nil {
		icmpLen += 24
	}
	f := make([]byte, 14+40+icmpLen)
	copy(f[0:6], []byte{0x33, 0x33, 0x00, 0x00, 0x00, 0x01}) // all-nodes mcast
	copy(f[6:12], mac)
	binary.BigEndian.PutUint16(f[12:14], 0x86dd)

	ip := f[14:54]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(icmpLen))
	ip[6] = 58  // ICMPv6
	ip[7] = 255 // hop limit (NDP requirement)
	gw := net.ParseIP("fe80::1")
	copy(ip[8:24], gw)
	copy(ip[24:40], net.ParseIP("ff02::1"))

	ra := f[54:]
	ra[0] = 134 // router advertisement
	ra[4] = 64  // cur hop limit
	// M=1 O=1: the address comes from DHCPv6; Linux ignores the /128 PIO.
	ra[5] = 0xc0
	binary.BigEndian.PutUint16(ra[6:8], 9000) // router lifetime (s)

	opt := ra[16:]
	// Prefix Information: /128, on-link OFF (the address is host-scoped; all
	// traffic goes via fe80::1). The legacy A flag is retained for compatibility;
	// Linux acquires the exact address from DHCPv6, not this PIO.
	opt[0], opt[1] = 3, 4
	opt[2] = 128                                      // prefix length
	opt[3] = 0x40                                     // A=1, L=0
	binary.BigEndian.PutUint32(opt[4:8], 0xffffffff)  // valid lifetime
	binary.BigEndian.PutUint32(opt[8:12], 0xffffffff) // preferred lifetime
	copy(opt[16:32], podIP)

	opt = opt[32:]
	opt[0], opt[1] = 5, 1 // MTU
	binary.BigEndian.PutUint32(opt[4:8], uint32(mtu))

	opt = opt[8:]
	opt[0], opt[1] = 1, 1 // source link-layer address
	copy(opt[2:8], mac)

	if rdnss != nil {
		opt = opt[8:]
		opt[0], opt[1] = 25, 3 // RDNSS, one address
		binary.BigEndian.PutUint32(opt[4:8], 9000)
		copy(opt[8:24], rdnss.To16())
	}

	// ICMPv6 checksum over the pseudo-header + payload.
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
		}
	}
	add(ip[8:40])
	var ln [4]byte
	binary.BigEndian.PutUint32(ln[:], uint32(icmpLen))
	add(ln[:])
	add([]byte{0, 58})
	add(ra[:icmpLen])
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ra[2:4], ^uint16(sum))
	return f
}

// htons16 converts to network byte order for AF_PACKET binds.
func htons16(v uint16) uint16 { return v<<8 | v>>8 }
