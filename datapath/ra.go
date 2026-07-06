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
	"log/slog"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Router Advertisements for v6 VPC pods (#8, vm-provisioning.md Part 1,
// option C): cozyplane pins a /128, so SLAAC's prefix+IID model can't
// reproduce the address — but RFC 4862 permits a /128 prefix, in which case
// the "prefix" IS the address and the guest autoconfigures exactly it. A
// KubeVirt bridge-bound guest thus learns its address, default route
// (fe80::1, which the host veth owns), and — when a v6 resolver path exists —
// its DNS server (RDNSS), with no console access and no DHCPv6.
//
// This is control-plane traffic (a few packets per pod lifetime), so it lives
// in the agent, not the eBPF hooks: one AF_PACKET listener per v6 VPC veth
// (kernel-filtered to Router Solicitations), answering RS and emitting
// periodic unsolicited RAs. Veths are discovered from their alias records —
// the same source the rebuild trusts — via an initial scan plus a netlink
// link subscription, so a pod ADDed at any time is picked up immediately.

// raInterval is the unsolicited-RA period (also the fallback rescan cadence).
const raInterval = 200 * time.Second

// RunRAResponder serves Router Advertisements on every v6 VPC pod veth until
// ctx ends. mtu is the pod MTU to advertise; rdnss (optional) is the v6
// resolver address to hand out.
func RunRAResponder(ctx context.Context, mtu int, rdnss net.IP, log *slog.Logger) {
	serving := map[int]context.CancelFunc{}

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
		alive := map[int]bool{}
		for _, l := range links {
			ip6 := raEligible(l)
			if ip6 == nil {
				continue
			}
			idx := l.Attrs().Index
			alive[idx] = true
			if _, ok := serving[idx]; ok {
				continue
			}
			cctx, cancel := context.WithCancel(ctx)
			serving[idx] = cancel
			go serveRA(cctx, l.Attrs().Name, idx, l.Attrs().HardwareAddr, ip6, mtu, rdnss, log)
		}
		for idx, cancel := range serving {
			if !alive[idx] {
				cancel()
				delete(serving, idx)
			}
		}
	}

	scan()
	tick := time.NewTicker(raInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-updates:
			scan()
		case <-tick.C:
			scan()
		}
	}
}

// raEligible returns the pod's v6 VPC address when the link is a plain (non-
// gateway) VPC pod veth carrying one, else nil.
func raEligible(l netlink.Link) net.IP {
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
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons16(unix.ETH_P_IPV6)))
	if err != nil {
		log.Warn("RA responder: socket", "veth", veth, "err", err)
		return
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_IPV6), Ifindex: ifindex}); err != nil {
		log.Warn("RA responder: bind", "veth", veth, "err", err)
		return
	}
	// Kernel-side filter: only Router Solicitations reach userspace
	// (ethertype v6 is already bound; check next-header and ICMPv6 type).
	filter := []unix.SockFilter{
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
		if err := unix.Sendto(fd, frame, 0, dst); err != nil {
			log.Warn("RA responder: send", "veth", veth, "err", err)
		}
	}
	send()
	log.Info("RA responder serving", "veth", veth, "podIP", podIP, "rdnss", rdnss)

	// The RA's Managed flag points the guest at DHCPv6 for the address itself
	// (Linux ignores a /128 PIO — see dhcpv6.go); serve that exchange too.
	go serveDHCPv6(ctx, veth, ifindex, mac, podIP, rdnss, log)

	go func() {
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
	}()

	buf := make([]byte, 256)
	for {
		// A read deadline keeps the loop responsive to ctx cancellation.
		tv := unix.Timeval{Sec: 2}
		_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
		_, _, err := unix.Recvfrom(fd, buf, 0)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			continue // timeout or transient
		}
		send() // the filter admitted only RS: answer immediately
	}
}

// raFrame builds the Router Advertisement: src fe80::1 (the on-link gateway
// the host veth owns), dst all-nodes, with a /128 PIO (A=1, L=0) carrying the
// pod's exact address, an MTU option, the source link-layer option, and —
// when rdnss is set — an RDNSS option.
func raFrame(mac net.HardwareAddr, podIP net.IP, mtu int, rdnss net.IP) []byte {
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
	// M=1 O=1: the address comes from DHCPv6 (Linux ignores the /128 PIO
	// below; stacks that honor it can SLAAC instead and skip the exchange).
	ra[5] = 0xc0
	binary.BigEndian.PutUint16(ra[6:8], 9000) // router lifetime (s)

	opt := ra[16:]
	// Prefix Information: /128, on-link OFF (the address is host-scoped; all
	// traffic goes via fe80::1), autonomous ON — RFC 4862 autoconfigures the
	// exact address, no interface identifier involved.
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
