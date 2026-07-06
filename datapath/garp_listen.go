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
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Stage 3 of live migration (docs/live-migration.md): the instant cutover.
// When a VM resumes on its migration target it emits a gratuitous ARP (v4) or
// an unsolicited Neighbor Advertisement (v6) — the guest announcing "I am here
// now". That announcement is the tightest possible signal that the VM is live
// on this node, earlier and more precise than KubeVirt's VMI.status.nodeName
// (which lags the guest resume). The target agent listens for it on the staged
// veth and flips the Port's spec.node to itself the moment it arrives. This is
// the analog of OVN's activation-strategy=rarp; the controller's VMI-watch
// (stage 1) remains the fallback for a missed announcement.

// LocalPortVeth is a host-side pod/gateway veth with a rebuild alias.
type LocalPortVeth struct {
	Net     uint32
	IPs     []net.IP
	MAC     net.HardwareAddr
	Ifindex int
}

// ListLocalPortVeths returns every local host veth carrying a rebuild alias.
// The guest-announcement watcher scans these to find migration-involved veths
// (a VM whose Port is active on another node) without depending on Port events,
// which are not emitted when a CNI ADD stages a migration target.
func ListLocalPortVeths() ([]LocalPortVeth, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var out []LocalPortVeth
	for _, l := range links {
		name := l.Attrs().Name
		if !strings.HasPrefix(name, podVethPrefix) && !strings.HasPrefix(name, gwVethPrefix) {
			continue
		}
		rawNet, ips, mac, ok := parseVethAlias(l.Attrs().Alias)
		if !ok {
			continue
		}
		out = append(out, LocalPortVeth{Net: PortNet(rawNet), IPs: ips, MAC: mac, Ifindex: l.Attrs().Index})
	}
	return out, nil
}

// WatchGuestAnnounce blocks until the guest owning (vmIP, expectMAC) announces
// itself on the given veth — a gratuitous ARP for a v4 VPC IP, or an unsolicited
// Neighbor Advertisement for a v6 one — or ctx is cancelled. It returns nil on a
// match (the caller should then drive cutover) and ctx.Err() on cancellation.
//
// The socket is bound to the announcement's ethertype (ARP or IPv6), so only
// candidate frames are delivered; a 1s receive timeout lets the loop observe
// cancellation. Best-effort by nature: a missed announcement just falls back to
// the VMI-watch cutover.
func WatchGuestAnnounce(ctx context.Context, ifindex int, expectMAC net.HardwareAddr, vmIP net.IP) error {
	v4 := vmIP.To4() != nil
	ethProto := uint16(0x86dd) // IPv6
	if v4 {
		ethProto = 0x0806 // ARP
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(ethProto)))
	if err != nil {
		return fmt.Errorf("packet socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethProto), Ifindex: ifindex}); err != nil {
		return fmt.Errorf("bind packet socket to ifindex %d: %w", ifindex, err)
	}
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)

	buf := make([]byte, 1500)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue // timeout tick or interrupted — re-check ctx and retry
			}
			return fmt.Errorf("recv on ifindex %d: %w", ifindex, err)
		}
		if guestAnnouncedItself(buf[:n], expectMAC, vmIP, v4) {
			return nil
		}
	}
}

// guestAnnouncedItself reports whether frame is the migrated guest announcing
// (vmIP, expectMAC): a gratuitous ARP (sender protocol addr == vmIP) for v4, or
// an unsolicited NA (target addr == vmIP) for v6, with the L2/ARP source MAC
// matching the pinned Port MAC in both cases.
func guestAnnouncedItself(frame []byte, expectMAC net.HardwareAddr, vmIP net.IP, v4 bool) bool {
	if len(frame) < 14 {
		return false
	}
	srcMAC := net.HardwareAddr(frame[6:12])
	etherType := binary.BigEndian.Uint16(frame[12:14])

	if v4 {
		if etherType != 0x0806 || len(frame) < 42 {
			return false
		}
		arp := frame[14:]
		// op 1 (request/announcement) or 2 (reply) — stacks GARP as either.
		if op := binary.BigEndian.Uint16(arp[6:8]); op != 1 && op != 2 {
			return false
		}
		sha := net.HardwareAddr(arp[8:14])
		spa := net.IP(arp[14:18])
		return spa.Equal(vmIP.To4()) && macEqual(sha, expectMAC)
	}

	// v6: an ICMPv6 Neighbor Advertisement (type 136) whose target is vmIP.
	if etherType != 0x86dd || len(frame) < 14+40+24 {
		return false
	}
	ip6 := frame[14:54]
	if ip6[6] != 58 { // next header != ICMPv6 (no extension-header parsing needed for NDP)
		return false
	}
	icmp6 := frame[54:]
	if icmp6[0] != 136 { // not a Neighbor Advertisement
		return false
	}
	target := net.IP(icmp6[8:24])
	return target.Equal(vmIP.To16()) && macEqual(srcMAC, expectMAC)
}

func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
