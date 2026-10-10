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
	Name        string
	Net         uint32
	IPs         []net.IP
	MAC         net.HardwareAddr
	Ifindex     int
	Alias       string
	PortUID     string
	ContainerID string
	IfName      string
	RawNet      uint32
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
		if l.Type() != "veth" {
			continue
		}
		if !strings.HasPrefix(name, podVethPrefix) && !strings.HasPrefix(name, gwVethPrefix) {
			continue
		}
		rawNet, ips, mac, ok := parseVethAlias(l.Attrs().Alias)
		if !ok {
			continue
		}
		cid, iface := VethSandbox(l.Attrs().Alias)
		out = append(out, LocalPortVeth{Name: name, Net: PortNet(rawNet), IPs: ips, MAC: mac, Ifindex: l.Attrs().Index, Alias: l.Attrs().Alias, PortUID: VethPortIdentity(l.Attrs().Alias).UID, ContainerID: cid, IfName: iface, RawNet: rawNet})
	}
	return out, nil
}

// WatchGuestAnnounce blocks until the guest owning (vmIP, expectMAC) announces
// itself on the given veth — a gratuitous ARP for a v4 VPC IP, or an unsolicited
// Neighbor Advertisement for a v6 one — or ctx is cancelled. It returns nil on a
// match (the caller should then drive cutover) and ctx.Err() on cancellation.
//
// The socket is bound to the announcement's ethertype (ARP or IPv6), so only
// candidate frames are delivered; a 100ms readiness wait lets the loop observe
// cancellation. Best-effort by nature: a missed announcement just falls back to
// the VMI-watch cutover.
func WatchGuestAnnounce(ctx context.Context, ifindex int, expectMAC net.HardwareAddr, vmIP net.IP) error {
	filter, err := guestAnnouncementFilter(expectMAC, vmIP)
	if err != nil {
		return err
	}
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
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return fmt.Errorf("filter announcement socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethProto), Ifindex: ifindex}); err != nil {
		return fmt.Errorf("bind packet socket to ifindex %d: %w", ifindex, err)
	}
	return watchGuestAnnounceSocket(ctx, fd, ifindex, expectMAC, vmIP, v4)
}

func watchGuestAnnounceSocket(ctx context.Context, fd, ifindex int, expectMAC net.HardwareAddr, vmIP net.IP, v4 bool) error {
	if fd < 0 || fd > 2147483647 {
		return fmt.Errorf("invalid announcement descriptor")
	}
	buf := make([]byte, 1500)
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		nready, err := unix.Poll(poll, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("poll announcement socket: %w", err)
		}
		if nready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return fmt.Errorf("announcement socket closed: poll events %#x", poll[0].Revents)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue // re-poll; another receive must never busy-spin
			}
			return fmt.Errorf("recv on ifindex %d: %w", ifindex, err)
		}
		if guestAnnouncedItself(buf[:n], expectMAC, vmIP, v4) {
			return nil
		}
	}
}

// Every accepted frame is a candidate for the existing userspace recognizer.
// Reject noise before socket queueing so a staged guest cannot spin the agent.
func guestAnnouncementFilter(mac net.HardwareAddr, ip net.IP) ([]unix.SockFilter, error) {
	if len(mac) != 6 || ip.To16() == nil {
		return nil, fmt.Errorf("invalid guest announcement identity")
	}
	minimum := uint32(78)
	if ip.To4() != nil {
		minimum = 42
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_LEN},
		{Code: unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K, K: minimum, Jf: 255},
	}
	equal := func(size uint16, offset, value uint32) {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_LD | size | unix.BPF_ABS, K: offset},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: value, Jf: 255})
	}
	if v4 := ip.To4(); v4 != nil {
		equal(unix.BPF_H, 12, unix.ETH_P_ARP)
		equal(unix.BPF_H, 14, 1)
		equal(unix.BPF_H, 16, unix.ETH_P_IP)
		equal(unix.BPF_H, 18, 0x0604)
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_ABS, K: 20},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 1, Jt: 1},
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: 2, Jf: 255})
		equal(unix.BPF_W, 22, binary.BigEndian.Uint32(mac[:4]))
		equal(unix.BPF_H, 26, uint32(binary.BigEndian.Uint16(mac[4:])))
		equal(unix.BPF_W, 28, binary.BigEndian.Uint32(v4))
	} else {
		equal(unix.BPF_H, 12, unix.ETH_P_IPV6)
		equal(unix.BPF_B, 20, 58)
		equal(unix.BPF_B, 54, 136)
		equal(unix.BPF_W, 6, binary.BigEndian.Uint32(mac[:4]))
		equal(unix.BPF_H, 10, uint32(binary.BigEndian.Uint16(mac[4:])))
		v6 := ip.To16()
		for i := 0; i < 16; i += 4 {
			equal(unix.BPF_W, uint32(62+i), binary.BigEndian.Uint32(v6[i:i+4]))
		}
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: 1500}, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K})
	for i := range filter {
		if filter[i].Jf == 255 {
			filter[i].Jf = uint8(len(filter) - i - 2)
		}
	}
	return filter, nil
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
