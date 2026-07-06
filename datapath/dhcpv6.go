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
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

// A minimal stateful DHCPv6 server (RFC 8415), one per v6 VPC pod veth, with
// exactly one binding: the pod's pinned /128. It exists because Linux ignores
// a /128 Prefix Information Option — addrconf hard-requires prefix length 64
// on ethernet, so the SLAAC route (vm-provisioning.md option C) cannot carry
// an exact address; the RA instead sets the Managed flag and this server
// answers the resulting DHCPv6 exchange (option A — the same mechanism
// KubeVirt's masquerade binding uses, and the exact v6 mirror of the v4 DHCP
// the guest already gets). Every client on the link is the same guest, so
// SOLICIT/REQUEST/CONFIRM/RENEW/REBIND all yield the one address, with
// infinite lifetimes (the address is pinned identity — it never expires).

const (
	dhcp6Solicit   = 1
	dhcp6Advertise = 2
	dhcp6Request   = 3
	dhcp6Confirm   = 4
	dhcp6Renew     = 5
	dhcp6Rebind    = 6
	dhcp6Reply     = 7

	dhcp6OptClientID    = 1
	dhcp6OptServerID    = 2
	dhcp6OptIANA        = 3
	dhcp6OptIAAddr      = 5
	dhcp6OptStatus      = 13
	dhcp6OptRapidCommit = 14
	dhcp6OptDNS         = 23

	infiniteLifetime = 0xffffffff
)

// serveDHCPv6 answers the pod's DHCPv6 exchange on one veth until ctx ends.
func serveDHCPv6(ctx context.Context, veth string, ifindex int, mac net.HardwareAddr, podIP net.IP, rdnss net.IP, log *slog.Logger) {
	// The socket must bind the WILDCARD address: UDP delivery matches the
	// bound local address, so a socket bound to fe80::1 would never receive
	// datagrams addressed to the ff02::1:2 group, joined or not. Scope it to
	// the veth (SO_BINDTODEVICE; SO_REUSEADDR lets every veth's server bind
	// :547) and join All_DHCP_Relay_Agents_and_Servers on that link. Replies
	// go to the client's link-local address (its zone pins the interface),
	// and source selection picks the link's fe80::1.
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, veth)
		}); err != nil {
			return err
		}
		return serr
	}}
	pc, err := lc.ListenPacket(ctx, "udp6", "[::]:547")
	if err != nil {
		log.Warn("DHCPv6: listen", "veth", veth, "err", err)
		return
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()
	p := ipv6.NewPacketConn(conn)
	group := &net.UDPAddr{IP: net.ParseIP("ff02::1:2")}
	if err := p.JoinGroup(&net.Interface{Index: ifindex, Name: veth}, group); err != nil {
		log.Warn("DHCPv6: join group", "veth", veth, "err", err)
		return
	}

	buf := make([]byte, 1500)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFromUDP(buf)
		if ctx.Err() != nil {
			return
		}
		if err != nil || n < 4 {
			continue
		}
		reply := buildDHCP6Reply(buf[:n], mac, podIP, rdnss)
		if reply == nil {
			continue
		}
		if _, err := conn.WriteToUDP(reply, src); err != nil {
			log.Warn("DHCPv6: send", "veth", veth, "err", err)
		}
	}
}

// buildDHCP6Reply builds the response for one client message, nil to ignore.
func buildDHCP6Reply(msg []byte, mac net.HardwareAddr, podIP net.IP, rdnss net.IP) []byte {
	typ := msg[0]
	txid := msg[1:4]

	var clientID []byte
	var iaid []byte
	rapid := false
	for opts := msg[4:]; len(opts) >= 4; {
		code := binary.BigEndian.Uint16(opts[0:2])
		olen := int(binary.BigEndian.Uint16(opts[2:4]))
		if 4+olen > len(opts) {
			break
		}
		body := opts[4 : 4+olen]
		switch code {
		case dhcp6OptClientID:
			clientID = body
		case dhcp6OptIANA:
			if olen >= 4 {
				iaid = body[0:4]
			}
		case dhcp6OptRapidCommit:
			rapid = true
		}
		opts = opts[4+olen:]
	}
	if clientID == nil {
		return nil
	}
	if iaid == nil {
		iaid = []byte{0, 0, 0, 1}
	}

	var rtype byte
	switch typ {
	case dhcp6Solicit:
		rtype = dhcp6Advertise
		if rapid {
			rtype = dhcp6Reply
		}
	case dhcp6Request, dhcp6Confirm, dhcp6Renew, dhcp6Rebind:
		rtype = dhcp6Reply
	default:
		return nil
	}

	out := make([]byte, 0, 256)
	out = append(out, rtype)
	out = append(out, txid...)
	out = appendOpt(out, dhcp6OptClientID, clientID)
	// Server DUID: DUID-LL (type 3, hwtype 1) over the veth MAC.
	duid := make([]byte, 4+len(mac))
	binary.BigEndian.PutUint16(duid[0:2], 3)
	binary.BigEndian.PutUint16(duid[2:4], 1)
	copy(duid[4:], mac)
	out = appendOpt(out, dhcp6OptServerID, duid)
	if rapid && rtype == dhcp6Reply {
		out = appendOpt(out, dhcp6OptRapidCommit, nil)
	}
	// IA_NA{iaid, T1=T2=infinite} containing IAADDR{podIP, infinite, infinite}:
	// the address is pinned identity — the guest never needs to renew.
	iaaddr := make([]byte, 24)
	copy(iaaddr[0:16], podIP.To16())
	binary.BigEndian.PutUint32(iaaddr[16:20], infiniteLifetime)
	binary.BigEndian.PutUint32(iaaddr[20:24], infiniteLifetime)
	iana := make([]byte, 12, 12+4+len(iaaddr))
	copy(iana[0:4], iaid)
	binary.BigEndian.PutUint32(iana[4:8], infiniteLifetime)
	binary.BigEndian.PutUint32(iana[8:12], infiniteLifetime)
	iana = appendOpt(iana, dhcp6OptIAAddr, iaaddr)
	out = appendOpt(out, dhcp6OptIANA, iana)
	if rdnss != nil {
		out = appendOpt(out, dhcp6OptDNS, rdnss.To16())
	}
	return out
}

func appendOpt(b []byte, code uint16, body []byte) []byte {
	var hdr [4]byte
	binary.BigEndian.PutUint16(hdr[0:2], code)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	b = append(b, hdr[:]...)
	return append(b, body...)
}
