// Package ipam shares address constraints between allocators and API writers.
package ipam

import (
	"net"
	"net/netip"
)

const (
	BridgeIPv4       = "169.254.1.1"
	BridgeIPv6       = "fe80::1"
	HairpinIPv4      = "169.254.42.1"
	HairpinIPv6      = "fe80::2a:1"
	MaxCandidateWalk = 65536
	MaxClaimAttempts = 256
)

var reserved = map[netip.Addr]struct{}{
	netip.MustParseAddr(BridgeIPv4):           {},
	netip.MustParseAddr(BridgeIPv6):           {},
	netip.MustParseAddr(HairpinIPv4):          {},
	netip.MustParseAddr(HairpinIPv6):          {},
	netip.MustParseAddr("64:ff9b::a9fe:101"):  {},
	netip.MustParseAddr("64:ff9b::a9fe:2a01"): {},
}

// IsReserved also recognizes IPv4-mapped inputs; CIDRs around these individual
// addresses remain usable. No tenant-wide or cluster-wide CIDR exclusion.
func IsReserved(ip net.IP) bool {
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	_, found := reserved[address.Unmap()]
	return found
}

// IsPoolReserved applies the network/.1 convention to explicit and reused
// claims too. Gateway attachments use their separate authorized claim path.
func IsPoolReserved(network *net.IPNet, ip net.IP) bool {
	if network == nil || ip == nil || IsReserved(ip) {
		return true
	}
	base := network.IP.Mask(network.Mask)
	address, valid := netip.AddrFromSlice(base)
	if !valid {
		return true
	}
	return ip.Equal(base) || ip.Equal(net.IP(address.Unmap().Next().AsSlice()))
}
