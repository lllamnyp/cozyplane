package datapath

import (
	"fmt"
	"net"
	"net/netip"
)

// normalizedCIDR keeps IPv4 and native IPv6 containment separate, while
// treating mapped /96../128 masks as ordinary IPv4 /0../32 masks.
func normalizedCIDR(cidr *net.IPNet) (netip.Prefix, error) {
	if cidr == nil {
		return netip.Prefix{}, fmt.Errorf("missing CIDR")
	}
	ones, bits := cidr.Mask.Size()
	addr, ok := netip.AddrFromSlice(cidr.IP)
	if !ok || (bits != 32 && bits != 128) {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR address or mask")
	}
	if bits == 32 {
		addr = addr.Unmap()
		if !addr.Is4() {
			return netip.Prefix{}, fmt.Errorf("IPv4 mask on IPv6 address")
		}
	} else if addr.Is4() || addr.Is4In6() {
		if ones >= 96 {
			addr = addr.Unmap()
			ones -= 96
		} else if addr.Is4() {
			return netip.Prefix{}, fmt.Errorf("IPv6 mask on IPv4 address")
		}
	}
	return netip.PrefixFrom(addr, ones).Masked(), nil
}

// cidrAddressPrefix is the single conversion from logical CIDR masks to the
// RFC 6052 address space used by every route and policy LPM map.
func cidrAddressPrefix(cidr *net.IPNet) (overlayAddr128, uint32, error) {
	addr, bits, _, err := cidrPolicyPrefix(cidr)
	return addr, bits, err
}

func cidrPolicyPrefix(cidr *net.IPNet) (overlayAddr128, uint32, uint8, error) {
	prefix, err := normalizedCIDR(cidr)
	if err != nil {
		return overlayAddr128{}, 0, 0, err
	}
	bits := uint32(prefix.Bits())
	family := uint8(6)
	ip := prefix.Addr().As16()
	addr, err := addr128(ip[:])
	if prefix.Addr().Is4() {
		bits += 96
		family = 4
	}
	return addr, bits, family, err
}

func npCIDRDirection(dir, family uint8) uint8 {
	if family == 4 {
		return dir | 0x40
	}
	return dir | 0x80
}
