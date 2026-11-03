// SPDX-License-Identifier: GPL-2.0
#ifndef COZYPLANE_ADDRESS128_H
#define COZYPLANE_ADDRESS128_H

// A 128-bit address in network byte order. IPv4 is stored in its RFC 6052
// (NAT64) form 64:ff9b::a.b.c.d — a routable v6 address, so a future cross-family
// translator's 64:ff9b::v4 matches these map entries. (Well-known prefix for now;
// a network-specific prefix is a later config knob behind NAT64_PREFIX.) All map
// addresses are this type; the hooks map each packet's v4 or v6 addresses into it.
struct addr128 {
	__u8 b[16];
};

// The NAT64 well-known prefix 64:ff9b::/96, as the leading 12 bytes.
#define NAT64_PREFIX { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0 }

// v4_to_128 writes a v4 address (network order, as in the packet) into its
// NAT64-mapped 128-bit form.
static __always_inline void v4_to_128(struct addr128 *a, __u32 v4)
{
	__u8 pfx[12] = NAT64_PREFIX;
	__builtin_memcpy(a->b, pfx, 12);
	__builtin_memcpy(&a->b[12], &v4, 4);
}

#endif
