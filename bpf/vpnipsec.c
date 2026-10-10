// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "address128.h"

struct address_key { __u32 family; __u8 address[16]; };
struct destination_key { __u32 prefixlen; __u32 family; __u8 address[16]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct address_key);
	__type(value, __u32);
} denied SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 4096);
	__type(key, struct destination_key);
	__type(value, __u32);
} destinations SEC(".maps");

// XFRM has already authenticated the source against this interface's remote_ts.
// Deny local sockets as well as forwarding outside the served VPCs, before the
// kernel route lookup. XFRM may retain the outer link's MAC header on ingress;
// always read relative to the decrypted network header rather than skb data.
SEC("tc") int vpn_ipsec_ingress(struct __sk_buff *skb) {
	__u8 version;
	struct address_key dst = {};
	if (bpf_skb_load_bytes_relative(skb, 0, &version, 1, BPF_HDR_START_NET)) return 2;
	if ((version >> 4) == 4) {
		__u8 header[20];
		if (bpf_skb_load_bytes_relative(skb, 0, header, sizeof(header), BPF_HDR_START_NET)) return 2;
		if ((version & 15) < 5) return 2;
		dst.family = 4;
		__u32 destination4;
		struct addr128 destination128;
		__builtin_memcpy(&destination4, header + 16, 4);
		v4_to_128(&destination128, destination4);
		__builtin_memcpy(dst.address, destination128.b, 16);
	} else if ((version >> 4) == 6) {
		__u8 header[40];
		if (bpf_skb_load_bytes_relative(skb, 0, header, sizeof(header), BPF_HDR_START_NET)) return 2;
		dst.family = 6;
		__builtin_memcpy(dst.address, header + 24, 16);
	} else return 2;
	if (bpf_map_lookup_elem(&denied, &dst)) return 2;
	struct destination_key key = { .prefixlen = 160, .family = dst.family };
	__builtin_memcpy(key.address, dst.address, 16);
	return bpf_map_lookup_elem(&destinations, &key) ? 0 : 2;
}
char LICENSE[] SEC("license") = "GPL";
