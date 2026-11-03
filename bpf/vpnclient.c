// SPDX-License-Identifier: Apache-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "address128.h"

struct address_key { __u32 family; __u8 address[16]; };
struct destination_key { __u32 prefixlen; __u32 family; __u32 peer; __u8 address[16]; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct address_key);
	__type(value, __u32);
} sources SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 9216);
	__type(key, struct address_key);
	__type(value, __u32);
} denied SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, 65536);
	__type(key, struct destination_key);
	__type(value, __u32);
} destinations SEC(".maps");

// WireGuard is a layer-three device: skb starts with the IP header, no Ethernet.
SEC("tc") int vpn_client_ingress(struct __sk_buff *skb) {
	__u8 version;
	struct address_key src = {}, dst = {};
	if (bpf_skb_load_bytes(skb, 0, &version, 1)) return 2;
	if ((version >> 4) == 4) {
		__u8 header[20];
		if (bpf_skb_load_bytes(skb, 0, header, sizeof(header))) return 2;
		if ((version & 15) < 5) return 2;
		src.family = dst.family = 4;
		__u32 source4, destination4;
		struct addr128 source128, destination128;
		__builtin_memcpy(&source4, header + 12, 4);
		__builtin_memcpy(&destination4, header + 16, 4);
		v4_to_128(&source128, source4);
		v4_to_128(&destination128, destination4);
		__builtin_memcpy(src.address, source128.b, 16);
		__builtin_memcpy(dst.address, destination128.b, 16);
	} else if ((version >> 4) == 6) {
		__u8 header[40];
		if (bpf_skb_load_bytes(skb, 0, header, sizeof(header))) return 2;
		src.family = dst.family = 6;
		__builtin_memcpy(src.address, header + 8, 16);
		__builtin_memcpy(dst.address, header + 24, 16);
	} else return 2;
	__u32 *peer = bpf_map_lookup_elem(&sources, &src);
	if (!peer) return 2;
	// Always deny appliance and client addresses, even within authorized prefixes.
	if (bpf_map_lookup_elem(&denied, &dst)) return 2;
	struct destination_key key = { .prefixlen = 192, .family = dst.family, .peer = *peer };
	__builtin_memcpy(key.address, dst.address, 16);
	return bpf_map_lookup_elem(&destinations, &key) ? 0 : 2;
}
char LICENSE[] SEC("license") = "GPL";
