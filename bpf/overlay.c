// SPDX-License-Identifier: GPL-2.0
//
// cozyplane M0 datapath: default-network Geneve overlay.
//
// One tc program runs at the ingress of every pod's host-side veth (i.e. the
// pod's egress). It classifies the destination:
//
//   - destination in another node's pod CIDR  -> set the Geneve tunnel key
//     (default VNI, remote node IP from the `remotes` LPM map) and redirect to
//     the node's collect_metadata Geneve device for encap.
//   - anything else (local pod, node, off-cluster) -> TC_ACT_OK, let the kernel
//     route it. Local pods are reached by /32 routes; decapsulated packets
//     arriving on the Geneve device are likewise delivered by kernel routing.
//
// Only OTHER nodes' pod CIDRs are installed in `remotes`, so local traffic
// never matches and is never hairpinned through the tunnel.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Every node's Geneve device shares this fixed MAC. The encap path rewrites the
// inner Ethernet destination to it, so a decapsulated frame is addressed to the
// receiving node's own Geneve device (PACKET_HOST) and the kernel forwards it to
// the local pod — no receive-side program needed.
#define OVERLAY_DMAC { 0x02, 0xcf, 0xcf, 0xcf, 0xcf, 0xcf }

char __license[] SEC("license") = "GPL";

// LPM key: prefixlen + IPv4 address in network byte order.
struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

// remotes: other nodes' pod CIDRs -> that node's IP (host byte order value).
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} remotes SEC(".maps");

// config indices.
#define CFG_GENEVE_IFINDEX 0
#define CFG_VNI            1

// config: small array of node-local datapath parameters.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} params SEC(".maps");

static __always_inline __u32 cfg(__u32 idx)
{
	__u32 *v = bpf_map_lookup_elem(&params, &idx);
	return v ? *v : 0;
}

SEC("tc")
int cozyplane_from_pod(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	struct lpm_key key = {
		.prefixlen = 32,
		.addr = ip->daddr, // network byte order
	};
	__u32 *node_ip = bpf_map_lookup_elem(&remotes, &key);
	if (!node_ip)
		return TC_ACT_OK; // local pod / node / off-cluster: kernel routes it

	__u32 geneve_ifindex = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve_ifindex)
		return TC_ACT_OK;

	// Address the inner frame to the shared overlay MAC so the receiving
	// node's Geneve device accepts it as PACKET_HOST and forwards it.
	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;

	struct bpf_tunnel_key tkey = {};
	tkey.tunnel_id = cfg(CFG_VNI);
	tkey.remote_ipv4 = *node_ip; // host byte order, as the helper expects

	int ret = bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey),
					 BPF_F_ZERO_CSUM_TX);
	if (ret < 0)
		return TC_ACT_SHOT;

	return bpf_redirect(geneve_ifindex, 0);
}
