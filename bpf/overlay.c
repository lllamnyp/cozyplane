// SPDX-License-Identifier: GPL-2.0
//
// cozyplane M1 datapath: per-network (VPC) Geneve overlay with isolation.
//
// One tc program runs at the ingress of every pod's host-side veth (the pod's
// egress) and at the node uplink's egress (host-originated traffic). For each
// IPv4 packet it:
//
//   1. determines the source network from the `ports` map (veth ifindex -> net
//      id; absent => 0, the default/system network), and the destination
//      network from the `networks` LPM (dst CIDR -> net id; absent => 0);
//   2. drops the packet if the two networks differ (tenant isolation: a VPC pod
//      reaches only its own VPC; the default network reaches only itself);
//   3. if the destination is on another node (`remotes` LPM, keyed by IP), sets
//      the Geneve tunnel key (net id as VNI, remote node IP) and redirects to
//      the Geneve device for encap; otherwise lets the kernel route it locally.
//
// M1 requires VPC CIDRs to be unique cluster-wide, so routing/delivery can stay
// keyed on IP (kernel routing + the shared-MAC decap trick from M0). Overlapping
// CIDRs arrive with the dual-address bridge milestone.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// Every node's Geneve device shares this fixed MAC. The encap path rewrites the
// inner Ethernet destination to it, so a decapsulated frame is addressed to the
// receiving node's own Geneve device (PACKET_HOST) and the kernel forwards it.
#define OVERLAY_DMAC { 0x02, 0xcf, 0xcf, 0xcf, 0xcf, 0xcf }

char __license[] SEC("license") = "GPL";

// LPM key: prefixlen + IPv4 address in network byte order.
struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

// remotes: pod IP / node pod CIDR -> that node's IP (host byte order value).
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} remotes SEC(".maps");

// networks: VPC CIDR -> network id. The default/system network is id 0 and is
// not present here.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} networks SEC(".maps");

// ports: host-side veth ifindex -> network id of the attached pod.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ports SEC(".maps");

#define CFG_GENEVE_IFINDEX 0
#define CFG_VNI            1

// params: small array of node-local datapath parameters.
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

static __always_inline __u32 net_of(void *map, __u32 addr)
{
	struct lpm_key key = { .prefixlen = 32, .addr = addr };
	__u32 *id = bpf_map_lookup_elem(map, &key);
	return id ? *id : 0;
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

	// Traffic to the link-local gateway (169.254.1.1) — e.g. a pod's reply to
	// masqueraded node->pod (bridge) traffic — is handled by the host stack and
	// conntrack: never isolated, never encapsulated.
	if (ip->daddr == bpf_htonl(0xA9FE0101))
		return TC_ACT_OK;

	// Source network: the attached veth's net id (0 = default/system, also for
	// host-originated traffic on the uplink, whose ifindex isn't in `ports`).
	__u32 ifindex = skb->ifindex;
	__u32 srcnet = 0;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	if (sp)
		srcnet = *sp;

	// Destination network from its CIDR (0 = default / off-cluster).
	__u32 dstnet = net_of(&networks, ip->daddr);

	// Isolation: only same-network traffic is permitted.
	if (srcnet != dstnet)
		return TC_ACT_SHOT;

	struct lpm_key key = { .prefixlen = 32, .addr = ip->daddr };
	__u32 *node_ip = bpf_map_lookup_elem(&remotes, &key);
	if (!node_ip)
		return TC_ACT_OK; // local or off-cluster: kernel routes it

	__u32 geneve_ifindex = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve_ifindex)
		return TC_ACT_OK;

	// Address the inner frame to the shared overlay MAC so the receiving
	// node's Geneve device accepts it as PACKET_HOST and forwards it.
	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;

	struct bpf_tunnel_key tkey = {};
	tkey.tunnel_id = srcnet ? srcnet : cfg(CFG_VNI);
	tkey.remote_ipv4 = *node_ip; // host byte order, as the helper expects

	if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0)
		return TC_ACT_SHOT;

	return bpf_redirect(geneve_ifindex, 0);
}
