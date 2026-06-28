// SPDX-License-Identifier: GPL-2.0
//
// cozyplane datapath: per-network (VPC) Geneve overlay with placement-independent
// enforcement.
//
// Every packet is inspected at two hooks it always traverses regardless of pod
// placement:
//
//   - cozyplane_from_pod, at the ingress of a pod's host-side veth: all egress.
//   - cozyplane_to_pod, at the egress of a pod's host-side veth: all ingress
//     (every delivery path — same-node redirect, cross-node decap+route, the
//     node->pod bridge — leaves via the destination veth, so this hook sees it).
//
// Pod locality determines only *transport*, never whether a packet is checked:
// same-node pod-to-pod is delivered by an eBPF redirect (through to_pod), not a
// kernel-routing shortcut, so co-located pods cannot bypass policy.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define LINK_LOCAL_GW 0xA9FE0101 // 169.254.1.1 (host order)

// Shared Geneve MAC: the encap path rewrites the inner Ethernet destination to
// it so cross-node frames are PACKET_HOST on arrival and the kernel forwards
// them to the local pod (which then leaves via the pod veth -> to_pod).
#define OVERLAY_DMAC { 0x02, 0xcf, 0xcf, 0xcf, 0xcf, 0xcf }

char __license[] SEC("license") = "GPL";

struct lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

// A local pod endpoint: its host-side veth ifindex and pod-interface MAC.
struct endpoint {
	__u32 ifindex;
	__u8 mac[6];
	__u8 pad[2];
};

// remotes: pod IP / node pod CIDR -> remote node IP (host byte order value).
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} remotes SEC(".maps");

// networks: VPC CIDR -> network id (0 = default/system, absent here).
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

// locals: pod IP -> endpoint, for pods on this node (same-node redirect).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct endpoint);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} locals SEC(".maps");

#define CFG_GENEVE_IFINDEX 0
#define CFG_VNI            1

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

static __always_inline int parse_ipv4(struct __sk_buff *skb, struct iphdr **ip)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return -1;
	*ip = (void *)(eth + 1);
	if ((void *)(*ip + 1) > data_end)
		return -1;
	return 0;
}

// cozyplane_from_pod: source-side hook (pod egress). Enforces same-network
// isolation, then delivers: same-node via redirect, cross-node via encap.
SEC("tc")
int cozyplane_from_pod(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	// Replies to masqueraded node->pod (bridge) traffic go to the gateway; the
	// host stack/conntrack handles them.
	if (ip->daddr == bpf_htonl(LINK_LOCAL_GW))
		return TC_ACT_OK;

	__u32 ifindex = skb->ifindex;
	__u32 srcnet = 0;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	if (sp)
		srcnet = *sp;
	__u32 dstnet = net_of(&networks, ip->daddr);

	// Isolation: only same-network traffic is permitted (egress side).
	if (srcnet != dstnet)
		return TC_ACT_SHOT;

	// Same-node destination: redirect through the pod's veth egress (-> to_pod).
	// No kernel-routing shortcut, so the destination's ingress hook still runs.
	__u32 dip = ip->daddr;
	struct endpoint *l = bpf_map_lookup_elem(&locals, &dip);
	if (l) {
		if (bpf_skb_store_bytes(skb, 0, l->mac, sizeof(l->mac), 0) < 0)
			return TC_ACT_SHOT;
		return bpf_redirect(l->ifindex, 0);
	}

	// Remote destination: encapsulate.
	__u32 *node_ip = bpf_map_lookup_elem(&remotes, &(struct lpm_key){ .prefixlen = 32, .addr = ip->daddr });
	if (!node_ip)
		return TC_ACT_OK; // off-cluster / node / fabric-bridge: kernel handles it

	__u32 geneve_ifindex = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve_ifindex)
		return TC_ACT_OK;

	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;

	struct bpf_tunnel_key tkey = {};
	tkey.tunnel_id = srcnet ? srcnet : cfg(CFG_VNI);
	tkey.remote_ipv4 = *node_ip;
	if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(geneve_ifindex, 0);
}

// cozyplane_to_pod: destination-side hook (pod ingress). Every delivery path
// leaves via the destination veth, so this runs for same-node, cross-node, and
// node->pod traffic alike — the placement-independent point for ingress policy.
SEC("tc")
int cozyplane_to_pod(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	// node->pod bridge traffic is masqueraded from the gateway; allow it.
	if (ip->saddr == bpf_htonl(LINK_LOCAL_GW))
		return TC_ACT_OK;

	__u32 ifindex = skb->ifindex;
	__u32 dstnet = 0;
	__u32 *dp = bpf_map_lookup_elem(&ports, &ifindex);
	if (dp)
		dstnet = *dp;
	__u32 srcnet = net_of(&networks, ip->saddr);

	// Isolation: only same-network traffic may enter the pod (ingress side).
	if (srcnet != dstnet)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}
