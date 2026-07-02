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

// ports-map value layout: bit 31 flags a VPC egress-gateway leg; the low bits
// are the network id (VNIs stay far below 2^23, see TUN_F_GATEWAY).
#define PORT_F_GATEWAY (1u << 31)
#define PORT_NET(v) ((v) & ~PORT_F_GATEWAY)

// Gateway-forwarded traffic may carry an off-VPC source (the internet) into a
// tenant pod, which the ingress anti-spoof check would otherwise drop. It is
// blessed in-kernel only: same-node via skb->mark, cross-node via a flag bit
// inside the 24-bit Geneve VNI (so the receiving node can re-mark after decap).
// Tenants cannot forge either.
#define GW_MARK        0x100000  // bit 20: clear of kube-proxy (0x4000/0x8000) and Cilium magic
#define TUN_F_GATEWAY  (1 << 23) // top bit of the Geneve VNI; real VNIs are < 2^23

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

// A directed (source net, destination net) pair of peered networks.
struct peer_key {
	__u32 src_net;
	__u32 dst_net;
};

// peers: presence permits traffic from src_net to dst_net when the two differ.
// The agent writes both directions of a peering, so lookups never normalize.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct peer_key);
	__type(value, __u8);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} peers SEC(".maps");

// nets_allowed: same network, or two networks connected by a VPC peering.
static __always_inline int nets_allowed(__u32 src, __u32 dst)
{
	if (src == dst)
		return 1;
	struct peer_key key = { .src_net = src, .dst_net = dst };
	return bpf_map_lookup_elem(&peers, &key) != NULL;
}

// A VPC's egress gateway, from the agent's own point of view.
struct gw_entry {
	__u32 gw_ip;   // the gateway's VPC-leg address (network byte order, locals key)
	__u32 node_ip; // 0 if the gateway is on this node, else its node (host order)
};

// gateways: network id -> egress gateway. Off-VPC traffic from a pod in the
// network is delivered to the gateway instead of being dropped.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct gw_entry);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} gateways SEC(".maps");

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
	__u32 srcnet = 0, is_gw = 0;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	if (sp) {
		srcnet = PORT_NET(*sp);
		is_gw = *sp & PORT_F_GATEWAY;
	}
	__u32 dstnet = net_of(&networks, ip->daddr);

	// Isolation: same-network or explicitly peered traffic only (egress side) —
	// except a VPC pod's off-net traffic, which goes to the VPC's egress
	// gateway when one exists. Fabric->VPC and unpeered cross-VPC still drop.
	if (!nets_allowed(srcnet, dstnet)) {
		if (!srcnet || dstnet)
			return TC_ACT_SHOT;
		struct gw_entry *g = bpf_map_lookup_elem(&gateways, &srcnet);
		if (!g)
			return TC_ACT_SHOT; // closed island: no gateway for this VPC
		if (!g->node_ip) {
			// Gateway on this node: redirect into its VPC leg (-> to_pod).
			struct endpoint *gl = bpf_map_lookup_elem(&locals, &g->gw_ip);
			if (!gl)
				return TC_ACT_SHOT;
			if (bpf_skb_store_bytes(skb, 0, gl->mac, sizeof(gl->mac), 0) < 0)
				return TC_ACT_SHOT;
			return bpf_redirect(gl->ifindex, 0);
		}
		// Remote gateway: encapsulate toward its node; from_overlay there
		// hands the packet to the gateway's veth.
		__u32 geneve = cfg(CFG_GENEVE_IFINDEX);
		if (!geneve)
			return TC_ACT_SHOT;
		__u8 gmac[6] = OVERLAY_DMAC;
		if (bpf_skb_store_bytes(skb, 0, gmac, sizeof(gmac), 0) < 0)
			return TC_ACT_SHOT;
		struct bpf_tunnel_key gkey = {};
		gkey.tunnel_id = srcnet;
		gkey.remote_ipv4 = g->node_ip;
		if (bpf_skb_set_tunnel_key(skb, &gkey, sizeof(gkey), BPF_F_ZERO_CSUM_TX) < 0)
			return TC_ACT_SHOT;
		return bpf_redirect(geneve, 0);
	}

	// Same-node destination: redirect through the pod's veth egress (-> to_pod).
	// No kernel-routing shortcut, so the destination's ingress hook still runs.
	__u32 dip = ip->daddr;
	struct endpoint *l = bpf_map_lookup_elem(&locals, &dip);
	if (l) {
		// A gateway forwarding into its VPC may carry an off-VPC source (the
		// internet's reply); mark it so the destination's anti-spoof admits it.
		if (is_gw)
			skb->mark = GW_MARK;
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
	if (is_gw)
		tkey.tunnel_id |= TUN_F_GATEWAY; // re-marked by from_overlay after decap
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
		dstnet = PORT_NET(*dp);
	__u32 srcnet = net_of(&networks, ip->saddr);

	// Isolation: same-network or explicitly peered traffic only (ingress side).
	// The exception is gateway-forwarded traffic into a VPC pod: its source is
	// off-VPC (the internet, cluster DNS) so srcnet is 0, but it carries the
	// in-kernel gateway mark that tenants cannot forge.
	if (!nets_allowed(srcnet, dstnet)) {
		if (!(srcnet == 0 && dstnet != 0 && skb->mark == GW_MARK))
			return TC_ACT_SHOT;
	}

	return TC_ACT_OK;
}

// cozyplane_from_overlay: attached at the ingress of the Geneve device, where
// packets arrive already decapsulated but with the tunnel key still readable.
// Two gateway-related jobs; everything else passes to the kernel unchanged:
//
//  1. re-mark gateway-forwarded traffic (TUN_F_GATEWAY in the VNI) so the
//     destination pod's to_pod anti-spoof admits it (skb->mark does not
//     survive encapsulation, the VNI bit does);
//  2. deliver tenant->outside traffic to a gateway hosted on THIS node: its
//     destination is off-net, so the kernel has no /32 route for it — redirect
//     it into the gateway's VPC leg (through the gateway's to_pod hook).
SEC("tc")
int cozyplane_from_overlay(struct __sk_buff *skb)
{
	struct bpf_tunnel_key tk;
	if (bpf_skb_get_tunnel_key(skb, &tk, sizeof(tk), 0) < 0)
		return TC_ACT_OK;

	if (tk.tunnel_id & TUN_F_GATEWAY) {
		skb->mark = GW_MARK; // survives kernel forwarding to the local veth
		return TC_ACT_OK;    // dst is a VPC IP; the kernel's /32 route delivers
	}

	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;
	if (net_of(&networks, ip->daddr))
		return TC_ACT_OK; // in-VPC destination: kernel /32 delivery as usual

	__u32 vni = (__u32)tk.tunnel_id;
	struct gw_entry *g = bpf_map_lookup_elem(&gateways, &vni);
	if (!g || g->node_ip)
		return TC_ACT_OK; // no local gateway for this VNI (default net included)
	struct endpoint *l = bpf_map_lookup_elem(&locals, &g->gw_ip);
	if (!l)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, 0, l->mac, sizeof(l->mac), 0) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(l->ifindex, 0);
}
