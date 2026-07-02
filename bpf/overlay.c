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
//     (every delivery path — same-node redirect, cross-node decap+redirect, the
//     node->pod bridge — leaves via the destination veth, so this hook sees it).
//
// Pod locality determines only *transport*, never whether a packet is checked:
// same-node pod-to-pod is delivered by an eBPF redirect (through to_pod), not a
// kernel-routing shortcut, so co-located pods cannot bypass policy.
//
// Everything a tenant pod addresses is keyed by (network id, IP), never by IP
// alone, so two VPCs may use overlapping CIDRs: their pods can share an IP and
// still be told apart by the network scope. The default/system network (id 0,
// tunnel VNI = the configured default) keeps unique cluster-pod-CIDR addresses
// and is delivered by the kernel (the fabric bridge relies on that), so only
// genuine VPC overlay traffic takes the eBPF delivery path below.

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
// it so a decapped default-network frame is PACKET_HOST on arrival and the
// kernel forwards it to the local pod. VPC frames are redirected by
// from_overlay before the kernel routes them, so the MAC is immaterial there.
#define OVERLAY_DMAC { 0x02, 0xcf, 0xcf, 0xcf, 0xcf, 0xcf }

char __license[] SEC("license") = "GPL";

// Scoped LPM key: {network id, address}. Entries always fully specify the
// network id (prefixlen >= 32), so a lookup only ever matches within its own
// scope — the same address in two networks resolves independently.
struct lpm_key {
	__u32 prefixlen;
	__u32 scope_net;
	__u32 addr;
};

// A local pod, keyed by (network id, IP): overlapping VPCs may host the same IP.
struct local_key {
	__u32 net;
	__u32 ip;
};

// A local pod endpoint: its host-side veth ifindex and pod-interface MAC.
struct endpoint {
	__u32 ifindex;
	__u8 mac[6];
	__u8 pad[2];
};

// remotes: (scope net, dst IP / node pod CIDR) -> remote node IP (host order).
// Node pod CIDRs live at scope 0 (default network); VPC pod /32s at scope=VNI.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} remotes SEC(".maps");

// networks: (scope net, CIDR) -> destination net id. A VPC's own CIDR is stored
// at its own scope; a peering adds each side's CIDR under the other's scope.
// Absent => 0 (the default network).
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

// locals: (network id, pod IP) -> endpoint, for pods on this node.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
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
	__u32 gw_ip;   // the gateway's VPC-leg address (network byte order)
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

// net_of resolves an address to a network id *as seen from* a scope network:
// the destination's net from the source's scope (from_pod), or the source's
// net from the destination's scope (to_pod). Absent => 0 (default/off-net).
static __always_inline __u32 net_of(void *map, __u32 scope, __u32 addr)
{
	struct lpm_key key = { .prefixlen = 64, .scope_net = scope, .addr = addr };
	__u32 *id = bpf_map_lookup_elem(map, &key);
	return id ? *id : 0;
}

static __always_inline __u32 *remote_of(__u32 scope, __u32 addr)
{
	struct lpm_key key = { .prefixlen = 64, .scope_net = scope, .addr = addr };
	return bpf_map_lookup_elem(&remotes, &key);
}

static __always_inline struct endpoint *local_of(__u32 net, __u32 ip)
{
	struct local_key key = { .net = net, .ip = ip };
	return bpf_map_lookup_elem(&locals, &key);
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

// deliver_local redirects the frame into a local pod's veth (through to_pod).
static __always_inline int deliver_local(struct __sk_buff *skb, struct endpoint *ep)
{
	if (bpf_skb_store_bytes(skb, 0, ep->mac, sizeof(ep->mac), 0) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(ep->ifindex, 0);
}

// encap sets the Geneve tunnel key and redirects to the Geneve device. tunnel_id
// is the destination network so the receiver can demux by VNI; the gateway flag
// rides the top VNI bit for the receiver's anti-spoof re-mark.
static __always_inline int encap(struct __sk_buff *skb, __u32 dstnet, __u32 node_ip, __u32 gw)
{
	__u32 geneve = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve)
		return TC_ACT_OK;
	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;
	struct bpf_tunnel_key tkey = {};
	tkey.tunnel_id = dstnet ? dstnet : cfg(CFG_VNI);
	if (gw)
		tkey.tunnel_id |= TUN_F_GATEWAY;
	tkey.remote_ipv4 = node_ip;
	if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(geneve, 0);
}

// cozyplane_from_pod: source-side hook (pod egress). Enforces isolation, then
// delivers: same-node via redirect, cross-node via encap, off-VPC via gateway.
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
	// The destination's network, resolved within the source's scope: its own
	// CIDR or a peer's. Overlapping CIDRs in other VPCs are invisible here.
	__u32 dstnet = net_of(&networks, srcnet, ip->daddr);

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
			struct endpoint *gl = local_of(srcnet, g->gw_ip);
			if (!gl)
				return TC_ACT_SHOT;
			return deliver_local(skb, gl);
		}
		// Remote gateway: encapsulate toward its node under the VPC's VNI;
		// from_overlay there hands the packet to the gateway's veth.
		return encap(skb, srcnet, g->node_ip, 0);
	}

	// Same-node destination: redirect through the pod's veth egress (-> to_pod).
	struct endpoint *l = local_of(dstnet, ip->daddr);
	if (l) {
		// A gateway forwarding into its VPC may carry an off-VPC source (the
		// internet's reply); mark it so the destination's anti-spoof admits it.
		if (is_gw)
			skb->mark = GW_MARK;
		return deliver_local(skb, l);
	}

	// Remote destination in the same network (or a peer): encapsulate.
	__u32 *node_ip = remote_of(dstnet, ip->daddr);
	if (node_ip)
		return encap(skb, dstnet, *node_ip, is_gw);

	return TC_ACT_OK; // off-cluster / node / fabric-bridge: kernel handles it
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
	// Recover the source's network from the destination's scope (symmetric to
	// from_pod): its own CIDR or a peer's under this pod's network.
	__u32 srcnet = net_of(&networks, dstnet, ip->saddr);

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
// For VPC traffic it *is* the delivery step: the kernel cannot route two
// overlapping VPC IPs, so we demux by the tunnel VNI and redirect into the
// matching local pod (or the local gateway). Default-network traffic
// (tunnel VNI = the configured default) is left to the kernel — the fabric
// bridge and default pods keep their unique-IP routing.
SEC("tc")
int cozyplane_from_overlay(struct __sk_buff *skb)
{
	struct bpf_tunnel_key tk;
	if (bpf_skb_get_tunnel_key(skb, &tk, sizeof(tk), 0) < 0)
		return TC_ACT_OK;

	__u32 gw = tk.tunnel_id & TUN_F_GATEWAY;
	__u32 vni = (__u32)tk.tunnel_id & ~TUN_F_GATEWAY;
	if (vni == cfg(CFG_VNI))
		return TC_ACT_OK; // default network: kernel routes (fabric bridge etc.)

	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	// A local pod in this VPC (intra-VPC, peered, or a gateway->tenant reply).
	struct endpoint *ep = local_of(vni, ip->daddr);
	if (ep) {
		if (gw)
			skb->mark = GW_MARK;
		return deliver_local(skb, ep);
	}

	// Not a local pod: tenant->outside traffic for a gateway hosted here.
	struct gw_entry *g = bpf_map_lookup_elem(&gateways, &vni);
	if (g && !g->node_ip) {
		struct endpoint *gep = local_of(vni, g->gw_ip);
		if (gep)
			return deliver_local(skb, gep);
	}
	return TC_ACT_OK;
}
