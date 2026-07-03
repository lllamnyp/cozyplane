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

#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

// Netfilter is entirely absent from the datapath: the fabric<->VPC bridge NAT
// (north-south) is done here in eBPF with a small connection table, not
// iptables. Packet offsets for an IPv4 frame with no IP options (ihl == 5).
#define ETH_HLEN     14
#define IP_HDR_OFF   ETH_HLEN
#define IP_CSUM_OFF  (IP_HDR_OFF + 10)
#define IP_SADDR_OFF (IP_HDR_OFF + 12)
#define IP_DADDR_OFF (IP_HDR_OFF + 16)
#define L4_OFF       (IP_HDR_OFF + 20)
#define L4_SPORT_OFF (L4_OFF + 0)
#define L4_DPORT_OFF (L4_OFF + 2)
#define TCP_CSUM_OFF (L4_OFF + 16)
#define UDP_CSUM_OFF (L4_OFF + 6)

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

// bridges: fabric IP (unique, from the node pod CIDR — network byte order) ->
// the pod's (network id, VPC IP). A plain /32 route sends the fabric IP to the
// pod's veth; to_pod NATs it fabric->vpc and masquerades the client to the
// gateway. Replaces the per-pod iptables DNAT + fwmark policy routing.
struct bridge_ep {
	__u32 net;
	__u32 vpc_ip; // network byte order
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bridge_ep);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} bridges SEC(".maps");

// floating: externally-routable IP (network order) -> the bound pod's {net, VPC
// IP} (reusing struct bridge_ep). The bridges map turned outward: instead of a
// fabric IP from the node pod CIDR, the key is a public address advertised
// (ARP/NDP) from the target pod's own node. from_uplink redirects an inbound
// packet into the pod's veth; to_pod DNATs public->VPC while *preserving* the
// external client's source, and from_pod reverses the reply. No masquerade, no
// gateway — this is the fabric bridge with source preservation.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct bridge_ep);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} floating SEC(".maps");

// float_ct records a floating-IP inbound connection so the reply can be reversed
// (VPC IP -> publicIP) without masquerading the client. It is what bounds the
// reverse-NAT to *reply* traffic: a pod's own-initiated egress from a
// floating-bound IP has no ct entry and is left alone (reversing that too would
// be the future Elastic-IP-egress upgrade). Keyed by the 5-tuple as the reply
// presents it; the value is the publicIP to restore.
struct float_ct_key {
	__u8 proto;
	__u8 pad[3];
	__u32 net;
	__u32 vpc_ip;      // network order
	__u32 client_ip;   // network order
	__u16 pod_port;    // network order
	__u16 client_port; // network order
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct float_ct_key);
	__type(value, __u32); // publicIP, network order
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} float_ct SEC(".maps");

// The bridge's own L4 connection table (no kernel conntrack). A north-south
// connection is masqueraded to 169.254.1.1:gw_port; the pod's reply is reversed
// by looking the gw_port back up. ct_fwd dedups retransmits to one gw_port.
struct ct_fwd_key {
	__u8 proto;
	__u8 pad[3];
	__u32 net;
	__u32 client_ip; // network order
	__u32 fabric_ip; // network order
	__u16 client_port; // network order
	__u16 pod_port;    // network order
};

struct ct_rev_key {
	__u8 proto;
	__u8 pad;
	__u16 gw_port;  // network order (the masqueraded source port)
	__u32 net;
	__u32 vpc_ip;   // network order
	__u16 pod_port; // network order
	__u16 pad2;
};

struct ct_rev_val {
	__u32 fabric_ip;   // network order
	__u32 client_ip;   // network order
	__u16 client_port; // network order
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ct_fwd_key);
	__type(value, __u16);
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_fwd SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ct_rev_key);
	__type(value, struct ct_rev_val);
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ct_rev SEC(".maps");

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

// ---- eBPF bridge NAT (north-south, no netfilter) -------------------------

// l4_ports reads the source/destination ports of a TCP/UDP packet with no IP
// options. For ICMP there are no ports, so the bridge only handles TCP/UDP.
static __always_inline int l4_ports(struct __sk_buff *skb, __u16 *sport, __u16 *dport)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + L4_OFF + 4 > data_end)
		return -1;
	__u16 *p = data + L4_OFF;
	*sport = p[0];
	*dport = p[1];
	return 0;
}

static __always_inline __u32 l4_csum_off(__u8 proto)
{
	return proto == IPPROTO_TCP ? TCP_CSUM_OFF : UDP_CSUM_OFF;
}

// nat_addr rewrites an IPv4 address in the header (at addr_off) and fixes the
// IP checksum and the L4 pseudo-header checksum. UDP with a zero checksum is
// left "no checksum" via BPF_F_MARK_MANGLED_0.
static __always_inline void nat_addr(struct __sk_buff *skb, __u8 proto, __u32 addr_off, __u32 old, __u32 new)
{
	__u64 flags = BPF_F_PSEUDO_HDR | 4;
	if (proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	bpf_l4_csum_replace(skb, l4_csum_off(proto), old, new, flags);
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old, new, 4);
	bpf_skb_store_bytes(skb, addr_off, &new, sizeof(new), 0);
}

// nat_port rewrites an L4 port (at port_off) and fixes the L4 checksum.
static __always_inline void nat_port(struct __sk_buff *skb, __u8 proto, __u32 port_off, __u16 old, __u16 new)
{
	__u64 flags = 2;
	if (proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	bpf_l4_csum_replace(skb, l4_csum_off(proto), old, new, flags);
	bpf_skb_store_bytes(skb, port_off, &new, sizeof(new), 0);
}

// alloc_gw_port picks a free masquerade port for a new north-south connection:
// the reverse-lookup key {proto, gw_port, net, vpc_ip, pod_port} must be unique,
// so probe (bounded) with BPF_NOEXIST — the insert that wins owns the port.
static __always_inline __u16 alloc_gw_port(__u8 proto, __u32 net, __u32 vpc_ip, __u16 pod_port,
					   __u32 fabric_ip, __u32 client_ip, __u16 client_port)
{
	__u32 base = bpf_get_prandom_u32();
	struct ct_rev_val rv = {
		.fabric_ip = fabric_ip,
		.client_ip = client_ip,
		.client_port = client_port,
	};
#pragma unroll
	for (int i = 0; i < 16; i++) {
		__u16 p = bpf_htons(1024 + ((base + i) % 64000));
		struct ct_rev_key rk = {
			.proto = proto,
			.gw_port = p,
			.net = net,
			.vpc_ip = vpc_ip,
			.pod_port = pod_port,
		};
		if (bpf_map_update_elem(&ct_rev, &rk, &rv, BPF_NOEXIST) == 0)
			return p;
	}
	return 0;
}

// bridge_forward is the north-south DNAT+SNAT, done in to_pod when a packet's
// destination is a fabric IP: fabric->VPC on the destination, client->gateway
// (169.254.1.1:gw_port) on the source. The pod sees only the gateway.
static __always_inline int bridge_forward(struct __sk_buff *skb, struct iphdr *ip, __u32 net, __u32 vpc_ip)
{
	if (ip->ihl != 5)
		return TC_ACT_SHOT;
	__u8 proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_SHOT; // bridge handles TCP/UDP; ICMP to a fabric IP is dropped
	__u16 cport, pport;
	if (l4_ports(skb, &cport, &pport) < 0)
		return TC_ACT_SHOT;
	__u32 client = ip->saddr, fabric = ip->daddr;

	struct ct_fwd_key fk = {
		.proto = proto,
		.net = net,
		.client_ip = client,
		.fabric_ip = fabric,
		.client_port = cport,
		.pod_port = pport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port(proto, net, vpc_ip, pport, fabric, client, cport);
		if (!gw_port)
			return TC_ACT_SHOT;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}

	nat_addr(skb, proto, IP_DADDR_OFF, fabric, vpc_ip);
	nat_addr(skb, proto, IP_SADDR_OFF, client, bpf_htonl(LINK_LOCAL_GW));
	nat_port(skb, proto, L4_SPORT_OFF, cport, gw_port);
	return TC_ACT_OK; // delivered to the pod (src is now the gateway)
}

// deliver_net0 sends a (default-network) packet to `dst`: same-node redirect,
// cross-node encap, or hand off to the kernel (local node / off-cluster). Used
// for a bridge reply after it has been un-NATed to fabric->client.
static __always_inline int deliver_net0(struct __sk_buff *skb, __u32 dst)
{
	struct endpoint *l = local_of(0, dst);
	if (l)
		return deliver_local(skb, l);
	__u32 *node_ip = remote_of(0, dst);
	if (node_ip)
		return encap(skb, 0, *node_ip, 0);
	return TC_ACT_OK;
}

// bridge_reverse is the reply un-NAT, done in from_pod when a VPC pod replies to
// the gateway (169.254.1.1): look the masquerade port back up, restore
// vpc->fabric on the source and gateway->client on the destination, then
// deliver the reply on the default network.
static __always_inline int bridge_reverse(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	if (ip->ihl != 5)
		return TC_ACT_OK;
	__u8 proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_OK;
	__u16 pport, gw_port;
	if (l4_ports(skb, &pport, &gw_port) < 0)
		return TC_ACT_OK;

	struct ct_rev_key rk = {
		.proto = proto,
		.gw_port = gw_port,
		.net = net,
		.vpc_ip = ip->saddr,
		.pod_port = pport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK; // no state: the kernel has no route for the gateway, drops it

	__u32 vpc_ip = ip->saddr;
	nat_addr(skb, proto, IP_SADDR_OFF, vpc_ip, rv->fabric_ip);
	nat_addr(skb, proto, IP_DADDR_OFF, bpf_htonl(LINK_LOCAL_GW), rv->client_ip);
	nat_port(skb, proto, L4_DPORT_OFF, gw_port, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

// floating_forward is the inbound half of a floating IP, done in to_pod when a
// packet's destination is a floating address: DNAT public->VPC on the
// destination while KEEPING the external client as the source (no masquerade),
// record the connection so the reply can be reversed, and deliver. Sanctioned
// north-south, like bridge_forward — the isolation check below does not run.
static __always_inline int floating_forward(struct __sk_buff *skb, struct iphdr *ip, __u32 net, __u32 vpc_ip)
{
	if (ip->ihl != 5)
		return TC_ACT_SHOT;
	__u8 proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_SHOT; // TCP/UDP only; ICMP to a floating IP is dropped (a follow-up)
	__u16 cport, pport;
	if (l4_ports(skb, &cport, &pport) < 0)
		return TC_ACT_SHOT;
	__u32 public_ip = ip->daddr;

	struct float_ct_key k = {
		.proto = proto,
		.net = net,
		.vpc_ip = vpc_ip,
		.client_ip = ip->saddr,
		.pod_port = pport,
		.client_port = cport,
	};
	bpf_map_update_elem(&float_ct, &k, &public_ip, BPF_ANY);

	nat_addr(skb, proto, IP_DADDR_OFF, public_ip, vpc_ip);
	return TC_ACT_OK; // delivered to the pod, the real client still its source
}

// floating_reverse is the reply half, done in from_pod when a VPC pod replies to
// the external client of one of its floating IPs. If a float_ct entry matches,
// SNAT the source VPC IP -> publicIP and report handled (1); the caller lets the
// kernel route it out the uplink. No match => 0: not a floating reply, fall
// through to the normal egress path.
static __always_inline int floating_reverse(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	if (ip->ihl != 5)
		return 0;
	__u8 proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return 0;
	__u16 pport, cport;
	if (l4_ports(skb, &pport, &cport) < 0)
		return 0;

	struct float_ct_key k = {
		.proto = proto,
		.net = net,
		.vpc_ip = ip->saddr,
		.client_ip = ip->daddr,
		.pod_port = pport,
		.client_port = cport,
	};
	__u32 *public_ip = bpf_map_lookup_elem(&float_ct, &k);
	if (!public_ip)
		return 0;

	nat_addr(skb, proto, IP_SADDR_OFF, ip->saddr, *public_ip);
	return 1;
}

// cozyplane_from_pod: source-side hook (pod egress). Enforces isolation, then
// delivers: same-node via redirect, cross-node via encap, off-VPC via gateway.
SEC("tc")
int cozyplane_from_pod(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	__u32 ifindex = skb->ifindex;
	__u32 srcnet = 0, is_gw = 0;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	if (sp) {
		srcnet = PORT_NET(*sp);
		is_gw = *sp & PORT_F_GATEWAY;
	}

	// A VPC pod's reply to the gateway (169.254.1.1) is the return half of the
	// north-south bridge: un-NAT it and deliver on the default network.
	if (ip->daddr == bpf_htonl(LINK_LOCAL_GW))
		return bridge_reverse(skb, ip, srcnet);
	// The destination's network, resolved within the source's scope: its own
	// CIDR or a peer's. Overlapping CIDRs in other VPCs are invisible here.
	__u32 dstnet = net_of(&networks, srcnet, ip->daddr);

	// A VPC pod replying to the external client of one of its floating IPs: the
	// destination is off-net (dstnet 0) but a float_ct match reverses the
	// source-preserving NAT (VPC IP -> publicIP); the kernel then routes it out
	// the uplink. Checked before isolation, which would send it to the gateway
	// or drop it.
	if (srcnet && !dstnet && floating_reverse(skb, ip, srcnet))
		return TC_ACT_OK;

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

	// Same-node north-south: a default-network packet to a local VPC pod's
	// fabric IP. Redirect into the pod's veth (to_pod does the DNAT), bypassing
	// the kernel FORWARD chain so no netfilter accept rule is needed.
	struct bridge_ep *be = bpf_map_lookup_elem(&bridges, &ip->daddr);
	if (be) {
		struct endpoint *l = local_of(be->net, be->vpc_ip);
		if (l)
			return deliver_local(skb, l);
	}

	return TC_ACT_OK; // off-cluster / node: kernel handles it
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

	// The forward half of the north-south bridge: a packet whose destination is
	// a fabric IP (routed here by the pod's /32) is DNATed to the VPC IP and its
	// client masqueraded to the gateway, then delivered — no isolation check
	// (this IS the sanctioned north-south path). Fabric IPs are unique, so the
	// lookup is unambiguous even under overlapping VPC CIDRs.
	struct bridge_ep *be = bpf_map_lookup_elem(&bridges, &ip->daddr);
	if (be)
		return bridge_forward(skb, ip, be->net, be->vpc_ip);

	// A floating IP: DNAT public->VPC, preserving the external client's source.
	// Also sanctioned north-south (no isolation check follows).
	struct bridge_ep *fe = bpf_map_lookup_elem(&floating, &ip->daddr);
	if (fe)
		return floating_forward(skb, ip, fe->net, fe->vpc_ip);

	// A masqueraded reply already carries the gateway source; allow it.
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

	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	__u32 gw = tk.tunnel_id & TUN_F_GATEWAY;
	__u32 vni = (__u32)tk.tunnel_id & ~TUN_F_GATEWAY;
	if (vni == cfg(CFG_VNI)) {
		// Default network. A cross-node north-south packet to a local VPC pod's
		// fabric IP is delivered to its veth here (to_pod does the DNAT),
		// bypassing the kernel FORWARD chain; everything else the kernel routes.
		struct bridge_ep *be = bpf_map_lookup_elem(&bridges, &ip->daddr);
		if (be) {
			struct endpoint *l = local_of(be->net, be->vpc_ip);
			if (l)
				return deliver_local(skb, l);
		}
		return TC_ACT_OK;
	}

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

// cozyplane_from_uplink: attached at the node uplink's ingress. It is the only
// entry point for off-cluster ingress. A packet destined to a floating IP
// advertised from this node is redirected into the target pod's veth, where
// to_pod's floating_forward DNATs public->VPC (source-preserving); everything
// else — overlay traffic, node traffic — is left to the kernel untouched, at the
// cost of one hash lookup. The target is always local: a floating IP is
// advertised only from the node hosting its pod.
SEC("tc")
int cozyplane_from_uplink(struct __sk_buff *skb)
{
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	struct bridge_ep *fe = bpf_map_lookup_elem(&floating, &ip->daddr);
	if (!fe)
		return TC_ACT_OK;
	struct endpoint *l = local_of(fe->net, fe->vpc_ip);
	if (!l)
		return TC_ACT_OK; // advertised here but the pod moved: leave it to the kernel
	return deliver_local(skb, l);
}
