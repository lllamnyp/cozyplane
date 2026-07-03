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

#define ETH_P_IP  0x0800
#define ETH_P_ARP 0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define LINK_LOCAL_GW 0xA9FE0101 // 169.254.1.1 (host order)

// ARP over Ethernet/IPv4 (the 28-byte payload after the Ethernet header).
struct arp_eth {
	__be16 htype;
	__be16 ptype;
	__u8   hlen;
	__u8   plen;
	__be16 op;
	__u8   sha[6]; // sender hardware address
	__be32 sip;    // sender IP
	__u8   tha[6]; // target hardware address
	__be32 tip;    // target IP
} __attribute__((packed));

// A 6-byte MAC in an 8-byte cell (the node uplink's, for the ARP responder).
struct cozy_mac {
	__u8 addr[6];
	__u8 pad[2];
};

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
#define ICMP_CSUM_OFF (L4_OFF + 2)
#define ICMP_ID_OFF   (L4_OFF + 4)
#define ICMP_ECHO_REPLY   0
#define ICMP_ECHO_REQUEST 8

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

// v4_of_128 reads the v4 address out of a NAT64-mapped 128-bit address (network
// order). Used only where the family is known to be v4.
static __always_inline __u32 v4_of_128(const struct addr128 *a)
{
	__u32 v4;
	__builtin_memcpy(&v4, &a->b[12], 4);
	return v4;
}

// Scoped LPM key: {network id, address}. Entries always fully specify the
// network id (prefixlen >= 32), so a lookup only ever matches within its own
// scope — the same address in two networks resolves independently. The address
// is 128-bit, so a fully-specified v4 entry has prefixlen 32 + 128 = 160.
struct lpm_key {
	__u32 prefixlen;
	__u32 scope_net;
	struct addr128 addr;
};

// A local pod, keyed by (network id, IP): overlapping VPCs may host the same IP.
struct local_key {
	__u32 net;
	struct addr128 ip;
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
	struct addr128 gw_ip; // the gateway's VPC-leg address (network byte order)
	__u32 node_ip;        // 0 if the gateway is on this node, else its node (host order)
	__u32 pad;
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
	__u32 pad;
	struct addr128 vpc_ip; // network byte order
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, struct bridge_ep);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} bridges SEC(".maps");

// floating: externally-routable IP (network order) -> the bound pod's {net, VPC
// IP} (reusing struct bridge_ep). The bridges map turned outward: instead of a
// fabric IP from the node pod CIDR, the key is a public address advertised
// (ARP/NDP) from the target pod's own node. from_uplink redirects an inbound
// packet into the pod's veth; to_pod DNATs public->VPC (keeping the client's
// source), and from_pod SNATs the pod's egress the other way. A true public IP:
// the same address inbound and outbound, no masquerade, no gateway, no conntrack.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, struct bridge_ep);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} floating SEC(".maps");

// floating_egress is the reverse of `floating`: (net, VPC IP) -> publicIP. A
// floating pod's off-net egress is SNATed from its public IP through this map,
// so a reply to an inbound connection and a connection the pod originates are
// the same stateless rewrite (no float_ct). Keyed like `locals`.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
	__type(value, struct addr128); // publicIP, network order
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} floating_egress SEC(".maps");

// internal holds the cluster-internal CIDRs (pod/service/node networks) at scope
// 0. A floating pod egresses straight out the uplink, bypassing the VPC gateway
// that would otherwise enforce the tenant->system boundary — so from_pod drops
// its traffic to any of these. Programmed by the agent.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(max_entries, 64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} internal SEC(".maps");

// The bridge's own L4 connection table (no kernel conntrack). A north-south
// connection is masqueraded to 169.254.1.1:gw_port; the pod's reply is reversed
// by looking the gw_port back up. ct_fwd dedups retransmits to one gw_port.
struct ct_fwd_key {
	__u8 proto;
	__u8 pad[3];
	__u32 net;
	struct addr128 client_ip; // network order
	struct addr128 fabric_ip; // network order
	__u16 client_port; // network order
	__u16 pod_port;    // network order
};

struct ct_rev_key {
	__u8 proto;
	__u8 pad;
	__u16 gw_port;  // network order (the masqueraded source port)
	__u32 net;
	struct addr128 vpc_ip; // network order
	__u16 pod_port; // network order
	__u16 pad2;
};

struct ct_rev_val {
	struct addr128 fabric_ip; // network order
	struct addr128 client_ip; // network order
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
#define CFG_UPLINK_IFINDEX 2

// floating_reverse returns this when the packet is not a floating-IP reply, so
// the caller falls through to the normal egress path.
#define FLOAT_MISS -1

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 4);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} params SEC(".maps");

// uplink_mac holds the node uplink's MAC (index 0), so from_uplink can put it in
// the floating-IP ARP replies it crafts. Written by the agent at attach time.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cozy_mac);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uplink_mac SEC(".maps");

static __always_inline __u32 cfg(__u32 idx)
{
	__u32 *v = bpf_map_lookup_elem(&params, &idx);
	return v ? *v : 0;
}

// A fully-specified scoped LPM lookup: 32 scope bits + 128 address bits.
#define LPM_FULL 160

// net_of resolves an address to a network id *as seen from* a scope network:
// the destination's net from the source's scope (from_pod), or the source's
// net from the destination's scope (to_pod). Absent => 0 (default/off-net).
static __always_inline __u32 net_of(void *map, __u32 scope, struct addr128 addr)
{
	struct lpm_key key = { .prefixlen = LPM_FULL, .scope_net = scope, .addr = addr };
	__u32 *id = bpf_map_lookup_elem(map, &key);
	return id ? *id : 0;
}

static __always_inline __u32 *remote_of(__u32 scope, struct addr128 addr)
{
	struct lpm_key key = { .prefixlen = LPM_FULL, .scope_net = scope, .addr = addr };
	return bpf_map_lookup_elem(&remotes, &key);
}

static __always_inline struct endpoint *local_of(__u32 net, struct addr128 ip)
{
	struct local_key key = { .net = net, .ip = ip };
	return bpf_map_lookup_elem(&locals, &key);
}

static __always_inline int is_internal(struct addr128 addr)
{
	struct lpm_key key = { .prefixlen = LPM_FULL, .scope_net = 0, .addr = addr };
	return bpf_map_lookup_elem(&internal, &key) != NULL;
}

static __always_inline struct bridge_ep *bridge_of(struct addr128 fabric)
{
	return bpf_map_lookup_elem(&bridges, &fabric);
}

static __always_inline struct bridge_ep *float_of(struct addr128 pub)
{
	return bpf_map_lookup_elem(&floating, &pub);
}

static __always_inline struct addr128 *floating_egress_of(__u32 net, struct addr128 vpc_ip)
{
	struct local_key key = { .net = net, .ip = vpc_ip };
	return bpf_map_lookup_elem(&floating_egress, &key);
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
// left "no checksum" via BPF_F_MARK_MANGLED_0. ICMP is special: its checksum
// does not cover the IP header, so an address change touches only the IP csum.
static __always_inline void nat_addr(struct __sk_buff *skb, __u8 proto, __u32 addr_off, __u32 old, __u32 new)
{
	if (proto != IPPROTO_ICMP) {
		__u64 flags = BPF_F_PSEUDO_HDR | 4;
		if (proto == IPPROTO_UDP)
			flags |= BPF_F_MARK_MANGLED_0;
		bpf_l4_csum_replace(skb, l4_csum_off(proto), old, new, flags);
	}
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

// icmp_echo reads an ICMP echo message's type and identifier (IPv4, no options).
// The identifier is what the bridge/floating conntrack keys on in place of an L4
// port. Returns -1 if the packet is too short to hold the 8-byte ICMP header.
static __always_inline int icmp_echo(struct __sk_buff *skb, __u8 *type, __u16 *id)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + L4_OFF + 8 > data_end)
		return -1;
	__u8 *t = data + L4_OFF;
	__u16 *idp = data + ICMP_ID_OFF;
	*type = *t;
	*id = *idp;
	return 0;
}

// nat_icmp_id rewrites the ICMP echo identifier and fixes the ICMP checksum
// (which has no pseudo-header — a plain 2-byte incremental update).
static __always_inline void nat_icmp_id(struct __sk_buff *skb, __u16 old, __u16 new)
{
	bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old, new, 2);
	bpf_skb_store_bytes(skb, ICMP_ID_OFF, &new, sizeof(new), 0);
}

// alloc_gw_port picks a free masquerade port for a new north-south connection:
// the reverse-lookup key {proto, gw_port, net, vpc_ip, pod_port} must be unique,
// so probe (bounded) with BPF_NOEXIST — the insert that wins owns the port.
static __always_inline __u16 alloc_gw_port(__u8 proto, __u32 net, struct addr128 vpc_ip, __u16 pod_port,
					   struct addr128 fabric_ip, struct addr128 client_ip, __u16 client_port)
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

// bridge_forward_icmp is the ICMP-echo forward half: the echo identifier stands
// in for the L4 port. A request is DNATed fabric->VPC, its client masqueraded to
// the gateway, and its id rewritten to a unique gw_id so replies demux (the
// client is hidden, so id is the only distinguishing field). Only echo requests
// cross; ICMP errors are dropped (PMTU is a follow-up).
static __always_inline int bridge_forward_icmp(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	__u8 type;
	__u16 id;
	if (icmp_echo(skb, &type, &id) < 0)
		return TC_ACT_SHOT;
	if (type != ICMP_ECHO_REQUEST)
		return TC_ACT_SHOT;
	__u32 client = ip->saddr, fabric = ip->daddr;
	struct addr128 client128, fabric128;
	v4_to_128(&client128, client);
	v4_to_128(&fabric128, fabric);

	struct ct_fwd_key fk = {
		.proto = IPPROTO_ICMP,
		.net = net,
		.client_ip = client128,
		.fabric_ip = fabric128,
		.client_port = id,
	};
	__u16 gw_id;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_id = *have;
	} else {
		gw_id = alloc_gw_port(IPPROTO_ICMP, net, vpc_ip, 0, fabric128, client128, id);
		if (!gw_id)
			return TC_ACT_SHOT;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
	}

	nat_addr(skb, IPPROTO_ICMP, IP_DADDR_OFF, fabric, v4_of_128(&vpc_ip));
	nat_addr(skb, IPPROTO_ICMP, IP_SADDR_OFF, client, bpf_htonl(LINK_LOCAL_GW));
	nat_icmp_id(skb, id, gw_id);
	return TC_ACT_OK;
}

// bridge_forward is the north-south DNAT+SNAT, done in to_pod when a packet's
// destination is a fabric IP: fabric->VPC on the destination, client->gateway
// (169.254.1.1:gw_port) on the source. The pod sees only the gateway.
static __always_inline int bridge_forward(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	if (ip->ihl != 5)
		return TC_ACT_SHOT;
	__u8 proto = ip->protocol;
	if (proto == IPPROTO_ICMP)
		return bridge_forward_icmp(skb, ip, net, vpc_ip);
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_SHOT; // bridge handles TCP/UDP/ICMP-echo; other ICMP is dropped
	__u16 cport, pport;
	if (l4_ports(skb, &cport, &pport) < 0)
		return TC_ACT_SHOT;
	__u32 client = ip->saddr, fabric = ip->daddr;
	struct addr128 client128, fabric128;
	v4_to_128(&client128, client);
	v4_to_128(&fabric128, fabric);

	struct ct_fwd_key fk = {
		.proto = proto,
		.net = net,
		.client_ip = client128,
		.fabric_ip = fabric128,
		.client_port = cport,
		.pod_port = pport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port(proto, net, vpc_ip, pport, fabric128, client128, cport);
		if (!gw_port)
			return TC_ACT_SHOT;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}

	nat_addr(skb, proto, IP_DADDR_OFF, fabric, v4_of_128(&vpc_ip));
	nat_addr(skb, proto, IP_SADDR_OFF, client, bpf_htonl(LINK_LOCAL_GW));
	nat_port(skb, proto, L4_SPORT_OFF, cport, gw_port);
	return TC_ACT_OK; // delivered to the pod (src is now the gateway)
}

// deliver_net0 sends a (default-network) packet to `dst`: same-node redirect,
// cross-node encap, or hand off to the kernel (local node / off-cluster). Used
// for a bridge reply after it has been un-NATed to fabric->client.
static __always_inline int deliver_net0(struct __sk_buff *skb, struct addr128 dst)
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
// bridge_reverse_icmp is the ICMP-echo reverse half: an echo reply the pod sends
// to the gateway carries the gw_id in its identifier; look it up, restore
// vpc->fabric and gateway->client, and rewrite the id back to the client's
// original before delivering on the default network.
static __always_inline int bridge_reverse_icmp(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	__u8 type;
	__u16 gw_id;
	if (icmp_echo(skb, &type, &gw_id) < 0)
		return TC_ACT_OK;
	if (type != ICMP_ECHO_REPLY)
		return TC_ACT_OK;
	struct addr128 vpc128;
	v4_to_128(&vpc128, ip->saddr);

	struct ct_rev_key rk = {
		.proto = IPPROTO_ICMP,
		.gw_port = gw_id,
		.net = net,
		.vpc_ip = vpc128,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK;

	nat_addr(skb, IPPROTO_ICMP, IP_SADDR_OFF, ip->saddr, v4_of_128(&rv->fabric_ip));
	nat_addr(skb, IPPROTO_ICMP, IP_DADDR_OFF, bpf_htonl(LINK_LOCAL_GW), v4_of_128(&rv->client_ip));
	nat_icmp_id(skb, gw_id, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

static __always_inline int bridge_reverse(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	if (ip->ihl != 5)
		return TC_ACT_OK;
	__u8 proto = ip->protocol;
	if (proto == IPPROTO_ICMP)
		return bridge_reverse_icmp(skb, ip, net);
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_OK;
	__u16 pport, gw_port;
	if (l4_ports(skb, &pport, &gw_port) < 0)
		return TC_ACT_OK;
	struct addr128 vpc128;
	v4_to_128(&vpc128, ip->saddr);

	struct ct_rev_key rk = {
		.proto = proto,
		.gw_port = gw_port,
		.net = net,
		.vpc_ip = vpc128,
		.pod_port = pport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK; // no state: the kernel has no route for the gateway, drops it

	nat_addr(skb, proto, IP_SADDR_OFF, ip->saddr, v4_of_128(&rv->fabric_ip));
	nat_addr(skb, proto, IP_DADDR_OFF, bpf_htonl(LINK_LOCAL_GW), v4_of_128(&rv->client_ip));
	nat_port(skb, proto, L4_DPORT_OFF, gw_port, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

// floating_forward is the inbound half of a floating IP, done in to_pod when a
// packet's destination is a floating address: a stateless DNAT public->VPC that
// keeps the external client as the source (no masquerade). Sanctioned
// north-south, like bridge_forward — the isolation check below does not run.
// TCP, UDP, and ICMP echo (request or reply — a reply is the return half of the
// pod's own outbound ping); other ICMP is dropped.
static __always_inline int floating_forward(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	if (ip->ihl != 5)
		return TC_ACT_SHOT;
	__u8 proto = ip->protocol;
	if (proto == IPPROTO_ICMP) {
		__u8 type;
		__u16 id;
		if (icmp_echo(skb, &type, &id) < 0)
			return TC_ACT_SHOT;
		if (type != ICMP_ECHO_REQUEST && type != ICMP_ECHO_REPLY)
			return TC_ACT_SHOT;
	} else if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		return TC_ACT_SHOT;
	}
	nat_addr(skb, proto, IP_DADDR_OFF, ip->daddr, v4_of_128(&vpc_ip));
	return TC_ACT_OK; // delivered to the pod, the real client still its source
}

// floating_egress_snat is the outbound half, done in from_pod for a floating
// pod's *internet*-bound traffic: SNAT source VPC->public and redirect it out
// the uplink (kernel neighbour resolution for the destination — which also
// sidesteps rp_filter and the FORWARD chain). It serves both a reply to an
// inbound connection and a connection the pod originates: a true public IP, the
// same address in both directions, stateless.
//
// Cluster-internal destinations are left to the normal path (FLOAT_MISS): they
// fall through to the VPC gateway, which proxies cluster DNS and denies the rest
// exactly as it does for a non-floating pod — so a floating pod keeps the same
// internal reachability, and simply *also* egresses the internet from its public
// IP. FLOAT_MISS likewise when the pod has no floating IP. ICMP needs no id
// rewrite (the identifier is the pod's own).
static __always_inline int floating_egress_snat(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	if (ip->ihl != 5)
		return FLOAT_MISS;
	__u8 proto = ip->protocol;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMP)
		return FLOAT_MISS;
	struct addr128 src128, dst128;
	v4_to_128(&src128, ip->saddr);
	v4_to_128(&dst128, ip->daddr);
	struct addr128 *public_ip = floating_egress_of(net, src128);
	if (!public_ip)
		return FLOAT_MISS;
	if (is_internal(dst128))
		return FLOAT_MISS; // internal: let the gateway proxy DNS / deny the rest
	__u32 uplink = cfg(CFG_UPLINK_IFINDEX);
	if (!uplink)
		return FLOAT_MISS;
	nat_addr(skb, proto, IP_SADDR_OFF, ip->saddr, v4_of_128(public_ip));
	return bpf_redirect_neigh(uplink, NULL, 0, 0);
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
	struct addr128 d128;
	v4_to_128(&d128, ip->daddr);
	// The destination's network, resolved within the source's scope: its own
	// CIDR or a peer's. Overlapping CIDRs in other VPCs are invisible here.
	__u32 dstnet = net_of(&networks, srcnet, d128);

	// Off-net traffic from a floating pod egresses from its public IP (both its
	// replies and the connections it originates): SNAT VPC->public and redirect
	// out the uplink, dropping cluster-internal destinations. Checked before
	// isolation, which would otherwise send it to the gateway or drop it.
	if (srcnet && !dstnet) {
		int fr = floating_egress_snat(skb, ip, srcnet);
		if (fr != FLOAT_MISS)
			return fr;
		// The miss path leaves the packet untouched, but floating_egress_snat's
		// inlined body writes the packet on its hit path, so the verifier treats
		// `ip` as invalidated here — re-derive it.
		if (parse_ipv4(skb, &ip) < 0)
			return TC_ACT_OK;
	}

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
	struct endpoint *l = local_of(dstnet, d128);
	if (l) {
		// A gateway forwarding into its VPC may carry an off-VPC source (the
		// internet's reply); mark it so the destination's anti-spoof admits it.
		if (is_gw)
			skb->mark = GW_MARK;
		return deliver_local(skb, l);
	}

	// Remote destination in the same network (or a peer): encapsulate.
	__u32 *node_ip = remote_of(dstnet, d128);
	if (node_ip)
		return encap(skb, dstnet, *node_ip, is_gw);

	// Same-node north-south: a default-network packet to a local VPC pod's
	// fabric IP. Redirect into the pod's veth (to_pod does the DNAT), bypassing
	// the kernel FORWARD chain so no netfilter accept rule is needed.
	struct bridge_ep *be = bridge_of(d128);
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
	struct addr128 d128, s128;
	v4_to_128(&d128, ip->daddr);
	v4_to_128(&s128, ip->saddr);

	struct bridge_ep *be = bridge_of(d128);
	if (be)
		return bridge_forward(skb, ip, be->net, be->vpc_ip);

	// A floating IP: DNAT public->VPC, preserving the external client's source.
	// Also sanctioned north-south (no isolation check follows).
	struct bridge_ep *fe = float_of(d128);
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
	__u32 srcnet = net_of(&networks, dstnet, s128);

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
	struct addr128 d128;
	v4_to_128(&d128, ip->daddr);
	if (vni == cfg(CFG_VNI)) {
		// Default network. A cross-node north-south packet to a local VPC pod's
		// fabric IP is delivered to its veth here (to_pod does the DNAT),
		// bypassing the kernel FORWARD chain; everything else the kernel routes.
		struct bridge_ep *be = bridge_of(d128);
		if (be) {
			struct endpoint *l = local_of(be->net, be->vpc_ip);
			if (l)
				return deliver_local(skb, l);
		}
		return TC_ACT_OK;
	}

	// A local pod in this VPC (intra-VPC, peered, or a gateway->tenant reply).
	struct endpoint *ep = local_of(vni, d128);
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

// floating_arp answers ARP for a floating IP whose target pod is local: it is
// how the address is advertised, with no host-side /32 or proxy_arp. An ARP
// request for such an IP is rewritten in place into a reply — sender = this
// node's uplink MAC + the floating IP, target = the requester — and reflected
// back out the uplink. Returns a TC action when handled, or FLOAT_MISS to let
// the caller fall through (not an ARP request for one of our floating IPs).
static __always_inline int floating_arp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return FLOAT_MISS;
	struct arp_eth *arp = (void *)(eth + 1);
	if ((void *)(arp + 1) > data_end)
		return FLOAT_MISS;
	if (arp->op != bpf_htons(ARPOP_REQUEST))
		return FLOAT_MISS;

	// ARP is v4-only (v6 floating IPs advertise via NDP, a later phase).
	struct addr128 tip128;
	v4_to_128(&tip128, arp->tip);
	struct bridge_ep *fe = float_of(tip128);
	if (!fe)
		return FLOAT_MISS;
	if (!local_of(fe->net, fe->vpc_ip))
		return FLOAT_MISS; // not our pod (shouldn't be programmed here otherwise)

	__u32 zero = 0;
	struct cozy_mac *node = bpf_map_lookup_elem(&uplink_mac, &zero);
	if (!node)
		return FLOAT_MISS;

	__u8 req_mac[6];
	__builtin_memcpy(req_mac, arp->sha, 6);
	__be32 req_ip = arp->sip;
	__be32 fip = arp->tip;

	arp->op = bpf_htons(ARPOP_REPLY);
	__builtin_memcpy(arp->sha, node->addr, 6);
	arp->sip = fip;
	__builtin_memcpy(arp->tha, req_mac, 6);
	arp->tip = req_ip;
	__builtin_memcpy(eth->h_dest, req_mac, 6);
	__builtin_memcpy(eth->h_source, node->addr, 6);

	return bpf_redirect(skb->ifindex, 0); // back out the uplink to the requester
}

// cozyplane_from_uplink: attached at the node uplink's ingress. It is the only
// entry point for off-cluster ingress, and it also advertises floating IPs by
// answering ARP for them (floating_arp). A packet destined to a floating IP with
// a live local pod is redirected into that pod's veth, where to_pod's
// floating_forward DNATs public->VPC (source-preserving); everything else —
// overlay traffic, node traffic — is left to the kernel untouched, at the cost of
// one hash lookup. The target is always local: a floating IP is advertised only
// from the node hosting its pod.
SEC("tc")
int cozyplane_from_uplink(struct __sk_buff *skb)
{
	int arp = floating_arp(skb);
	if (arp != FLOAT_MISS)
		return arp;

	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0)
		return TC_ACT_OK;

	struct addr128 d128;
	v4_to_128(&d128, ip->daddr);
	struct bridge_ep *fe = float_of(d128);
	if (!fe)
		return TC_ACT_OK;
	struct endpoint *l = local_of(fe->net, fe->vpc_ip);
	if (!l)
		return TC_ACT_OK; // advertised here but the pod moved: leave it to the kernel
	return deliver_local(skb, l);
}
