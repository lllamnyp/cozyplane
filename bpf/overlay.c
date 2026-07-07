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

#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP  0x0806
#define ARPOP_REQUEST 1
#define ARPOP_REPLY   2
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define LINK_LOCAL_GW 0xA9FE0101 // 169.254.1.1 (host order)

// The hairpin loopback: when a ServiceVIP backend dials its own service and
// selects itself, the client half is SNAT'd to this address so the two
// directions of the flow stay distinguishable inside one pod. Never routed —
// the whole flow lives on one veth (out and straight back in).
#define SVC_LOOPBACK 0xA9FE2A01 // 169.254.42.1 (host order)
#define SVC_LOOPBACK6 { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x2a, 0x01 } }

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

#define IPPROTO_ICMP   1
#define IPPROTO_TCP    6
#define IPPROTO_UDP    17
#define IPPROTO_ICMPV6 58

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
#define ICMP_DEST_UNREACH  3
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAM_PROB    12

// An ICMPv4 error embeds the original packet: its IPv4 header + at least the
// first 8 L4 bytes, right after the 8-byte ICMP header. Offsets assume an
// options-free embedded header (checked: version/ihl must read 0x45).
#define EMB_IP_OFF       (L4_OFF + 8)
#define EMB_IP_PROTO_OFF (EMB_IP_OFF + 9)
#define EMB_IP_CSUM_OFF  (EMB_IP_OFF + 10)
#define EMB_SADDR_OFF    (EMB_IP_OFF + 12)
#define EMB_DADDR_OFF    (EMB_IP_OFF + 16)
#define EMB_L4_OFF       (EMB_IP_OFF + 20)
#define EMB_SPORT_OFF    (EMB_L4_OFF)
#define EMB_DPORT_OFF    (EMB_L4_OFF + 2)
#define EMB_UDP_CSUM_OFF (EMB_L4_OFF + 6)

// IPv6 fabric-bridge offsets: a fixed 40-byte header (no extension headers on
// the inner VPC traffic the bridge handles). No L3 checksum exists in IPv6, so a
// v6 address rewrite touches only the L4 (pseudo-header) checksum — but over all
// 16 bytes, and for ICMPv6 too (unlike ICMPv4, whose csum ignores the IP header).
#define IP6_HDR_OFF   ETH_HLEN
#define IP6_SADDR_OFF (IP6_HDR_OFF + 8)
#define IP6_DADDR_OFF (IP6_HDR_OFF + 24)
#define L4_OFF6       (IP6_HDR_OFF + 40)
#define L4_SPORT_OFF6 (L4_OFF6 + 0)
#define L4_DPORT_OFF6 (L4_OFF6 + 2)
#define TCP_CSUM_OFF6  (L4_OFF6 + 16)
#define UDP_CSUM_OFF6  (L4_OFF6 + 6)
#define ICMP6_CSUM_OFF (L4_OFF6 + 2)
#define ICMP6_ID_OFF   (L4_OFF6 + 4)
#define ICMP6_ECHO_REQUEST 128
#define ICMP6_ECHO_REPLY   129

#define ICMP6_NEIGH_SOLICIT 135
#define ICMP6_NEIGH_ADVERT  136
// Neighbor Solicitation layout (fixed IPv6 header assumed): 4-byte
// flags/reserved word, 16-byte target, then options (source link-layer
// address, type 1, 8 bytes, when present).
#define NDP_FLAGS_OFF  (L4_OFF6 + 4)
#define NDP_TARGET_OFF (L4_OFF6 + 8)
#define NDP_OPT_OFF    (L4_OFF6 + 24)
#define NDP_OPT_MAC_OFF (NDP_OPT_OFF + 2)

// An ICMPv6 error (type < 128, RFC 4443) embeds the original packet after the
// 8-byte ICMPv6 header: a fixed 40-byte IPv6 header (extension headers are not
// handled — nexthdr must read TCP/UDP directly) + at least 8 L4 bytes.
#define EMB6_IP_OFF       (L4_OFF6 + 8)
#define EMB6_NEXTHDR_OFF  (EMB6_IP_OFF + 6)
#define EMB6_SADDR_OFF    (EMB6_IP_OFF + 8)
#define EMB6_DADDR_OFF    (EMB6_IP_OFF + 24)
#define EMB6_L4_OFF       (EMB6_IP_OFF + 40)
#define EMB6_SPORT_OFF    (EMB6_L4_OFF)
#define EMB6_DPORT_OFF    (EMB6_L4_OFF + 2)
#define EMB6_UDP_CSUM_OFF (EMB6_L4_OFF + 6)

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
#define SG_OK          0x200000  // bit 21: from_overlay already enforced security groups (TLV)
#define TUN_F_GATEWAY  (1 << 23) // top bit of the Geneve VNI; real VNIs are < 2^23

// Security-group identity TLV (docs/security-groups.md, v2 stage B). The source
// node stamps the source pod's authoritative {net, group bitmap} into a Geneve
// option on cross-node encap, so a destination trusts the source's identity
// across a VPC-peering trust boundary instead of inferring it from a spoofable
// source IP. Read in from_overlay (the only place tunnel metadata is visible).
#define SG_OPT_CLASS 0xC0FE // cozyplane private Geneve option class
#define SG_OPT_TYPE  1
struct sg_geneve_opt {
	__be16 opt_class;
	__u8 type;
	__u8 length;   // in 4-byte units of opt_data: 12 bytes -> 3
	__u32 src_net; // host order (both ends are cozyplane)
	__u64 srcmap;
} __attribute__((packed));

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

// v6_link_scoped reports whether a v6 address is link-local (fe80::/10) or
// multicast (ff00::/8). Such traffic — neighbour discovery (NS/NA) to the pod's
// on-link gateway, router solicitations, etc. — never leaves the pod<->host-veth
// link, so it bypasses VPC overlay delivery and the isolation check: the kernel
// and the host veth (which owns the gateway address) handle it, exactly as the
// kernel handles v4 ARP (which, not being an IP packet, never reaches these
// hooks at all). Without this, a pod's NS to its gateway's solicited-node
// multicast looks like off-net VPC egress and the isolation check drops it.
static __always_inline int v6_link_scoped(const struct addr128 *a)
{
	if (a->b[0] == 0xff) // ff00::/8 multicast
		return 1;
	if (a->b[0] == 0xfe && (a->b[1] & 0xc0) == 0x80) // fe80::/10 link-local
		return 1;
	return 0;
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

// masq_srcs holds the source CIDRs (the cluster pod supernet) whose
// off-cluster egress the datapath masquerades to the node address at the
// uplink (#10 — the eBPF replacement for the iptables MASQUERADE rule).
// Empty unless the agent runs --masquerade=bpf.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(max_entries, 16);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} masq_srcs SEC(".maps");

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
#define CFG_NODE_IP        3 // v4, network order in the low 32 bits
#define CFG_RESOLVER_PORT  4 // host order; 0 disables VPC DNS steering

// bpf-masquerade port range for cluster-egress SNAT (#10): disjoint from the
// host ephemeral range (32768+) so a reverse lookup can never capture the
// node's own connections, and below the default NodePort range (30000+) so an
// allocated port never collides with a kube-proxy NodePort.
#define MASQ_PORT_BASE 16384
#define MASQ_PORT_SPAN 13616

// floating_reverse returns this when the packet is not a floating-IP reply, so
// the caller falls through to the normal egress path.
#define FLOAT_MISS -1

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 8);
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

// node_ip6 holds the node's v6 address for the v6 bpf masquerade (one entry;
// params is a u32 array and cannot carry it). Zero disables v6 masquerade.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct addr128);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} node_ip6 SEC(".maps");

// migrate_fwd forwards a migrated VM's traffic from its OLD node to its new
// one during the cutover propagation window (live migration, stage 2). When a
// VM moves, remote nodes keep delivering to the stale source location until
// their `remotes` entry re-points (a few hundred ms of watch latency); the
// source, which no longer hosts the VM, re-encapsulates those packets to the
// target instead of dropping them — the cozyplane analog of OVN's
// requested-chassis=src,target. Keyed like `locals`; value is the target node
// IP (host order). Installed by the (old) source agent at cutover, removed
// after a short grace once every node's `remotes` has caught up.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
	__type(value, __u32);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} migrate_fwd SEC(".maps");

// vpc_counters meters east-west traffic per VPC (net), a metering/billing
// foundation (#2). PERCPU so the hooks never contend — the agent sums across
// CPUs when it reads. tx counts a VPC pod's egress (from_pod), rx its ingress
// on the main delivery path (to_pod); north-south (gateway/floating) metering
// is a later increment. The default network (net 0) is never metered.
struct vpc_counter {
	__u64 tx_packets;
	__u64 tx_bytes;
	__u64 rx_packets;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, struct vpc_counter);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_counters SEC(".maps");

// count_dir bumps one direction's counters for a net (no-op for net 0). The
// PERCPU value is this CPU's private copy, so the ++ needs no atomics.
//
// Deliberately NOT inlined and stack-free. Two verifier constraints shaped it:
// inlining at the top of the large from_pod program pushed path exploration
// past the 1M-instruction complexity budget (rejected on a 6.12 kernel, though
// the CI's 6.8 verifier accepted it — so it only showed on dev4); and as a
// BPF-to-BPF subprogram, any stack local of its own overflowed the 512-byte
// combined-call-stack limit (from_pod's frame is already near it). So the
// entry is NEVER created here — the agent pre-creates a zeroed vpc_counters
// entry per VPC net — and count_dir only looks up and increments, using no
// stack. A tenant's first packets before the agent creates the entry are
// simply not counted (negligible for a byte meter).
static __attribute__((noinline)) void count_dir(__u32 net, __u32 len, int rx)
{
	if (!net)
		return;
	struct vpc_counter *c = bpf_map_lookup_elem(&vpc_counters, &net);
	if (!c)
		return;
	if (rx) {
		c->rx_packets++;
		c->rx_bytes += len;
	} else {
		c->tx_packets++;
		c->tx_bytes += len;
	}
}

// Security groups (intra-VPC policy, #7). Enforcement is destination-side, in
// to_pod — the one delivery hook every east-west path already traverses, so it
// is placement-independent with no Geneve TLV yet. A port's membership is a
// bitmap of group ids; id 0 is unused (a zero bitmap = "no groups" = legacy
// allow-all intra-VPC), real ids run 1..SG_WORLD-1, and SG_WORLD (63) is the
// reserved pseudo-group for north-south (bridge/floating) sources matched by a
// cidr rule — so the same "allowed & srcmap" test covers both source kinds.
#define SG_WORLD 63

// sg_members: (net, VPC IP) -> u64 group bitmap. Absent/zero for both the
// destination (no groups) short-circuits to allow.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_members SEC(".maps");

// sg_rules: (dst-net, src-net, dst-group, proto, dst-port) -> u64 allowed-source
// bitmap, in src-net's id space. src_net == net for a same-VPC rule; for a
// peered-group rule it is the peer VPC's VNI (so peer group ids don't collide
// with same-VPC ids). port 0 is the any-port rule. The value's bits are source
// group ids (a group rule) and/or SG_WORLD (a cidr rule).
struct sg_rule_key {
	__u32 net;     // destination net
	__u32 src_net; // source net (peer VNI for a peer rule)
	__u16 group;   // destination group id
	__u16 port;    // destination port, network order; 0 = any port
	__u8 proto;    // IPPROTO_TCP / IPPROTO_UDP
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sg_rule_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_rules SEC(".maps");

// sg_drops meters policy drops per VPC (net), PERCPU and agent-seeded like
// vpc_counters — the observability the #2 metering foundation wants.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, __u64);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_drops SEC(".maps");

// count_sg_drop bumps a net's policy-drop counter. Stack-free and noinline for
// the same verifier reasons as count_dir; the agent pre-seeds the entry.
static __attribute__((noinline)) void count_sg_drop(__u32 net)
{
	if (!net)
		return;
	__u64 *d = bpf_map_lookup_elem(&sg_drops, &net);
	if (d)
		(*d)++;
}

// sg_query is the fully-initialized argument to sg_admit: a single PTR_TO_STACK
// keeps the BPF-to-BPF call verifier-friendly (multiple scalar args tripped a
// register-liveness check on the 6.12 verifier).
struct sg_query {
	struct local_key dst; // net + destination VPC IP
	__u32 src_net;        // the source's net (peer VNI across a peering)
	__u64 srcmap;         // the source's group bitmap (0 = ungrouped)
	__u16 dport;          // destination port, network order
	__u8 proto;           // IPPROTO_TCP / IPPROTO_UDP
	__u8 pad[1];
};

// sg_admit decides whether the queried packet is permitted. Returns 1 (allow)
// when the destination is in no group (legacy) or a rule of one of its groups
// admits the source; 0 (deny) otherwise. Noinline and near-stack-free (one key
// at a time), so to_pod's already-heavy frame stays within the combined
// call-stack limit — like count_dir.
static __attribute__((noinline)) int sg_admit(struct sg_query *q)
{
	__u64 *dm = bpf_map_lookup_elem(&sg_members, &q->dst);
	if (!dm || !*dm)
		return 1; // destination is in no group -> legacy allow
	__u64 dstmap = *dm;
	__u64 allowed = 0;
	struct sg_rule_key rk = { .net = q->dst.net, .src_net = q->src_net, .proto = q->proto };
#pragma unroll
	for (int g = 1; g < SG_WORLD; g++) {
		if (!(dstmap & (1ULL << g)))
			continue;
		rk.group = g;
		rk.port = q->dport;
		__u64 *r = bpf_map_lookup_elem(&sg_rules, &rk);
		if (r)
			allowed |= *r;
		rk.port = 0; // any-port rule for this (group, proto)
		__u64 *r0 = bpf_map_lookup_elem(&sg_rules, &rk);
		if (r0)
			allowed |= *r0;
	}
	return (allowed & q->srcmap) ? 1 : 0;
}

// sg_l4 reads the destination port and decides whether a packet should be gated
// by security-group rules. TCP is gated only on a *new* connection (SYN set,
// ACK clear): the reply direction of an admitted flow carries ACK and passes
// without a connection table, giving AWS-stateful-shaped semantics for TCP with
// no conntrack. UDP is always gated (stateless — intra-VPC UDP between grouped
// pods needs symmetric rules). Other protocols are never gated in v1. l4off is
// the L4 header offset (34 for v4, 54 for v6, no IP options — as l4_ports).
// Returns 1 to gate (with *dport, network order, set), 0 to skip.
static __always_inline int sg_l4(struct __sk_buff *skb, __u8 proto, __u32 l4off, __u16 *dport)
{
	// Load the port straight into *dport — a __u16 temp gets kept in a
	// caller-saved register across the flags load-call, which clobbers it
	// (verifier: R2 !read_ok on a 6.12 kernel).
	if (proto == IPPROTO_TCP) {
		__u8 flags;
		if (bpf_skb_load_bytes(skb, l4off + 2, dport, 2) < 0)
			return 0;
		if (bpf_skb_load_bytes(skb, l4off + 13, &flags, 1) < 0)
			return 0;
		return (flags & 0x02) && !(flags & 0x10); // SYN && !ACK
	}
	if (proto == IPPROTO_UDP) {
		if (bpf_skb_load_bytes(skb, l4off + 2, dport, 2) < 0)
			return 0;
		return 1;
	}
	return 0;
}

// dns_ips holds the cluster DNS ClusterIP per family ([0] = v4 in NAT64 form,
// [1] = v6). A VPC pod's query to this address is steered to the node-local
// split-horizon resolver (dns_steer/dns_return). A zero entry disables
// interception for that family.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct addr128);
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_ips SEC(".maps");

// fabric_of: (net, VPC IP) -> the pod's fabric IP, the inverse of `bridges`,
// programmed only when the two addresses are the same family (the fabric
// family can differ under the fabric-family fallback, in which case a
// same-family handle does not exist and the entry is absent). The DNS steer
// uses it as the pod's unique, node-routable source on the default network —
// the per-Port handle the resolver keys the tenant view on.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
	__type(value, struct addr128);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} fabric_of SEC(".maps");

// dns_ct records a steered query's original wire destination, keyed by the
// rewritten flow's unambiguous half ({proto, pod sport, fabric IP}), so
// dns_return can restore it as the reply's source. Needed because a socket-LB
// kube-proxy replacement (Cilium KPR forces socket LB on) translates the
// cluster DNS ClusterIP to a backend pod address *at connect() time* — the
// wire packet carries the backend, the pod's connected socket expects the
// reply to come from that exact backend, and the cgroup recvmsg hook
// translates it back to the ClusterIP for the application. Under a plain
// kube-proxy the recorded destination is simply the ClusterIP itself.
struct dns_ct_key {
	__u8 proto;
	__u8 pad;
	__u16 sport; // the pod's source port, network order
	struct addr128 fabric;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct dns_ct_key);
	__type(value, struct addr128);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} dns_ct SEC(".maps");

// ---- ServiceVIP maps (docs/services-in-vpc.md increment 2) ----------------
// A ServiceVIP is the ClusterIP-equivalent inside a VPC: an address from the
// VPC's own space that from_pod DNATs to a backend VPC IP. Keys are net-scoped
// like everything else, so overlapping CIDRs never collide, and a peered
// client resolves the vip under the service's net (its scope maps the peer's
// CIDR to that net).

#define SVC_MAX_BACKENDS 16

struct svc_key {
	__u32 net; // the service's net (the VPC that owns the VIP)
	struct addr128 vip;
	__u8 proto;
	__u8 pad;
	__u16 port; // service port, network order
};

struct svc_backend {
	struct addr128 ip; // backend VPC IP
	__u16 port;        // target port, network order
	__u16 pad;
};

// SVC_F_AFFINITY: Service.spec.sessionAffinity=ClientIP. The backend is chosen
// from the client IP alone (the source port is excluded from the hash), so
// every connection from one client lands on the same backend as long as the
// backend set is stable. Statelessly consistent — unlike kube-proxy there is
// no per-client timeout table, so a backend-set change may rebalance ~1/n of
// clients (which is also true of any consistent-hash LB).
#define SVC_F_AFFINITY 1

struct svc_val {
	__u32 n;
	__u32 flags;
	struct svc_backend be[SVC_MAX_BACKENDS];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct svc_key);
	__type(value, struct svc_val);
	__uint(max_entries, 16384);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_vips SEC(".maps");

// svc_fwd pins an established flow to its backend (a rebalance must not move
// mid-flow TCP), keyed by the client's view of the connection. Scoped to the
// CLIENT's net: the entry is written and read only on the client's node.
struct svc_fwd_key {
	__u32 net; // the client's net
	__u8 proto;
	__u8 pad;
	__u16 cport; // client source port, network order
	struct addr128 client;
	struct addr128 vip;
	__u16 vport; // service port, network order
	__u16 pad2;
};

struct svc_fwd_val {
	struct addr128 backend;
	__u16 tport;   // target port, network order
	__u16 hairpin; // 1 when backend == client (loopback-SNAT applied)
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct svc_fwd_key);
	__type(value, struct svc_fwd_val);
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_fwd SEC(".maps");

// svc_rev reverses the reply: backend:tport -> client becomes vip:vport ->
// client at the client's to_pod (or, hairpin, at the client's own from_pod).
struct svc_rev_key {
	__u32 net; // the client's net
	__u8 proto;
	__u8 pad;
	__u16 cport;
	struct addr128 backend;
	struct addr128 client;
	__u16 tport;
	__u16 pad2;
};

struct svc_rev_val {
	struct addr128 vip;
	__u16 vport;
	__u16 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct svc_rev_key);
	__type(value, struct svc_rev_val);
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_rev SEC(".maps");

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

static __always_inline int is_masq_src(struct addr128 addr)
{
	struct lpm_key key = { .prefixlen = LPM_FULL, .scope_net = 0, .addr = addr };
	return bpf_map_lookup_elem(&masq_srcs, &key) != NULL;
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

// A parsed IP packet, reduced to what the family-agnostic delivery path needs:
// both addresses as 128-bit map keys (v4 in NAT64 form, v6 native) and the
// family, so a caller can gate the v4-only NAT branches. The L4 protocol is the
// v4 protocol byte or the v6 next-header (extension headers are not walked — a
// v6 VPC's inner packets are plain TCP/UDP/ICMPv6, and only the overlay path,
// which never reads L4, runs for v6 today).
struct pkt {
	__u8 is_v6;
	__u8 proto;
	struct addr128 src;
	struct addr128 dst;
};

// parse_ip fills a struct pkt from either an IPv4 or IPv6 frame. The addresses
// are copied out (stack values), so they survive any later in-place packet
// rewrite that would invalidate a header pointer. Returns -1 for anything that
// is neither v4 nor v6 (e.g. ARP), which the caller passes to the kernel.
static __always_inline int parse_ip(struct __sk_buff *skb, struct pkt *p)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return -1;
		p->is_v6 = 0;
		p->proto = ip->protocol;
		v4_to_128(&p->src, ip->saddr);
		v4_to_128(&p->dst, ip->daddr);
		return 0;
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return -1;
		p->is_v6 = 1;
		p->proto = ip6->nexthdr;
		__builtin_memcpy(p->src.b, &ip6->saddr, 16);
		__builtin_memcpy(p->dst.b, &ip6->daddr, 16);
		return 0;
	}
	return -1;
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
static __always_inline int encap_sg(struct __sk_buff *skb, __u32 dstnet, __u32 node_ip, __u32 gw, __u32 srcnet, __u64 srcmap)
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
	// Stamp the source pod's authoritative group identity (stage B), but only
	// for a grouped source — the common ungrouped case pays nothing.
	if (srcmap) {
		struct sg_geneve_opt opt = {
			.opt_class = bpf_htons(SG_OPT_CLASS),
			.type = SG_OPT_TYPE,
			.length = 3,
			.src_net = srcnet,
			.srcmap = srcmap,
		};
		bpf_skb_set_tunnel_opt(skb, (void *)&opt, sizeof(opt));
	}
	return bpf_redirect(geneve, 0);
}

// encap without a security-group TLV (gateway, default-network, migration
// re-encap — no tenant source identity to vouch for).
static __always_inline int encap(struct __sk_buff *skb, __u32 dstnet, __u32 node_ip, __u32 gw)
{
	return encap_sg(skb, dstnet, node_ip, gw, 0, 0);
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

// ---- IPv6 fabric-bridge NAT primitives -----------------------------------
// The v6 fabric bridge reuses the bridges/ct_fwd/ct_rev maps (all addr128-keyed)
// and mirrors the v4 bridge; only the header rewrites differ, because IPv6 has no
// L3 checksum and folds the address into every L4 pseudo-header (ICMPv6 included).

// The v6 masquerade gateway: fe80::1, the address the host veth owns. A bridged
// pod's client is masqueraded to it, so the pod's reply comes back to from_pod.
#define LINK_LOCAL_GW6 { { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } }

static __always_inline int addr128_eq(const struct addr128 *a, const struct addr128 *b)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		if (a->b[i] != b->b[i])
			return 0;
	return 1;
}

// l4_ports6 reads the TCP/UDP ports of an IPv6 frame (fixed 40-byte header).
static __always_inline int l4_ports6(struct __sk_buff *skb, __u16 *sport, __u16 *dport)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + L4_OFF6 + 4 > data_end)
		return -1;
	__u16 *p = data + L4_OFF6;
	*sport = p[0];
	*dport = p[1];
	return 0;
}

// icmp6_echo reads an ICMPv6 echo message's type and identifier (fixed header).
static __always_inline int icmp6_echo(struct __sk_buff *skb, __u8 *type, __u16 *id)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	if (data + L4_OFF6 + 8 > data_end)
		return -1;
	__u8 *t = data + L4_OFF6;
	__u16 *idp = data + ICMP6_ID_OFF;
	*type = *t;
	*id = *idp;
	return 0;
}

static __always_inline __u32 l4_csum_off6(__u8 proto)
{
	if (proto == IPPROTO_TCP)
		return TCP_CSUM_OFF6;
	if (proto == IPPROTO_UDP)
		return UDP_CSUM_OFF6;
	return ICMP6_CSUM_OFF; // ICMPv6
}

// nat_addr6 rewrites a 16-byte IPv6 address (at addr_off) and fixes the L4
// checksum over the full address change. There is no IPv6 header checksum; TCP,
// UDP, and ICMPv6 all carry the address in their pseudo-header sum, so the fix
// applies to every L4 proto the bridge handles. UDP with a zero checksum keeps
// its "no checksum" marker via BPF_F_MARK_MANGLED_0.
static __always_inline void nat_addr6(struct __sk_buff *skb, __u8 proto, __u32 addr_off,
				      const struct addr128 *old, const struct addr128 *new)
{
	__s64 diff = bpf_csum_diff((__be32 *)old->b, 16, (__be32 *)new->b, 16, 0);
	__u64 flags = BPF_F_PSEUDO_HDR;
	if (proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	bpf_l4_csum_replace(skb, l4_csum_off6(proto), 0, diff, flags);
	bpf_skb_store_bytes(skb, addr_off, new->b, 16, 0);
}

// nat_port6 rewrites an L4 port (at port_off) of an IPv6 frame and fixes the L4
// checksum. The port is not in the pseudo-header, so a plain 2-byte update.
static __always_inline void nat_port6(struct __sk_buff *skb, __u8 proto, __u32 port_off, __u16 old, __u16 new)
{
	__u64 flags = 2;
	if (proto == IPPROTO_UDP)
		flags |= BPF_F_MARK_MANGLED_0;
	bpf_l4_csum_replace(skb, l4_csum_off6(proto), old, new, flags);
	bpf_skb_store_bytes(skb, port_off, &new, sizeof(new), 0);
}

// nat_icmp6_id rewrites the ICMPv6 echo identifier and fixes the ICMPv6 checksum
// (a plain 2-byte incremental update, like ICMPv4).
static __always_inline void nat_icmp6_id(struct __sk_buff *skb, __u16 old, __u16 new)
{
	bpf_l4_csum_replace(skb, ICMP6_CSUM_OFF, old, new, 2);
	bpf_skb_store_bytes(skb, ICMP6_ID_OFF, &new, sizeof(new), 0);
}

// icmp_v4_err reports whether an ICMPv4 type is an error that embeds the
// packet it is about (dest-unreachable incl. frag-needed, time-exceeded,
// parameter-problem).
static __always_inline int icmp_v4_err(__u8 type)
{
	return type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED || type == ICMP_PARAM_PROB;
}

// csum_upd16/32: RFC 1624 incremental checksum update (HC' = ~(~HC + ~m + m')),
// in plain C so embedded checksum fields can be recomputed and then written
// like any other payload bytes (each write folded into the outer ICMP
// checksum exactly once by emb_store16).
static __always_inline __u16 csum_upd16(__u16 c, __u16 old, __u16 new)
{
	__u32 sum = (__u16)~c;
	sum += (__u16)~old;
	sum += new;
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static __always_inline __u16 csum_upd32(__u16 c, __u32 old, __u32 new)
{
	c = csum_upd16(c, old & 0xffff, new & 0xffff);
	return csum_upd16(c, old >> 16, new >> 16);
}

// emb — the fields the bridge rewrites inside an ICMPv4 error's embedded
// packet. Loaded/stored with skb_{load,store}_bytes at constant offsets.
struct emb {
	__u8  proto;
	__u32 saddr, daddr; // network order
	__u16 sport, dport; // network order
	__u16 ip_csum;      // embedded IP header checksum
	__u16 udp_csum;     // embedded UDP checksum (0 = none)
};

static __always_inline int emb_load(struct __sk_buff *skb, struct emb *e)
{
	__u8 vihl;
	if (bpf_skb_load_bytes(skb, EMB_IP_OFF, &vihl, 1) < 0 || vihl != 0x45)
		return -1;
	if (bpf_skb_load_bytes(skb, EMB_IP_PROTO_OFF, &e->proto, 1) < 0 ||
	    bpf_skb_load_bytes(skb, EMB_IP_CSUM_OFF, &e->ip_csum, 2) < 0 ||
	    bpf_skb_load_bytes(skb, EMB_SADDR_OFF, &e->saddr, 4) < 0 ||
	    bpf_skb_load_bytes(skb, EMB_DADDR_OFF, &e->daddr, 4) < 0 ||
	    bpf_skb_load_bytes(skb, EMB_SPORT_OFF, &e->sport, 2) < 0 ||
	    bpf_skb_load_bytes(skb, EMB_DPORT_OFF, &e->dport, 2) < 0)
		return -1;
	e->udp_csum = 0;
	if (e->proto == IPPROTO_UDP &&
	    bpf_skb_load_bytes(skb, EMB_UDP_CSUM_OFF, &e->udp_csum, 2) < 0)
		return -1;
	return 0;
}

// emb_store16/32 write an embedded field and fold the change into the OUTER
// ICMP checksum (which sums the whole payload). Every embedded byte the
// bridge touches — data and checksum fields alike — goes through these, so
// the outer checksum stays exact; a receiver verifies it, making any rewrite
// bug self-detect as a drop rather than silent corruption.
static __always_inline void emb_store16(struct __sk_buff *skb, __u32 off, __u16 old, __u16 new)
{
	bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old, new, 2);
	bpf_skb_store_bytes(skb, off, &new, sizeof(new), 0);
}

static __always_inline void emb_store32(struct __sk_buff *skb, __u32 off, __u32 old, __u32 new)
{
	bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old, new, 4);
	bpf_skb_store_bytes(skb, off, &new, sizeof(new), 0);
}

// emb_rewrite applies one address+port translation to the embedded packet:
// saddr->nsaddr, daddr->ndaddr, and (when nport != 0) the port at port_off ->
// nport. The embedded IP checksum is recomputed for the address changes; the
// embedded UDP checksum (when present) for both — its pseudo-header sums the
// addresses. An absent UDP checksum that would become 0 stays 0 (no checksum).
static __always_inline void emb_rewrite(struct __sk_buff *skb, struct emb *e,
					__u32 nsaddr, __u32 ndaddr,
					__u32 port_off, __u16 oport, __u16 nport)
{
	__u16 ip_csum = e->ip_csum;
	ip_csum = csum_upd32(ip_csum, e->saddr, nsaddr);
	ip_csum = csum_upd32(ip_csum, e->daddr, ndaddr);

	if (e->saddr != nsaddr)
		emb_store32(skb, EMB_SADDR_OFF, e->saddr, nsaddr);
	if (e->daddr != ndaddr)
		emb_store32(skb, EMB_DADDR_OFF, e->daddr, ndaddr);
	if (ip_csum != e->ip_csum)
		emb_store16(skb, EMB_IP_CSUM_OFF, e->ip_csum, ip_csum);
	if (nport && nport != oport)
		emb_store16(skb, port_off, oport, nport);

	if (e->proto == IPPROTO_UDP && e->udp_csum) {
		__u16 udp = e->udp_csum;
		udp = csum_upd32(udp, e->saddr, nsaddr); // pseudo-header
		udp = csum_upd32(udp, e->daddr, ndaddr);
		if (nport)
			udp = csum_upd16(udp, oport, nport);
		if (!udp)
			udp = 0xffff; // 0 means "no checksum" on the wire
		if (udp != e->udp_csum)
			emb_store16(skb, EMB_UDP_CSUM_OFF, e->udp_csum, udp);
	}
}

// icmp6_err reports whether an ICMPv6 type is an error (RFC 4443: errors are
// types 0-127 — dest-unreachable, packet-too-big, time-exceeded, param-problem).
static __always_inline int icmp6_err(__u8 type)
{
	return type < 128;
}

// csum_upd128 folds a 16-byte address change into a checksum (the ICMPv6 /
// UDPv6 pseudo-header sums the full addresses).
static __always_inline __u16 csum_upd128(__u16 c, const struct addr128 *o, const struct addr128 *n)
{
	__u32 ow[4], nw[4];
	__builtin_memcpy(ow, o->b, 16);
	__builtin_memcpy(nw, n->b, 16);
#pragma unroll
	for (int i = 0; i < 4; i++)
		c = csum_upd32(c, ow[i], nw[i]);
	return c;
}

// emb6 — the fields the v6 bridge rewrites inside an ICMPv6 error's embedded
// packet. The embedded IPv6 header has no checksum of its own (unlike v4);
// only the outer ICMPv6 checksum and the embedded UDP checksum matter.
struct emb6 {
	__u8  proto;
	struct addr128 saddr, daddr;
	__u16 sport, dport; // network order
	__u16 udp_csum;
};

static __always_inline int emb6_load(struct __sk_buff *skb, struct emb6 *e)
{
	__u8 ver;
	if (bpf_skb_load_bytes(skb, EMB6_IP_OFF, &ver, 1) < 0 || (ver >> 4) != 6)
		return -1;
	if (bpf_skb_load_bytes(skb, EMB6_NEXTHDR_OFF, &e->proto, 1) < 0 ||
	    bpf_skb_load_bytes(skb, EMB6_SADDR_OFF, &e->saddr, 16) < 0 ||
	    bpf_skb_load_bytes(skb, EMB6_DADDR_OFF, &e->daddr, 16) < 0 ||
	    bpf_skb_load_bytes(skb, EMB6_SPORT_OFF, &e->sport, 2) < 0 ||
	    bpf_skb_load_bytes(skb, EMB6_DPORT_OFF, &e->dport, 2) < 0)
		return -1;
	e->udp_csum = 0;
	if (e->proto == IPPROTO_UDP &&
	    bpf_skb_load_bytes(skb, EMB6_UDP_CSUM_OFF, &e->udp_csum, 2) < 0)
		return -1;
	return 0;
}

// emb6_store16 / emb6_store_addr write embedded fields and fold every changed
// byte into the OUTER ICMPv6 checksum exactly once (same discipline as v4:
// receivers verify it, so a rewrite bug self-detects as a drop).
static __always_inline void emb6_store16(struct __sk_buff *skb, __u32 off, __u16 old, __u16 new)
{
	bpf_l4_csum_replace(skb, ICMP6_CSUM_OFF, old, new, 2);
	bpf_skb_store_bytes(skb, off, &new, sizeof(new), 0);
}

static __always_inline void emb6_store_addr(struct __sk_buff *skb, __u32 off,
					    const struct addr128 *o, const struct addr128 *n)
{
	__u32 ow[4], nw[4];
	__builtin_memcpy(ow, o->b, 16);
	__builtin_memcpy(nw, n->b, 16);
#pragma unroll
	for (int i = 0; i < 4; i++)
		if (ow[i] != nw[i])
			bpf_l4_csum_replace(skb, ICMP6_CSUM_OFF, ow[i], nw[i], 4);
	bpf_skb_store_bytes(skb, off, n->b, 16, 0);
}

// emb6_rewrite applies one address+port translation to the embedded v6 packet.
// The embedded UDP checksum (mandatory in v6) is recomputed for the
// pseudo-header address changes and the port.
static __always_inline void emb6_rewrite(struct __sk_buff *skb, struct emb6 *e,
					 const struct addr128 *nsaddr, const struct addr128 *ndaddr,
					 __u32 port_off, __u16 oport, __u16 nport)
{
	emb6_store_addr(skb, EMB6_SADDR_OFF, &e->saddr, nsaddr);
	emb6_store_addr(skb, EMB6_DADDR_OFF, &e->daddr, ndaddr);
	if (nport && nport != oport)
		emb6_store16(skb, port_off, oport, nport);
	if (e->proto == IPPROTO_UDP && e->udp_csum) {
		__u16 udp = e->udp_csum;
		udp = csum_upd128(udp, &e->saddr, nsaddr);
		udp = csum_upd128(udp, &e->daddr, ndaddr);
		if (nport)
			udp = csum_upd16(udp, oport, nport);
		if (!udp)
			udp = 0xffff;
		if (udp != e->udp_csum)
			emb6_store16(skb, EMB6_UDP_CSUM_OFF, e->udp_csum, udp);
	}
}

// alloc_gw_port picks a free masquerade port for a new north-south connection:
// the reverse-lookup key {proto, gw_port, net, vpc_ip, pod_port} must be unique,
// so probe (bounded) with BPF_NOEXIST — the insert that wins owns the port.
static __always_inline __u16 alloc_gw_port_in(__u8 proto, __u32 net, struct addr128 vpc_ip, __u16 pod_port,
					      struct addr128 fabric_ip, struct addr128 client_ip, __u16 client_port,
					      __u32 port_base, __u32 port_span)
{
	__u32 base = bpf_get_prandom_u32();
	struct ct_rev_val rv = {
		.fabric_ip = fabric_ip,
		.client_ip = client_ip,
		.client_port = client_port,
	};
#pragma unroll
	for (int i = 0; i < 16; i++) {
		__u16 p = bpf_htons(port_base + ((base + i) % port_span));
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

static __always_inline __u16 alloc_gw_port(__u8 proto, __u32 net, struct addr128 vpc_ip, __u16 pod_port,
					   struct addr128 fabric_ip, struct addr128 client_ip, __u16 client_port)
{
	return alloc_gw_port_in(proto, net, vpc_ip, pod_port, fabric_ip, client_ip, client_port, 1024, 64000);
}

// bridge_forward_icmp_err translates a network-emitted ICMP error (typically
// frag-needed — the PMTU signal) toward the pod. The error is addressed to the
// fabric IP because the pod's un-NAT'd reply carried it as source; its embedded
// packet is that reply, fabric:pod_port -> client:client_port. Look the flow up
// in ct_fwd (the same key its forward direction uses), then translate outer and
// embedded through the same NAT: the pod must see the embedded packet exactly
// as it sent it (vpc:pod_port -> gw:gw_port) or its stack won't match a socket.
// Errors about ICMP-echo flows are not translated (no PMTU value for pings).
static __always_inline int bridge_forward_icmp_err(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	struct emb e;
	if (emb_load(skb, &e) < 0)
		return TC_ACT_SHOT;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return TC_ACT_SHOT;
	__u32 osrc = ip->saddr, odst = ip->daddr; // copied: stores below invalidate ip
	if (e.saddr != odst)
		return TC_ACT_SHOT; // embedded source must be the fabric IP the error targets

	struct addr128 client128, fabric128;
	v4_to_128(&client128, e.daddr);
	v4_to_128(&fabric128, e.saddr);
	struct ct_fwd_key fk = {
		.proto = e.proto,
		.net = net,
		.client_ip = client128,
		.fabric_ip = fabric128,
		.client_port = e.dport,
		.pod_port = e.sport,
	};
	__u16 *gw_port = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (!gw_port)
		return TC_ACT_SHOT; // no such bridged flow

	__u32 vpc = v4_of_128(&vpc_ip), gw = bpf_htonl(LINK_LOCAL_GW);
	nat_addr(skb, IPPROTO_ICMP, IP_DADDR_OFF, odst, vpc);
	nat_addr(skb, IPPROTO_ICMP, IP_SADDR_OFF, osrc, gw); // reporter hidden, like any client
	emb_rewrite(skb, &e, vpc, gw, EMB_DPORT_OFF, e.dport, *gw_port);
	return TC_ACT_OK; // delivered to the pod; its stack applies the PMTU/error
}

// bridge_forward_icmp is the ICMP-echo forward half: the echo identifier stands
// in for the L4 port. A request is DNATed fabric->VPC, its client masqueraded to
// the gateway, and its id rewritten to a unique gw_id so replies demux (the
// client is hidden, so id is the only distinguishing field). Echo requests and
// ICMP errors cross (bridge_forward_icmp_err); the rest is dropped.
static __always_inline int bridge_forward_icmp(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	__u8 type;
	__u16 id;
	if (icmp_echo(skb, &type, &id) < 0)
		return TC_ACT_SHOT;
	if (icmp_v4_err(type))
		return bridge_forward_icmp_err(skb, ip, net, vpc_ip);
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
// bridge_reverse_icmp_err translates a pod-emitted ICMP error (port
// unreachable, time-exceeded — what makes UDP probes fail fast and traceroute
// terminate) out to the client. The pod addressed it to the gateway because
// the offending packet's masqueraded source was gw:gw_port; that packet is
// embedded, so ct_rev keyed on the embedded (gw_port, vpc, pod_port) recovers
// the client, and outer + embedded are translated back: the client's stack
// must see its own original packet (client:client_port -> fabric:pod_port)
// inside the error to match it to a socket. Errors about echo flows pass for
// TCP/UDP only (no value in translating errors about pings).
static __always_inline int bridge_reverse_icmp_err(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	struct emb e;
	if (emb_load(skb, &e) < 0)
		return TC_ACT_OK;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return TC_ACT_OK;
	__u32 osrc = ip->saddr; // copied: stores below invalidate ip
	if (e.saddr != bpf_htonl(LINK_LOCAL_GW) || e.daddr != osrc)
		return TC_ACT_OK; // embedded must be a bridged inbound: gw -> this pod

	struct addr128 vpc128;
	v4_to_128(&vpc128, e.daddr);
	struct ct_rev_key rk = {
		.proto = e.proto,
		.gw_port = e.sport,
		.net = net,
		.vpc_ip = vpc128,
		.pod_port = e.dport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK;

	__u32 fabric = v4_of_128(&rv->fabric_ip), client = v4_of_128(&rv->client_ip);
	nat_addr(skb, IPPROTO_ICMP, IP_SADDR_OFF, osrc, fabric);
	nat_addr(skb, IPPROTO_ICMP, IP_DADDR_OFF, bpf_htonl(LINK_LOCAL_GW), client);
	emb_rewrite(skb, &e, client, fabric, EMB_SPORT_OFF, e.sport, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

static __always_inline int bridge_reverse_icmp(struct __sk_buff *skb, struct iphdr *ip, __u32 net)
{
	__u8 type;
	__u16 gw_id;
	if (icmp_echo(skb, &type, &gw_id) < 0)
		return TC_ACT_OK;
	if (icmp_v4_err(type))
		return bridge_reverse_icmp_err(skb, ip, net);
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

// bridge_forward6_icmp_err translates a network-emitted ICMPv6 error toward
// the pod — packet-too-big above all: v6 does not fragment in flight, so
// without this the pod never learns the path MTU for its bridged replies. The
// v6 twin of bridge_forward_icmp_err; the outer address rewrites ride
// nat_addr6 (the ICMPv6 checksum's pseudo-header covers them), the embedded
// rewrite folds into the same checksum via emb6_rewrite.
static __always_inline int bridge_forward6_icmp_err(struct __sk_buff *skb, struct pkt *p, __u32 net, struct addr128 vpc_ip)
{
	struct emb6 e;
	if (emb6_load(skb, &e) < 0)
		return TC_ACT_SHOT;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return TC_ACT_SHOT;
	if (!addr128_eq(&e.saddr, &p->dst))
		return TC_ACT_SHOT; // embedded source must be the fabric IP the error targets

	struct ct_fwd_key fk = {
		.proto = e.proto,
		.net = net,
		.client_ip = e.daddr,
		.fabric_ip = e.saddr,
		.client_port = e.dport,
		.pod_port = e.sport,
	};
	__u16 *gw_port = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (!gw_port)
		return TC_ACT_SHOT;

	struct addr128 gw = LINK_LOCAL_GW6;
	nat_addr6(skb, IPPROTO_ICMPV6, IP6_DADDR_OFF, &p->dst, &vpc_ip);
	nat_addr6(skb, IPPROTO_ICMPV6, IP6_SADDR_OFF, &p->src, &gw);
	emb6_rewrite(skb, &e, &vpc_ip, &gw, EMB6_DPORT_OFF, e.dport, *gw_port);
	return TC_ACT_OK;
}

// bridge_reverse6_icmp_err translates a pod-emitted ICMPv6 error (port
// unreachable to a probe, time-exceeded) out to the client — the v6 twin of
// bridge_reverse_icmp_err.
static __always_inline int bridge_reverse6_icmp_err(struct __sk_buff *skb, struct pkt *p, __u32 net)
{
	struct addr128 gw = LINK_LOCAL_GW6;
	struct emb6 e;
	if (emb6_load(skb, &e) < 0)
		return TC_ACT_OK;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return TC_ACT_OK;
	if (!addr128_eq(&e.saddr, &gw) || !addr128_eq(&e.daddr, &p->src))
		return TC_ACT_OK; // embedded must be a bridged inbound: gw -> this pod

	struct ct_rev_key rk = {
		.proto = e.proto,
		.gw_port = e.sport,
		.net = net,
		.vpc_ip = e.daddr,
		.pod_port = e.dport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK;

	nat_addr6(skb, IPPROTO_ICMPV6, IP6_SADDR_OFF, &p->src, &rv->fabric_ip);
	nat_addr6(skb, IPPROTO_ICMPV6, IP6_DADDR_OFF, &gw, &rv->client_ip);
	emb6_rewrite(skb, &e, &rv->client_ip, &rv->fabric_ip, EMB6_SPORT_OFF, e.sport, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

// bridge_forward6 is the v6 fabric bridge forward half, done in to_pod when a
// packet's destination is a v6 fabric IP: DNAT fabric->VPC and masquerade the
// client to fe80::1:gw_port, mirroring bridge_forward. The client/fabric/vpc
// addresses are already 128-bit in `p`, and ct_fwd/ct_rev are addr128-keyed, so
// the connection table is shared with v4. TCP/UDP/ICMPv6-echo; other ICMPv6 is
// dropped (NDP never reaches here — it is link-scoped and short-circuited).
static __always_inline int bridge_forward6(struct __sk_buff *skb, struct pkt *p, __u32 net, struct addr128 vpc_ip)
{
	__u8 proto = p->proto;
	struct addr128 gw = LINK_LOCAL_GW6;

	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 id;
		if (icmp6_echo(skb, &type, &id) < 0)
			return TC_ACT_SHOT;
		if (icmp6_err(type))
			return bridge_forward6_icmp_err(skb, p, net, vpc_ip);
		if (type != ICMP6_ECHO_REQUEST)
			return TC_ACT_SHOT;
		struct ct_fwd_key fk = {
			.proto = proto,
			.net = net,
			.client_ip = p->src,
			.fabric_ip = p->dst,
			.client_port = id,
		};
		__u16 gw_id;
		__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
		if (have) {
			gw_id = *have;
		} else {
			gw_id = alloc_gw_port(proto, net, vpc_ip, 0, p->dst, p->src, id);
			if (!gw_id)
				return TC_ACT_SHOT;
			bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
		}
		nat_addr6(skb, proto, IP6_DADDR_OFF, &p->dst, &vpc_ip);
		nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &gw);
		nat_icmp6_id(skb, id, gw_id);
		return TC_ACT_OK;
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_SHOT;
	__u16 cport, pport;
	if (l4_ports6(skb, &cport, &pport) < 0)
		return TC_ACT_SHOT;
	struct ct_fwd_key fk = {
		.proto = proto,
		.net = net,
		.client_ip = p->src,
		.fabric_ip = p->dst,
		.client_port = cport,
		.pod_port = pport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port(proto, net, vpc_ip, pport, p->dst, p->src, cport);
		if (!gw_port)
			return TC_ACT_SHOT;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}
	nat_addr6(skb, proto, IP6_DADDR_OFF, &p->dst, &vpc_ip);
	nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &gw);
	nat_port6(skb, proto, L4_SPORT_OFF6, cport, gw_port);
	return TC_ACT_OK; // delivered to the pod (src is now the gateway)
}

// bridge_reverse6 is the v6 reply un-NAT, done in from_pod when a v6 VPC pod
// replies to fe80::1: recover the masquerade port, restore vpc->fabric on the
// source and gateway->client on the destination, and deliver on the default
// network. The parallel of bridge_reverse.
static __always_inline int bridge_reverse6(struct __sk_buff *skb, struct pkt *p, __u32 net)
{
	__u8 proto = p->proto;
	struct addr128 gw = LINK_LOCAL_GW6;

	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 gw_id;
		if (icmp6_echo(skb, &type, &gw_id) < 0)
			return TC_ACT_OK;
		if (icmp6_err(type))
			return bridge_reverse6_icmp_err(skb, p, net);
		if (type != ICMP6_ECHO_REPLY)
			return TC_ACT_OK;
		struct ct_rev_key rk = {
			.proto = proto,
			.gw_port = gw_id,
			.net = net,
			.vpc_ip = p->src,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return TC_ACT_OK;
		nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &rv->fabric_ip);
		nat_addr6(skb, proto, IP6_DADDR_OFF, &gw, &rv->client_ip);
		nat_icmp6_id(skb, gw_id, rv->client_port);
		return deliver_net0(skb, rv->client_ip);
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return TC_ACT_OK;
	__u16 pport, gw_port;
	if (l4_ports6(skb, &pport, &gw_port) < 0)
		return TC_ACT_OK;
	struct ct_rev_key rk = {
		.proto = proto,
		.gw_port = gw_port,
		.net = net,
		.vpc_ip = p->src,
		.pod_port = pport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return TC_ACT_OK;
	nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &rv->fabric_ip);
	nat_addr6(skb, proto, IP6_DADDR_OFF, &gw, &rv->client_ip);
	nat_port6(skb, proto, L4_DPORT_OFF6, gw_port, rv->client_port);
	return deliver_net0(skb, rv->client_ip);
}

// floating_forward is the inbound half of a floating IP, done in to_pod when a
// packet's destination is a floating address: a stateless DNAT public->VPC that
// keeps the external client as the source (no masquerade). Sanctioned
// north-south, like bridge_forward — the isolation check below does not run.
// TCP, UDP, ICMP echo (request or reply — a reply is the return half of the
// pod's own outbound ping), and ICMP errors (frag-needed = the pod's inbound
// PMTU signal). Floating is stateless and source-preserving, so an error needs
// only the public->VPC swap in the outer destination and the embedded source
// (the pod's dropped packet left with the public address as its source).
static __always_inline int floating_forward(struct __sk_buff *skb, struct iphdr *ip, __u32 net, struct addr128 vpc_ip)
{
	if (ip->ihl != 5)
		return TC_ACT_SHOT;
	__u8 proto = ip->protocol;
	__u32 vpc = v4_of_128(&vpc_ip);
	if (proto == IPPROTO_ICMP) {
		__u8 type;
		__u16 id;
		if (icmp_echo(skb, &type, &id) < 0)
			return TC_ACT_SHOT;
		if (icmp_v4_err(type)) {
			struct emb e;
			__u32 odst = ip->daddr; // copied: stores below invalidate ip
			if (emb_load(skb, &e) < 0)
				return TC_ACT_SHOT;
			if (e.saddr != odst)
				return TC_ACT_SHOT; // embedded source must be the public IP
			nat_addr(skb, proto, IP_DADDR_OFF, odst, vpc);
			emb_rewrite(skb, &e, vpc, e.daddr, 0, 0, 0);
			return TC_ACT_OK;
		}
		if (type != ICMP_ECHO_REQUEST && type != ICMP_ECHO_REPLY)
			return TC_ACT_SHOT;
	} else if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		return TC_ACT_SHOT;
	}
	nat_addr(skb, proto, IP_DADDR_OFF, ip->daddr, vpc);
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
	__u32 pub = v4_of_128(public_ip), osrc = ip->saddr; // copied: stores invalidate ip
	if (proto == IPPROTO_ICMP) {
		// A pod-emitted ICMP error (port unreachable to a probe, frag-needed)
		// embeds the client's inbound packet, whose destination was the
		// public address before the floating DNAT: swap it back so the
		// client's stack can match the error to its socket. Stateless, like
		// the rest of the floating path.
		__u8 type;
		__u16 id;
		if (icmp_echo(skb, &type, &id) == 0 && icmp_v4_err(type)) {
			struct emb e;
			if (emb_load(skb, &e) == 0 && e.daddr == osrc)
				emb_rewrite(skb, &e, e.saddr, pub, 0, 0, 0);
		}
	}
	nat_addr(skb, proto, IP_SADDR_OFF, osrc, pub);
	return bpf_redirect_neigh(uplink, NULL, 0, 0);
}

#define MASQ_MISS -1

// masq_snat is the cluster-egress bpf masquerade (#10), run in from_pod at the
// uplink-egress attachment only: a packet whose source is a (default-network)
// pod address and whose destination is off-cluster gets its source rewritten
// to the node IP and its port/id to an allocated masquerade port — the same
// ct_fwd/ct_rev machinery as the north-south bridge, reused with net=0 and
// inverted roles (vpc_ip:=remote, fabric_ip/client_ip:=pod). Ports come from
// MASQ_PORT_BASE..+SPAN: disjoint from the host ephemeral range so reverse
// lookups can't capture the node's own connections, and below the NodePort
// range so an allocation never collides with one. v4-only, TCP/UDP/ICMP-echo —
// the same practical envelope as the kernel MASQUERADE rule it replaces.
static __always_inline int masq_snat(struct __sk_buff *skb, struct pkt *p)
{
	if (!is_masq_src(p->src) || is_internal(p->dst))
		return MASQ_MISS;
	__u32 node_ip = cfg(CFG_NODE_IP);
	if (!node_ip)
		return MASQ_MISS;

	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > end || ip->ihl != 5)
		return MASQ_MISS;
	__u8 proto = ip->protocol;
	__u32 osrc = ip->saddr;

	if (proto == IPPROTO_ICMP) {
		__u8 type;
		__u16 id;
		if (icmp_echo(skb, &type, &id) < 0 || type != ICMP_ECHO_REQUEST)
			return MASQ_MISS;
		struct ct_fwd_key fk = {
			.proto = proto, .net = 0,
			.client_ip = p->src, .fabric_ip = p->dst,
			.client_port = id,
		};
		__u16 gw_id;
		__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
		if (have) {
			gw_id = *have;
		} else {
			gw_id = alloc_gw_port_in(proto, 0, p->dst, 0, p->src, p->src, id,
						 MASQ_PORT_BASE, MASQ_PORT_SPAN);
			if (!gw_id)
				return MASQ_MISS; // table full: better unmasqueraded than dropped
			bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
		}
		nat_addr(skb, proto, IP_SADDR_OFF, osrc, node_ip);
		nat_icmp_id(skb, id, gw_id);
		return TC_ACT_OK;
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return MASQ_MISS;
	__u16 sport, dport;
	if (l4_ports(skb, &sport, &dport) < 0)
		return MASQ_MISS;
	struct ct_fwd_key fk = {
		.proto = proto, .net = 0,
		.client_ip = p->src, .fabric_ip = p->dst,
		.client_port = sport, .pod_port = dport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port_in(proto, 0, p->dst, dport, p->src, p->src, sport,
					   MASQ_PORT_BASE, MASQ_PORT_SPAN);
		if (!gw_port)
			return MASQ_MISS;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}
	nat_addr(skb, proto, IP_SADDR_OFF, osrc, node_ip);
	nat_port(skb, proto, L4_SPORT_OFF, sport, gw_port);
	return TC_ACT_OK;
}

// masq_reverse un-SNATs a reply to a bpf-masqueraded connection, run in
// from_uplink at the uplink ingress — BEFORE netfilter, so the kernel's
// conntrack (which watched the original pod-sourced flow leave through
// FORWARD) sees a reply that matches ESTABLISHED; no INVALID drop can fire.
// Only packets to the node IP whose port/id sits in the masquerade range and
// hits ct_rev are touched, so the node's own traffic (host ephemeral ports
// and NodePorts are outside the range) passes untouched. Inbound ICMP errors
// about masqueraded flows (frag-needed: the pod's PMTU signal) are translated
// with the same embedded-header rewrite as the bridge.
static __always_inline int masq_reverse(struct __sk_buff *skb, struct pkt *p)
{
	__u32 node_ip = cfg(CFG_NODE_IP);
	if (!node_ip || v4_of_128(&p->dst) != node_ip)
		return MASQ_MISS;

	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > end || ip->ihl != 5)
		return MASQ_MISS;
	__u8 proto = ip->protocol;
	__u32 odst = ip->daddr;

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 sport, dport;
		if (l4_ports(skb, &sport, &dport) < 0)
			return MASQ_MISS;
		__u16 h = bpf_ntohs(dport);
		if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
			return MASQ_MISS;
		struct ct_rev_key rk = {
			.proto = proto, .gw_port = dport, .net = 0,
			.vpc_ip = p->src, .pod_port = sport,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return MASQ_MISS;
		nat_addr(skb, proto, IP_DADDR_OFF, odst, v4_of_128(&rv->fabric_ip));
		nat_port(skb, proto, L4_DPORT_OFF, dport, rv->client_port);
		return TC_ACT_OK; // the kernel routes to the pod (host /32 route)
	}
	if (proto != IPPROTO_ICMP)
		return MASQ_MISS;
	__u8 type;
	__u16 id;
	if (icmp_echo(skb, &type, &id) < 0)
		return MASQ_MISS;
	if (type == ICMP_ECHO_REPLY) {
		__u16 h = bpf_ntohs(id);
		if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
			return MASQ_MISS;
		struct ct_rev_key rk = {
			.proto = proto, .gw_port = id, .net = 0,
			.vpc_ip = p->src,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return MASQ_MISS;
		nat_addr(skb, proto, IP_DADDR_OFF, odst, v4_of_128(&rv->fabric_ip));
		nat_icmp_id(skb, id, rv->client_port);
		return TC_ACT_OK;
	}
	if (!icmp_v4_err(type))
		return MASQ_MISS;
	struct emb e;
	if (emb_load(skb, &e) < 0)
		return MASQ_MISS;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return MASQ_MISS;
	if (e.saddr != odst)
		return MASQ_MISS; // embedded source must be the node (the SNAT'd packet)
	__u16 h = bpf_ntohs(e.sport);
	if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
		return MASQ_MISS;
	struct addr128 remote128;
	v4_to_128(&remote128, e.daddr);
	struct ct_rev_key rk = {
		.proto = e.proto, .gw_port = e.sport, .net = 0,
		.vpc_ip = remote128, .pod_port = e.dport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return MASQ_MISS;
	__u32 pod = v4_of_128(&rv->fabric_ip);
	nat_addr(skb, IPPROTO_ICMP, IP_DADDR_OFF, odst, pod);
	emb_rewrite(skb, &e, pod, e.daddr, EMB_SPORT_OFF, e.sport, rv->client_port);
	return TC_ACT_OK; // conntrack sees it RELATED to the pod's flow
}

// floating_forward6 is the v6 inbound half of a floating IP: a stateless DNAT
// public->VPC that keeps the external client as the source, mirroring
// floating_forward. TCP, UDP, ICMPv6 echo, and ICMPv6 errors (packet-too-big
// = the pod's inbound PMTU signal) with the embedded source swapped.
static __always_inline int floating_forward6(struct __sk_buff *skb, struct pkt *p, __u32 net, struct addr128 vpc_ip)
{
	__u8 proto = p->proto;
	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 id;
		if (icmp6_echo(skb, &type, &id) < 0)
			return TC_ACT_SHOT;
		if (icmp6_err(type)) {
			struct emb6 e;
			if (emb6_load(skb, &e) < 0)
				return TC_ACT_SHOT;
			if (!addr128_eq(&e.saddr, &p->dst))
				return TC_ACT_SHOT; // embedded source must be the public IP
			nat_addr6(skb, proto, IP6_DADDR_OFF, &p->dst, &vpc_ip);
			emb6_rewrite(skb, &e, &vpc_ip, &e.daddr, 0, 0, 0);
			return TC_ACT_OK;
		}
		if (type != ICMP6_ECHO_REQUEST && type != ICMP6_ECHO_REPLY)
			return TC_ACT_SHOT;
	} else if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		return TC_ACT_SHOT;
	}
	nat_addr6(skb, proto, IP6_DADDR_OFF, &p->dst, &vpc_ip);
	return TC_ACT_OK;
}

// floating_egress_snat6 is the v6 outbound half: SNAT VPC->public and redirect
// out the uplink, mirroring floating_egress_snat. Pod-emitted ICMPv6 errors
// about inbound floating flows get the embedded destination swapped back so
// the external client's stack can match them (traceroute6, port unreachable).
static __always_inline int floating_egress_snat6(struct __sk_buff *skb, struct pkt *p, __u32 net)
{
	__u8 proto = p->proto;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMPV6)
		return FLOAT_MISS;
	struct addr128 *public_ip = floating_egress_of(net, p->src);
	if (!public_ip)
		return FLOAT_MISS;
	if (is_internal(p->dst))
		return FLOAT_MISS;
	__u32 uplink = cfg(CFG_UPLINK_IFINDEX);
	if (!uplink)
		return FLOAT_MISS;
	struct addr128 pub = *public_ip; // copied: stores below invalidate map values too
	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 id;
		if (icmp6_echo(skb, &type, &id) == 0 && icmp6_err(type)) {
			struct emb6 e;
			if (emb6_load(skb, &e) == 0 && addr128_eq(&e.daddr, &p->src))
				emb6_rewrite(skb, &e, &e.saddr, &pub, 0, 0, 0);
		}
	}
	nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &pub);
	return bpf_redirect_neigh(uplink, NULL, 0, 0);
}

// floating_ndp answers a Neighbor Solicitation for a floating v6 address with
// a solicited+override Neighbor Advertisement carrying the uplink MAC — the
// NDP twin of floating_arp (the L2 advertisement that pulls inbound traffic
// to this node). The NS is rewritten to the NA in place and sent back out the
// uplink; the ICMPv6 checksum is updated incrementally for every changed
// field, pseudo-header included. DAD probes (unspecified source) are left
// unanswered: cozyplane owns the address authoritatively, and answering DAD
// would need the all-nodes multicast path instead.
static __always_inline int floating_ndp(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IPV6))
		return FLOAT_MISS;
	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_ICMPV6)
		return FLOAT_MISS;
	if (data + NDP_TARGET_OFF + 16 > data_end)
		return FLOAT_MISS;
	__u8 *icmp = data + L4_OFF6;
	if (icmp[0] != ICMP6_NEIGH_SOLICIT)
		return FLOAT_MISS;

	struct addr128 target, req, zero = {};
	__builtin_memcpy(target.b, data + NDP_TARGET_OFF, 16);
	__builtin_memcpy(req.b, &ip6->saddr, 16);
	if (addr128_eq(&req, &zero))
		return FLOAT_MISS; // DAD probe; not answered (see above)

	struct bridge_ep *fe = float_of(target);
	if (!fe)
		return FLOAT_MISS;
	if (!local_of(fe->net, fe->vpc_ip))
		return FLOAT_MISS;
	__u32 zidx = 0;
	struct cozy_mac *node = bpf_map_lookup_elem(&uplink_mac, &zidx);
	if (!node)
		return FLOAT_MISS;

	// Incremental ICMPv6 checksum over every change: the pseudo-header (src
	// becomes the target, dst becomes the requester) and the payload (type,
	// flags, option type when present).
	__u16 csum = 0;
	bpf_skb_load_bytes(skb, ICMP6_CSUM_OFF, &csum, 2);
	struct addr128 dst128;
	__builtin_memcpy(dst128.b, &ip6->daddr, 16);
	csum = csum_upd128(csum, &req, &target);   // pseudo src: requester -> target
	csum = csum_upd128(csum, &dst128, &req);   // pseudo dst: sol-node mcast -> requester
	__u16 otc = bpf_htons(ICMP6_NEIGH_SOLICIT << 8);
	__u16 ntc = bpf_htons(ICMP6_NEIGH_ADVERT << 8);
	csum = csum_upd16(csum, otc, ntc);         // type/code word
	__u32 oflags = 0;
	bpf_skb_load_bytes(skb, NDP_FLAGS_OFF, &oflags, 4);
	__u32 nflags = bpf_htonl(0x60000000);      // Solicited | Override
	csum = csum_upd32(csum, oflags, nflags);

	__u8 req_mac[6];
	__builtin_memcpy(req_mac, eth->h_source, 6);
	__u8 have_opt = (void *)(data + NDP_OPT_OFF + 8) <= data_end;
	if (have_opt) {
		// Source link-layer option -> target link-layer option with our MAC.
		__u16 oopt = 0, nopt;
		bpf_skb_load_bytes(skb, NDP_OPT_OFF, &oopt, 2);
		__u8 nb[2] = {2, 1};
		__builtin_memcpy(&nopt, nb, 2);
		csum = csum_upd16(csum, oopt, nopt);
		__u16 om[3], nm[3];
		bpf_skb_load_bytes(skb, NDP_OPT_MAC_OFF, om, 6);
		__builtin_memcpy(nm, node->addr, 6);
#pragma unroll
		for (int i = 0; i < 3; i++)
			csum = csum_upd16(csum, om[i], nm[i]);
		bpf_skb_store_bytes(skb, NDP_OPT_OFF, nb, 2, 0);
		bpf_skb_store_bytes(skb, NDP_OPT_MAC_OFF, node->addr, 6, 0);
	}

	__u8 na = ICMP6_NEIGH_ADVERT;
	bpf_skb_store_bytes(skb, L4_OFF6, &na, 1, 0);
	bpf_skb_store_bytes(skb, NDP_FLAGS_OFF, &nflags, 4, 0);
	bpf_skb_store_bytes(skb, IP6_SADDR_OFF, target.b, 16, 0);
	bpf_skb_store_bytes(skb, IP6_DADDR_OFF, req.b, 16, 0);
	bpf_skb_store_bytes(skb, ICMP6_CSUM_OFF, &csum, 2, 0);

	// Ethernet: back to the requester, from the node.
	__u8 nmac[6];
	__builtin_memcpy(nmac, node->addr, 6);
	bpf_skb_store_bytes(skb, 0, req_mac, 6, 0);
	bpf_skb_store_bytes(skb, 6, nmac, 6, 0);

	return bpf_redirect(skb->ifindex, 0); // back out the uplink to the requester
}

static __always_inline struct addr128 *masq_node6(void)
{
	__u32 zero = 0;
	struct addr128 z = {};
	struct addr128 *n = bpf_map_lookup_elem(&node_ip6, &zero);
	if (!n || addr128_eq(n, &z))
		return NULL;
	return n;
}

// masq_snat6 / masq_reverse6: the v6 cluster-egress masquerade, mirroring the
// v4 pair. Same ct tables (addr128-keyed, families coexist), same port range.
// This is what gives the gateway pod's forwarded tenant-v6 traffic (and any
// default-network pod's v6 egress) a routable return path — pod ULAs are not
// routable outside the cluster, exactly like the v4 pod CIDRs.
static __always_inline int masq_snat6(struct __sk_buff *skb, struct pkt *p)
{
	if (!is_masq_src(p->src) || is_internal(p->dst))
		return MASQ_MISS;
	if (v6_link_scoped(&p->dst))
		return MASQ_MISS; // NDP and friends are the node's own business
	struct addr128 *node6 = masq_node6();
	if (!node6)
		return MASQ_MISS;
	struct addr128 node = *node6, src = p->src;
	__u8 proto = p->proto;

	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 id;
		if (icmp6_echo(skb, &type, &id) < 0 || type != ICMP6_ECHO_REQUEST)
			return MASQ_MISS;
		struct ct_fwd_key fk = {
			.proto = proto, .net = 0,
			.client_ip = src, .fabric_ip = p->dst,
			.client_port = id,
		};
		__u16 gw_id;
		__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
		if (have) {
			gw_id = *have;
		} else {
			gw_id = alloc_gw_port_in(proto, 0, p->dst, 0, src, src, id,
						 MASQ_PORT_BASE, MASQ_PORT_SPAN);
			if (!gw_id)
				return MASQ_MISS;
			bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
		}
		nat_addr6(skb, proto, IP6_SADDR_OFF, &src, &node);
		nat_icmp6_id(skb, id, gw_id);
		return TC_ACT_OK;
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return MASQ_MISS;
	__u16 sport, dport;
	if (l4_ports6(skb, &sport, &dport) < 0)
		return MASQ_MISS;
	struct ct_fwd_key fk = {
		.proto = proto, .net = 0,
		.client_ip = src, .fabric_ip = p->dst,
		.client_port = sport, .pod_port = dport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port_in(proto, 0, p->dst, dport, src, src, sport,
					   MASQ_PORT_BASE, MASQ_PORT_SPAN);
		if (!gw_port)
			return MASQ_MISS;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}
	nat_addr6(skb, proto, IP6_SADDR_OFF, &src, &node);
	nat_port6(skb, proto, L4_SPORT_OFF6, sport, gw_port);
	return TC_ACT_OK;
}

static __always_inline int masq_reverse6(struct __sk_buff *skb, struct pkt *p)
{
	struct addr128 *node6 = masq_node6();
	if (!node6 || !addr128_eq(&p->dst, node6))
		return MASQ_MISS;
	struct addr128 node = *node6;
	__u8 proto = p->proto;

	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 sport, dport;
		if (l4_ports6(skb, &sport, &dport) < 0)
			return MASQ_MISS;
		__u16 h = bpf_ntohs(dport);
		if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
			return MASQ_MISS;
		struct ct_rev_key rk = {
			.proto = proto, .gw_port = dport, .net = 0,
			.vpc_ip = p->src, .pod_port = sport,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return MASQ_MISS;
		nat_addr6(skb, proto, IP6_DADDR_OFF, &node, &rv->fabric_ip);
		nat_port6(skb, proto, L4_DPORT_OFF6, dport, rv->client_port);
		return TC_ACT_OK;
	}
	if (proto != IPPROTO_ICMPV6)
		return MASQ_MISS;
	__u8 type;
	__u16 id;
	if (icmp6_echo(skb, &type, &id) < 0)
		return MASQ_MISS;
	if (type == ICMP6_ECHO_REPLY) {
		__u16 h = bpf_ntohs(id);
		if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
			return MASQ_MISS;
		struct ct_rev_key rk = {
			.proto = proto, .gw_port = id, .net = 0,
			.vpc_ip = p->src,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return MASQ_MISS;
		nat_addr6(skb, proto, IP6_DADDR_OFF, &node, &rv->fabric_ip);
		nat_icmp6_id(skb, id, rv->client_port);
		return TC_ACT_OK;
	}
	if (!icmp6_err(type))
		return MASQ_MISS;
	struct emb6 e;
	if (emb6_load(skb, &e) < 0)
		return MASQ_MISS;
	if (e.proto != IPPROTO_TCP && e.proto != IPPROTO_UDP)
		return MASQ_MISS;
	if (!addr128_eq(&e.saddr, &node))
		return MASQ_MISS;
	__u16 h = bpf_ntohs(e.sport);
	if (h < MASQ_PORT_BASE || h >= MASQ_PORT_BASE + MASQ_PORT_SPAN)
		return MASQ_MISS;
	struct ct_rev_key rk = {
		.proto = e.proto, .gw_port = e.sport, .net = 0,
		.vpc_ip = e.daddr, .pod_port = e.dport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return MASQ_MISS;
	struct addr128 pod = rv->fabric_ip;
	nat_addr6(skb, IPPROTO_ICMPV6, IP6_DADDR_OFF, &node, &pod);
	emb6_rewrite(skb, &e, &pod, &e.daddr, EMB6_SPORT_OFF, e.sport, rv->client_port);
	return TC_ACT_OK;
}

// cozyplane_from_pod: source-side hook (pod egress). Enforces isolation, then
// delivers: same-node via redirect, cross-node via encap, off-VPC via gateway.
// ---- ServiceVIP load balancing (services-in-vpc.md increment 2) -----------
// A VPC pod's connection to a ServiceVIP is DNAT'd to a backend VPC IP at the
// client's from_pod (after admission — same net or peered) and rev-SNAT'd back
// to the VIP at the client's to_pod. Backend choice is pinned per flow
// (svc_fwd) so a backend-set change never moves an established connection;
// the reverse entry (svc_rev) lives on the client's node, where both
// directions of the flow are guaranteed to pass.

#define SVC_MISS -1

static __always_inline __u32 svc_hash(const struct pkt *p, __u16 sport, __u16 dport)
{
	__u32 a, b;
	__builtin_memcpy(&a, &p->src.b[12], 4);
	__builtin_memcpy(&b, &p->dst.b[12], 4);
	// The caller reduces this with `% n` for tiny n, and the raw 5-tuple has
	// almost no low-bit entropy across a client's successive flows: the
	// kernel steps ephemeral source ports by a fixed stride (commonly 2), so
	// any XOR-only mix keeps `% 2` CONSTANT per client (found live — every
	// flow stuck to one backend). Knuth's multiplicative hash + a fold
	// avalanches the stride into the low bits.
	__u32 h = a ^ (b << 1) ^ sport ^ ((__u32)dport << 16) ^ p->proto;
	h *= 2654435761u;
	return h ^ (h >> 16);
}

// svc_forward: DNAT an admitted vip:vport packet to backend:tport. On a hit
// p->dst is updated so the caller's delivery continues toward the backend;
// a hairpin (backend == client) additionally SNATs the source to the
// loopback. Returns SVC_MISS when the destination is not a VIP.
static __always_inline int svc_forward(struct __sk_buff *skb, struct pkt *p, __u32 srcnet, __u32 dstnet)
{
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
		return SVC_MISS;
	if (!p->is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return SVC_MISS;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return SVC_MISS;

	struct svc_key sk = { .net = dstnet, .vip = p->dst, .proto = p->proto, .port = dport };
	struct svc_val *sv = bpf_map_lookup_elem(&svc_vips, &sk);
	if (!sv || !sv->n)
		return SVC_MISS;

	struct addr128 backend;
	__u16 tport, hairpin;
	struct svc_fwd_key fk = { .net = srcnet, .proto = p->proto, .cport = sport,
				  .client = p->src, .vip = p->dst, .vport = dport };
	struct svc_fwd_val *pin = bpf_map_lookup_elem(&svc_fwd, &fk);
	if (pin) {
		backend = pin->backend;
		tport = pin->tport;
		hairpin = pin->hairpin;
	} else {
		__u32 n = sv->n;
		if (!n)
			return SVC_MISS;
		if (n > SVC_MAX_BACKENDS)
			n = SVC_MAX_BACKENDS;
		// ClientIP affinity: drop the source port from the selection hash so
		// every flow from one client picks the same backend (the flow-pin
		// still keys on the real port, so each connection is tracked).
		__u16 hport = (sv->flags & SVC_F_AFFINITY) ? 0 : sport;
		// Multiply-shift reduction (idx = hash * n >> 32), NOT `% n`. Modulo
		// depends on the hash's LOW bits, and the kernel hands out ephemeral
		// source ports of one parity in a burst (Talos: all-even) — starving
		// the low bits so every flow from a client collapsed onto one backend
		// (found live on dev4). The high 32 bits of the 64-bit product carry
		// the full avalanche, so this is uniform for any n and any port stride.
		__u32 idx = (__u32)(((__u64)svc_hash(p, hport, dport) * n) >> 32);
		// Bound the index with an AND the compiler cannot elide (a plain
		// `if (idx >= MAX)` is provably dead to clang — idx < n <= MAX — so
		// it gets optimized out and the verifier never sees a bound on the
		// map-value pointer math). The asm emits a real BPF instruction.
		asm volatile("%0 &= %1" : "+r"(idx) : "i"(SVC_MAX_BACKENDS - 1));
		backend = sv->be[idx].ip;
		tport = sv->be[idx].port;
		hairpin = addr128_eq(&backend, &p->src) ? 1 : 0;
		struct svc_fwd_val fv = { .backend = backend, .tport = tport, .hairpin = hairpin };
		bpf_map_update_elem(&svc_fwd, &fk, &fv, BPF_ANY);
		struct svc_rev_key rk = { .net = srcnet, .proto = p->proto, .cport = sport,
					  .backend = backend, .client = p->src, .tport = tport };
		struct svc_rev_val rv = { .vip = p->dst, .vport = dport };
		bpf_map_update_elem(&svc_rev, &rk, &rv, BPF_ANY);
	}

	if (p->is_v6) {
		struct addr128 odst = p->dst, nb = backend;
		nat_addr6(skb, p->proto, IP6_DADDR_OFF, &odst, &nb);
		if (dport != tport)
			nat_port6(skb, p->proto, L4_DPORT_OFF6, dport, tport);
		if (hairpin) {
			struct addr128 osrc = p->src, lp = SVC_LOOPBACK6;
			nat_addr6(skb, p->proto, IP6_SADDR_OFF, &osrc, &lp);
		}
	} else {
		nat_addr(skb, p->proto, IP_DADDR_OFF, v4_of_128(&p->dst), v4_of_128(&backend));
		if (dport != tport)
			nat_port(skb, p->proto, L4_DPORT_OFF, dport, tport);
		if (hairpin)
			nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), bpf_htonl(SVC_LOOPBACK));
	}
	p->dst = backend; // delivery continues toward the backend
	return 0;
}

// svc_return: the reply half, at the client's to_pod — backend:tport back to
// vip:vport. A hit is sanctioned (the forward direction was admitted).
static __always_inline int svc_return(struct __sk_buff *skb, struct pkt *p, __u32 dstnet)
{
	if (!dstnet)
		return SVC_MISS;
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
		return SVC_MISS;
	if (!p->is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return SVC_MISS;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return SVC_MISS;

	struct svc_rev_key rk = { .net = dstnet, .proto = p->proto, .cport = dport,
				  .backend = p->src, .client = p->dst, .tport = sport };
	struct svc_rev_val *rv = bpf_map_lookup_elem(&svc_rev, &rk);
	if (!rv)
		return SVC_MISS;

	if (p->is_v6) {
		struct addr128 osrc = p->src, vip = rv->vip;
		nat_addr6(skb, p->proto, IP6_SADDR_OFF, &osrc, &vip);
		if (sport != rv->vport)
			nat_port6(skb, p->proto, L4_SPORT_OFF6, sport, rv->vport);
	} else {
		__u32 vip4 = v4_of_128(&rv->vip);
		nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), vip4);
		if (sport != rv->vport)
			nat_port(skb, p->proto, L4_SPORT_OFF, sport, rv->vport);
	}
	return TC_ACT_OK;
}

// svc_hairpin_reverse: the reply of a self-dial, at the pod's own from_pod —
// the server half answers to the loopback; restore vip:vport -> client and
// deliver straight back into the same pod.
static __always_inline int svc_hairpin_reverse(struct __sk_buff *skb, struct pkt *p, __u32 srcnet)
{
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
		return TC_ACT_SHOT;
	if (!p->is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return TC_ACT_SHOT;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return TC_ACT_SHOT;

	// Hairpin means client == backend == this pod (the packet's source).
	struct svc_rev_key rk = { .net = srcnet, .proto = p->proto, .cport = dport,
				  .backend = p->src, .client = p->src, .tport = sport };
	struct svc_rev_val *rv = bpf_map_lookup_elem(&svc_rev, &rk);
	if (!rv)
		return TC_ACT_SHOT; // loopback-addressed with no flow: nothing legitimate

	struct addr128 client = p->src;
	if (p->is_v6) {
		struct addr128 osrc = p->src, vip = rv->vip, odst = p->dst, ncl = client;
		nat_addr6(skb, p->proto, IP6_SADDR_OFF, &osrc, &vip);
		if (sport != rv->vport)
			nat_port6(skb, p->proto, L4_SPORT_OFF6, sport, rv->vport);
		nat_addr6(skb, p->proto, IP6_DADDR_OFF, &odst, &ncl);
	} else {
		nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), v4_of_128(&rv->vip));
		if (sport != rv->vport)
			nat_port(skb, p->proto, L4_SPORT_OFF, sport, rv->vport);
		nat_addr(skb, p->proto, IP_DADDR_OFF, v4_of_128(&p->dst), v4_of_128(&client));
	}
	struct endpoint *l = local_of(srcnet, client);
	if (!l)
		return TC_ACT_SHOT;
	return deliver_local(skb, l);
}

// ---- VPC DNS steering (split-horizon resolver) ----------------------------
// A VPC pod's query to the cluster DNS address cannot be answered by kube-dns
// (unreachable from a VPC by design); it is steered to the node-local
// split-horizon resolver instead. Both halves are stateless — no ct entry, no
// port allocation: the forward half rewrites {VPC src -> the pod's fabric IP,
// clusterDNS:53 -> node:resolver_port} (sport preserved; fabric IPs are unique,
// so the 5-tuple stays unambiguous), and the reverse half recovers everything
// from the bridges map + config. The fabric source doubles as the per-Port
// handle the resolver keys the tenant view on.

#define DNS_MISS -1

static __always_inline int addr128_zero(const struct addr128 *a)
{
#pragma unroll
	for (int i = 0; i < 16; i++)
		if (a->b[i])
			return 0;
	return 1;
}

// dns_steer: from_pod's forward half. Called only for a non-gateway VPC pod
// whose destination resolved off-VPC (dstnet == 0) — so a tenant whose own
// CIDR covers the cluster service range keeps its :53 traffic to itself, and
// pod-to-pod DNS inside a VPC is never hijacked.
static __always_inline int dns_steer(struct __sk_buff *skb, struct pkt *p, __u32 srcnet)
{
	__u16 rport = (__u16)cfg(CFG_RESOLVER_PORT);
	if (!rport)
		return DNS_MISS;
	if (p->proto != IPPROTO_UDP && p->proto != IPPROTO_TCP)
		return DNS_MISS;
	if (!p->is_v6) {
		// The fixed offsets below assume an options-free v4 header,
		// like the rest of the bridge NAT.
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return DNS_MISS;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return DNS_MISS;
	if (dport != bpf_htons(53))
		return DNS_MISS;

	// The query's wire destination is the cluster DNS address — or, under a
	// socket-LB kube-proxy replacement that already translated the ClusterIP
	// at connect() time, one of its backends: any *cluster-internal* :53 the
	// pod cannot legitimately reach is the cluster resolver in some form. A
	// tenant's DNS to an off-cluster server (via its egress gateway) never
	// matches; in-VPC :53 never even gets here (dstnet != 0).
	__u32 fam = p->is_v6 ? 1 : 0;
	struct addr128 *dns = bpf_map_lookup_elem(&dns_ips, &fam);
	if (!dns || addr128_zero(dns))
		return DNS_MISS;
	if (!addr128_eq(dns, &p->dst) && !is_internal(p->dst))
		return DNS_MISS;

	struct local_key fk = { .net = srcnet, .ip = p->src };
	struct addr128 *fabp = bpf_map_lookup_elem(&fabric_of, &fk);
	if (!fabp)
		return DNS_MISS; // no same-family fabric handle: fall through (drop/gateway)

	// Remember the original destination: the reply must appear to come from
	// it (a connected socket filters on it, and the socket-LB reverse hook
	// translates it back to the ClusterIP for the application).
	struct dns_ct_key ck = { .proto = p->proto, .sport = sport, .fabric = *fabp };
	bpf_map_update_elem(&dns_ct, &ck, &p->dst, BPF_ANY);

	if (p->is_v6) {
		__u32 zero = 0;
		struct addr128 *n6 = bpf_map_lookup_elem(&node_ip6, &zero);
		if (!n6 || addr128_zero(n6))
			return DNS_MISS;
		struct addr128 fab = *fabp, node = *n6;
		nat_addr6(skb, p->proto, IP6_SADDR_OFF, &p->src, &fab);
		nat_addr6(skb, p->proto, IP6_DADDR_OFF, &p->dst, &node);
		nat_port6(skb, p->proto, L4_DPORT_OFF6, bpf_htons(53), bpf_htons(rport));
		return TC_ACT_OK; // up the host stack to the resolver socket
	}

	__u32 node4 = cfg(CFG_NODE_IP);
	if (!node4)
		return DNS_MISS;
	__u32 fab4 = v4_of_128(fabp);
	nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), fab4);
	nat_addr(skb, p->proto, IP_DADDR_OFF, v4_of_128(&p->dst), node4);
	nat_port(skb, p->proto, L4_DPORT_OFF, bpf_htons(53), bpf_htons(rport));
	return TC_ACT_OK;
}

// dns_return: to_pod's reverse half. The resolver's reply —
// node:resolver_port -> fabric:sport, routed here by the fabric /32 — is
// rewritten back to clusterDNS:53 -> VPC IP before delivery, so the pod's stub
// resolver sees the answer come from the address it queried. Sanctioned path:
// on a hit the packet is delivered without the ingress isolation check, like
// the bridge. Kubelet probes to the same fabric IP never match: their source
// port is ephemeral, not the reserved resolver port.
static __always_inline int dns_return(struct __sk_buff *skb, struct pkt *p)
{
	__u16 rport = (__u16)cfg(CFG_RESOLVER_PORT);
	if (!rport)
		return DNS_MISS;
	if (p->proto != IPPROTO_UDP && p->proto != IPPROTO_TCP)
		return DNS_MISS;
	if (!p->is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return DNS_MISS;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return DNS_MISS;
	if (sport != bpf_htons(rport))
		return DNS_MISS;

	// Source must be this node (the resolver binds the node address).
	if (p->is_v6) {
		__u32 zero = 0;
		struct addr128 *n6 = bpf_map_lookup_elem(&node_ip6, &zero);
		if (!n6 || addr128_zero(n6) || !addr128_eq(n6, &p->src))
			return DNS_MISS;
	} else {
		if (v4_of_128(&p->src) != cfg(CFG_NODE_IP))
			return DNS_MISS;
	}

	struct bridge_ep *be = bridge_of(p->dst);
	if (!be)
		return DNS_MISS;

	// Restore the query's original wire destination as the reply source (the
	// ClusterIP, or the backend a socket-LB KPR had translated it to). On an
	// LRU eviction fall back to the cluster DNS address — correct for every
	// non-socket-LB deployment.
	struct addr128 orig;
	struct dns_ct_key ck = { .proto = p->proto, .sport = dport, .fabric = p->dst };
	struct addr128 *op = bpf_map_lookup_elem(&dns_ct, &ck);
	if (op) {
		orig = *op;
	} else {
		__u32 fam = p->is_v6 ? 1 : 0;
		struct addr128 *dns = bpf_map_lookup_elem(&dns_ips, &fam);
		if (!dns || addr128_zero(dns))
			return DNS_MISS;
		orig = *dns;
	}

	if (p->is_v6) {
		struct addr128 vpc = be->vpc_ip;
		nat_addr6(skb, p->proto, IP6_SADDR_OFF, &p->src, &orig);
		nat_addr6(skb, p->proto, IP6_DADDR_OFF, &p->dst, &vpc);
		nat_port6(skb, p->proto, L4_SPORT_OFF6, bpf_htons(rport), bpf_htons(53));
		return TC_ACT_OK;
	}
	__u32 vpc4 = v4_of_128(&be->vpc_ip);
	nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), v4_of_128(&orig));
	nat_addr(skb, p->proto, IP_DADDR_OFF, v4_of_128(&p->dst), vpc4);
	nat_port(skb, p->proto, L4_SPORT_OFF, bpf_htons(rport), bpf_htons(53));
	return TC_ACT_OK;
}

SEC("tc")
int cozyplane_from_pod(struct __sk_buff *skb)
{
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;

	__u32 ifindex = skb->ifindex;
	__u32 srcnet = 0, is_gw = 0;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	if (sp) {
		srcnet = PORT_NET(*sp);
		is_gw = *sp & PORT_F_GATEWAY;
	}

	// At the uplink-egress attachment only: bpf cluster-egress masquerade
	// (#10). A kernel-forwarded pod packet leaving the cluster gets SNAT'd
	// here instead of by an iptables MASQUERADE rule. Everything else (node
	// traffic, geneve encap, floated egress with its public source) misses.
	if (ifindex == cfg(CFG_UPLINK_IFINDEX)) {
		int m = p.is_v6 ? masq_snat6(skb, &p) : masq_snat(skb, &p);
		if (m != MASQ_MISS)
			return m;
	}

	// A v6 VPC pod's reply to fe80::1 is the return half of the v6 fabric bridge:
	// un-NAT it and deliver on the default network. Tested before the link-scoped
	// bypass below because it is *unicast* to the gateway, whereas NDP is to the
	// solicited-node multicast — so the two never collide.
	struct addr128 gw6 = LINK_LOCAL_GW6;
	if (p.is_v6 && addr128_eq(&p.dst, &gw6))
		return bridge_reverse6(skb, &p, srcnet);

	// A self-dialled ServiceVIP's reply half answers to the hairpin loopback;
	// like fe80::1 above, checked before the link-scoped bypass.
	struct addr128 svclp6 = SVC_LOOPBACK6;
	if (p.is_v6 && addr128_eq(&p.dst, &svclp6))
		return svc_hairpin_reverse(skb, &p, srcnet);

	// v6 link-local / multicast (the pod resolving its on-link gateway via NDP,
	// router solicitations, …) is link-scoped: hand it to the kernel so the host
	// veth answers, never overlay-deliver it or subject it to isolation.
	if (p.is_v6 && v6_link_scoped(&p.dst))
		return TC_ACT_OK;

	// The destination's network, resolved within the source's scope: its own
	// CIDR or a peer's. Overlapping CIDRs in other VPCs are invisible here.
	// Family-agnostic — the addresses are already 128-bit map keys.
	__u32 dstnet = net_of(&networks, srcnet, p.dst);

	// VPC DNS: a pod's off-VPC query to the cluster DNS address is steered to
	// the node-local split-horizon resolver — checked before the floating/
	// gateway/isolation logic so every VPC pod (floating, gateway'd, or plain)
	// gets DNS the same way, and only when the destination resolved off-VPC,
	// so a tenant whose CIDR covers the service range shadows it (sovereignty).
	if (srcnet && !is_gw && !dstnet) {
		int d = dns_steer(skb, &p, srcnet);
		if (d != DNS_MISS)
			return d;
	}

	// The north-south bridge and floating IPs are v4-only today (v6 fabric IPs
	// and an NDP responder are later phases), so a v6 packet skips straight to
	// the family-agnostic overlay delivery below.
	if (!p.is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0)
			return TC_ACT_OK;
		// A VPC pod's reply to the gateway (169.254.1.1) is the return half of
		// the north-south bridge: un-NAT it and deliver on the default network.
		if (ip->daddr == bpf_htonl(LINK_LOCAL_GW))
			return bridge_reverse(skb, ip, srcnet);
		// A self-dialled ServiceVIP's reply half answers to the hairpin
		// loopback: restore vip -> client and re-deliver into the pod.
		if (ip->daddr == bpf_htonl(SVC_LOOPBACK))
			return svc_hairpin_reverse(skb, &p, srcnet);
		// Off-net traffic from a floating pod egresses from its public IP (both
		// its replies and the connections it originates): SNAT VPC->public and
		// redirect out the uplink, dropping cluster-internal destinations.
		// Checked before isolation, which would otherwise send it to the gateway
		// or drop it. On a hit floating_egress_snat returns the action; on a miss
		// the packet is untouched, so p.src/p.dst (stack copies) stay valid.
		if (srcnet && !dstnet) {
			int fr = floating_egress_snat(skb, ip, srcnet);
			if (fr != FLOAT_MISS)
				return fr;
		}
	}
	// The v6 twin: a floating v6 pod's internet-bound traffic egresses from
	// its public address. Link-scoped v6 (NDP) was already bypassed above.
	if (p.is_v6 && srcnet && !dstnet) {
		int fr = floating_egress_snat6(skb, &p, srcnet);
		if (fr != FLOAT_MISS)
			return fr;
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

	// ServiceVIP: an admitted packet (same net or peered) whose destination is
	// a VIP of the destination net is DNAT'd to a backend VPC IP here — the
	// rewrite updates p.dst, so the delivery below simply carries on toward
	// the backend. A miss leaves the packet untouched.
	if (srcnet && !is_gw)
		svc_forward(skb, &p, srcnet, dstnet);

	// Same-node destination: redirect through the pod's veth egress (-> to_pod)
	// — VPC nets only. Default-network (net 0) traffic is delivered by the
	// kernel, as the model requires: a direct redirect would bypass netfilter,
	// and with it kube-proxy's conntrack — a ClusterIP reply from a same-node
	// backend then reaches the client still carrying the backend's source,
	// never un-DNAT'd, and the client's socket discards it. (Latent since M0;
	// surfaced whenever the scheduler co-located a client with its coredns.)
	if (dstnet) {
		struct endpoint *l = local_of(dstnet, p.dst);
		if (l) {
			// A gateway forwarding into its VPC may carry an off-VPC source
			// (the internet's reply); mark it so the destination's anti-spoof
			// admits it.
			if (is_gw)
				skb->mark = GW_MARK;
			return deliver_local(skb, l);
		}
	}

	// Remote destination in the same network (or a peer): encapsulate. Stamp
	// the source pod's authoritative group identity (stage B) so the receiver
	// trusts it across a peering. srcnet/p.src are the source node's own view
	// (from the veth's `ports` entry), not the (spoofable) claimed source.
	__u32 *node_ip = remote_of(dstnet, p.dst);
	if (node_ip) {
		__u64 srcmap = 0;
		if (srcnet && !is_gw) {
			struct local_key sk = { .net = srcnet, .ip = p.src };
			__u64 *sm = bpf_map_lookup_elem(&sg_members, &sk);
			if (sm)
				srcmap = *sm;
		}
		return encap_sg(skb, dstnet, *node_ip, is_gw, srcnet, srcmap);
	}

	// Same-node north-south: a default-network packet to a local VPC pod's
	// fabric IP. Redirect into the pod's veth (to_pod does the DNAT), bypassing
	// the kernel FORWARD chain so no netfilter accept rule is needed. Fabric IPs
	// are v4-only, so a v6 packet always misses here and falls to the kernel.
	struct bridge_ep *be = bridge_of(p.dst);
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
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;

	// The split-horizon resolver's DNS reply re-enters the pod here; un-NAT it
	// before the bridge below would masquerade it to the gateway address.
	int dr = dns_return(skb, &p);
	if (dr != DNS_MISS)
		return dr;

	// The north-south bridge and floating IPs are v4-only today; a v6 packet
	// goes straight to the family-agnostic isolation check below.
	if (!p.is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0)
			return TC_ACT_OK;
		// The forward half of the north-south bridge: a packet whose destination
		// is a fabric IP (routed here by the pod's /32) is DNATed to the VPC IP
		// and its client masqueraded to the gateway, then delivered — no
		// isolation check (this IS the sanctioned north-south path). Fabric IPs
		// are unique, so the lookup is unambiguous under overlapping VPC CIDRs.
		struct bridge_ep *be = bridge_of(p.dst);
		if (be)
			return bridge_forward(skb, ip, be->net, be->vpc_ip);

		// A floating IP: DNAT public->VPC, preserving the external client's
		// source. Also sanctioned north-south (no isolation check follows).
		struct bridge_ep *fe = float_of(p.dst);
		if (fe)
			return floating_forward(skb, ip, fe->net, fe->vpc_ip);

		// A masqueraded reply already carries the gateway source; allow it.
		if (ip->saddr == bpf_htonl(LINK_LOCAL_GW))
			return TC_ACT_OK;
		// The forward half of a hairpinned ServiceVIP self-dial carries the
		// loopback source (from_pod SNAT'd it); it never leaves the veth.
		if (ip->saddr == bpf_htonl(SVC_LOOPBACK))
			return TC_ACT_OK;
	}

	// The forward half of the v6 fabric bridge: destination is a v6 fabric IP ->
	// DNAT to the VPC IP and masquerade the client to fe80::1, then deliver. No
	// isolation check (this IS the sanctioned north-south path). Same bridges map
	// as v4, keyed by the 128-bit address, so a v6 fabric IP resolves here.
	if (p.is_v6) {
		// A v6 floating IP: stateless DNAT public->VPC, client preserved.
		struct bridge_ep *fe6 = float_of(p.dst);
		if (fe6)
			return floating_forward6(skb, &p, fe6->net, fe6->vpc_ip);
		struct bridge_ep *be = bridge_of(p.dst);
		if (be)
			return bridge_forward6(skb, &p, be->net, be->vpc_ip);
	}

	// v6 link-local / multicast reaching the pod (an NA from its on-link gateway,
	// router advertisements, …) is link-scoped; admit it without isolation.
	if (p.is_v6 && v6_link_scoped(&p.src))
		return TC_ACT_OK;

	__u32 ifindex = skb->ifindex;
	__u32 dstnet = 0;
	__u32 *dp = bpf_map_lookup_elem(&ports, &ifindex);
	if (dp)
		dstnet = PORT_NET(*dp);

	// A ServiceVIP backend's reply re-enters the client here: restore
	// backend:tport -> vip:vport. A hit is sanctioned — the forward direction
	// was admitted at the client's from_pod (same net or peered).
	int sr = svc_return(skb, &p, dstnet);
	if (sr != SVC_MISS)
		return sr;

	// Recover the source's network from the destination's scope (symmetric to
	// from_pod): its own CIDR or a peer's under this pod's network.
	__u32 srcnet = net_of(&networks, dstnet, p.src);

	// Isolation: same-network or explicitly peered traffic only (ingress side).
	// The exception is gateway-forwarded traffic into a VPC pod: its source is
	// off-VPC (the internet, cluster DNS) so srcnet is 0, but it carries the
	// in-kernel gateway mark that tenants cannot forge.
	if (!nets_allowed(srcnet, dstnet)) {
		if (!(srcnet == 0 && dstnet != 0 && skb->mark == GW_MARK))
			return TC_ACT_SHOT;
	}

	// Security-group ingress (destination-side, #7). Only genuine intra-VPC /
	// peered pod-to-pod traffic is gated: gateway-forwarded ingress (GW_MARK —
	// internet/DNS replies) is north-south and stateful-reply territory, left
	// alone. A same-VPC peered source's groups come from its own net
	// (sg_members[{srcnet, src}]); a peer with no admitting rule still misses and
	// is dropped once the destination is grouped (AWS-shaped default-deny).
	//
	// SG_OK means from_overlay already enforced this cross-node packet
	// authoritatively from the source's Geneve TLV (stage B) — skip the
	// (spoofable) inference here rather than re-check it.
	if (dstnet && !(skb->mark & (GW_MARK | SG_OK))) {
		__u16 dport;
		__u32 l4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
		if (sg_l4(skb, p.proto, l4off, &dport)) {
			// The source's groups live under the source's OWN net (srcnet ==
			// dstnet intra-VPC; the peer's VNI across a peering), and peer-group
			// rules are keyed by that src_net — so a peered group matches.
			struct local_key sk = { .net = srcnet, .ip = p.src };
			__u64 *sm = bpf_map_lookup_elem(&sg_members, &sk);
			struct sg_query q = {
				.dst = { .net = dstnet, .ip = p.dst },
				.src_net = srcnet,
				.srcmap = sm ? *sm : 0,
				.dport = dport,
				.proto = p.proto,
			};
			if (!sg_admit(&q)) {
				count_sg_drop(dstnet);
				return TC_ACT_SHOT;
			}
		}
	}

	// Meter admitted east-west traffic (#2), both directions from this one
	// placement-independent delivery hook: rx for the destination's net, tx
	// for the source's (same net intra-VPC, the peer's across a peering). A
	// VPC pod's own from_pod is too stack-heavy to host a BPF-to-BPF call, so
	// all east-west metering happens here. North-south (bridge/floating) and
	// ServiceVIP replies return earlier and aren't metered yet.
	count_dir(srcnet, skb->len, 0);
	count_dir(dstnet, skb->len, 1);

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

	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;

	__u32 gw = tk.tunnel_id & TUN_F_GATEWAY;
	__u32 vni = (__u32)tk.tunnel_id & ~TUN_F_GATEWAY;
	if (vni == cfg(CFG_VNI)) {
		// Default network. A cross-node north-south packet to a local VPC pod's
		// fabric IP (either family; the bridges map is 128-bit) is delivered to
		// its veth here (to_pod does the DNAT), bypassing the kernel FORWARD
		// chain; everything else — including the north-south *reply* toward a
		// default-network pod — is handed to the kernel, which is why
		// EnsureForwardRules must ACCEPT overlay traffic in both families.
		struct bridge_ep *be = bridge_of(p.dst);
		if (be) {
			struct endpoint *l = local_of(be->net, be->vpc_ip);
			if (l)
				return deliver_local(skb, l);
		}
		return TC_ACT_OK;
	}

	// A local pod in this VPC (intra-VPC, peered, or a gateway->tenant reply).
	// The lookup is 128-bit, so a v6 VPC pod is delivered exactly like a v4 one.
	struct endpoint *ep = local_of(vni, p.dst);
	if (ep) {
		if (gw) {
			skb->mark = GW_MARK;
		} else {
			// Authoritative security-group enforcement (stage B): a grouped
			// source stamped its {net, groups} in a Geneve option. Enforce it
			// here — the only place the tunnel metadata is readable — and mark
			// it done so to_pod won't re-check via (spoofable) inference. An
			// ungrouped source carries no option and falls through to to_pod's
			// same-node/inference path.
			struct sg_geneve_opt opt;
			if (bpf_skb_get_tunnel_opt(skb, (void *)&opt, sizeof(opt)) >= (int)sizeof(opt) &&
			    opt.opt_class == bpf_htons(SG_OPT_CLASS) && opt.type == SG_OPT_TYPE) {
				__u16 dport;
				__u32 l4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
				if (sg_l4(skb, p.proto, l4off, &dport)) {
					struct sg_query q = {
						.dst = { .net = vni, .ip = p.dst },
						.src_net = opt.src_net,
						.srcmap = opt.srcmap,
						.dport = dport,
						.proto = p.proto,
					};
					if (!sg_admit(&q)) {
						count_sg_drop(vni);
						return TC_ACT_SHOT;
					}
				}
				skb->mark |= SG_OK;
			}
		}
		return deliver_local(skb, ep);
	}

	// Not a local pod: tenant->outside traffic for a gateway hosted here.
	struct gw_entry *g = bpf_map_lookup_elem(&gateways, &vni);
	if (g && !g->node_ip) {
		struct endpoint *gep = local_of(vni, g->gw_ip);
		if (gep)
			return deliver_local(skb, gep);
	}

	// Migration forwarding (stage 2): this was the source node of a VM that
	// has moved. A remote node with a stale `remotes` entry still delivered
	// here; re-encapsulate to the target so nothing drops during the cutover
	// window. The target hosts the VM locally, so there is no loop.
	struct local_key mk = { .net = vni, .ip = p.dst };
	__u32 *tgt = bpf_map_lookup_elem(&migrate_fwd, &mk);
	if (tgt)
		return encap(skb, vni, *tgt, 0);

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
	int ndp = floating_ndp(skb);
	if (ndp != FLOAT_MISS)
		return ndp;

	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0) {
		// v6 inbound to a floating address: deliver to the local pod like the
		// v4 path below (to_pod on its veth does the public->VPC DNAT).
		struct pkt p6;
		if (parse_ip(skb, &p6) == 0 && p6.is_v6) {
			int m6 = masq_reverse6(skb, &p6);
			if (m6 != MASQ_MISS)
				return m6;
			struct bridge_ep *fe6 = float_of(p6.dst);
			if (fe6) {
				struct endpoint *l6 = local_of(fe6->net, fe6->vpc_ip);
				if (l6)
					return deliver_local(skb, l6);
			}
		}
		return TC_ACT_OK;
	}

	// Un-SNAT replies to bpf-masqueraded cluster egress (#10) before netfilter
	// sees them: the kernel's conntrack watched the pod-sourced flow leave, so
	// the restored reply matches ESTABLISHED and routes to the pod normally.
	struct pkt mp;
	if (parse_ip(skb, &mp) == 0 && !mp.is_v6) {
		int m = masq_reverse(skb, &mp);
		if (m != MASQ_MISS)
			return m;
	}

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
