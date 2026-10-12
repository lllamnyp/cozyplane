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
#define AF_INET 2 // for bpf_redir_neigh.nh_family (vmlinux.h carries no macros)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
// TCX_NEXT: not ours -- hand the packet to the next tcx program (Cilium in the
// chained variant); at the end of the chain it behaves as TC_ACT_OK. TC_ACT_OK
// itself is TCX_PASS, which ends the chain and would starve Cilium KPR.
#define TC_ACT_NEXT -1
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

// A 6-byte MAC in an 8-byte cell.
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
#define TCP_MIN_HLEN 20
#define TCP_MSS_KIND 2
#define TCP_MSS_LEN  4
#define TCP_OPT_EOL  0
#define TCP_OPT_NOP  1
#define TCP_SYN      0x02
#define TCP_ACK      0x10
// The lowest safe TCP payload across the default 1450 VPC leg, Geneve and the
// larger route-based IPsec/NAT-T overhead. Route-specific MTU is still enforced
// by the kernel; this only prevents a new TCP flow from depending on PMTU ICMP.
#define TCP_MSS_CLAMP 1200
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
// PORT_F_FORWARD marks a TENANT forwarding leg — a router or firewall attached
// to several VPCs (docs/multi-attach.md). It is deliberately NOT PORT_F_GATEWAY.
// Both lift the source-address RPF check, and there the resemblance must stop:
// a gateway's traffic is north-south and is exempted from east-west
// SecurityGroups, while a tenant router is the one workload whose traffic most
// needs policing. Reusing the gateway flag silently disabled SecurityGroups for
// the forwarder — measured on a live cluster before this bit existed.
#define PORT_F_FORWARD (1u << 30)
// PORT_F_FWD_SCOPED narrows PORT_F_FORWARD to declared prefixes (issue #6,
// VPCBinding.forwardingCIDRs): a foreign source is admitted only if it matches
// this port's `fwd_cidrs` allowlist, instead of the blanket "any foreign source"
// PORT_F_FORWARD alone grants. Set by the CNI when the binding names CIDRs;
// clear means the legacy all-foreign behaviour.
#define PORT_F_FWD_SCOPED (1u << 29)
#define PORT_NET(v) ((v) & ~(PORT_F_GATEWAY | PORT_F_FORWARD | PORT_F_FWD_SCOPED))
#define PORT_QUARANTINE 0xffffffffU

// Gateway-forwarded traffic may carry an off-VPC source (the internet) into a
// tenant pod, which the ingress anti-spoof check would otherwise drop. It is
// blessed in-kernel only: same-node via skb->mark, cross-node via a flag bit
// inside the 24-bit Geneve VNI (so the receiving node can re-mark after decap).
// Tenants cannot forge either.
#define GW_MARK        0x100000  // bit 20: clear of kube-proxy (0x4000/0x8000) and Cilium magic
#define SG_OK          0x200000  // bit 21: from_overlay already enforced security groups (TLV)
#define VPC_MARK       0x040000  // bit 18: destination resolved under an authenticated VPC scope
#define NS_MARK        0x400000  // bit 22: pod-originated north-south (subject to SG); host-
                                 // originated (kubelet) reaches the bridge unmarked and exempt
#define FWD_MARK       0x080000  // bit 19: a TENANT forwarding leg handed this
                                 // packet on, and its source belongs to another
                                 // VPC. It buys passage through the destination's
                                 // ISOLATION check and nothing else — unlike
                                 // GW_MARK it does NOT skip SecurityGroups; the
                                 // destination judges it as a north-south source
                                 // (a from:{cidr} rule), because this VPC holds
                                 // no identity for an address it does not own.
#define TUN_F_GATEWAY  (1 << 23) // top bit of the Geneve VNI; real VNIs are < 2^23
#define TUN_F_FORWARD  (1 << 22) // ... and the tenant-forwarding twin, so the
                                 // receiving node can re-mark after decap. Real
                                 // VNIs are therefore < 2^22, which is 4M — the
                                 // allocator starts at 100 and increments.

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

#include "address128.h"

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
	__u64 sg_owner[4]; // SHA-256 Port UID + sandbox, computed in userspace
};

// remotes: (scope net, dst IP / node pod CIDR) -> remote node IP (host order).
// Node pod CIDRs live at scope 0 (default network); VPC pod /32s at scope=VNI.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u32);
	// Sized for PODS, not nodes: with a flat pool the default network keys
	// remotes per pod (docs/api-groups.md), so 4096 would have been a cluster-
	// wide pod cap, not a node cap.
	__uint(max_entries, 131072);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} remotes SEC(".maps");

// node_remotes: a node address (any NIC) -> that node's Geneve underlay IP (host
// order, same encoding as `remotes`). A default-network pod's reply to — or
// dial of — a node address is encapsulated to that node over the overlay, so the
// underlay only ever carries node source IPs. Without it the reply falls to the
// kernel and hits the wire with a *pod* source, which a spoof-guarding fabric
// (e.g. OCI) drops — silently black-holing every cross-node node<->pod flow
// (hostNetwork apiserver -> webhook pod is the one that bites first). Exact /128
// keys (node addresses are underlay handles, not tenant-scoped CIDRs). Populated
// by the agent from each node's InternalIP plus its advertised default-route
// source address.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, __u32);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} node_remotes SEC(".maps");

// Fresh on every load: only Kubernetes Node InternalIPs may originate overlay
// metadata. Ordinary pods must never supply a VNI or a trusted identity TLV.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // Geneve endpoint, host order
	__type(value, __u8);
	__uint(max_entries, 1024);
} overlay_nodes SEC(".maps");

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

#define ROUTE_NH_MAX 2

// A route may carry two active next-hops. The bounded array keeps the map ABI
// verifier-friendly while covering the HA contract; count is one for every
// ordinary route and two for active-active VPN ECMP.
struct route_entry {
	struct gw_entry next_hops[ROUTE_NH_MAX];
	__u8 count;
	__u8 pad[7];
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

// vpc_routes: the per-VPC route table (issue #6, docs/vpn.md §3.1). A scoped-LPM
// twin of `gateways`: keyed by {scope_net, remote prefix}, valued by the same
// {gw_ip, node_ip} next-hop, delivered the same way. Consulted in from_pod for
// an off-VPC destination BEFORE the NAT decision, so a routed remote prefix
// reaches its appliance (a VPN endpoint / router) instead of being masqueraded
// toward the internet. A miss changes nothing — the existing NAT/gateway path
// is the fallback. Net-scoped, so overlapping tenant CIDRs never collide and a
// route is tenant-scoped by construction.
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct route_entry);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_routes SEC(".maps");

// Closed while the agent compiles or replaces routes. A rejected snapshot must
// never turn a requested tunnel prefix into ordinary NAT or gateway egress.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} route_guard SEC(".maps");

// Full 22-bit tenant VNI domain: a fixed 512 KiB bitmap, no scarce hash slots.
// Blocked scopes cannot fall through to ordinary NAT when route budgets reject
// their namespace. The global guard protects publication of this bitmap too.
struct route_scope_guard {
	__u32 blocked[128];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct route_scope_guard);
	__uint(max_entries, 1024);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} route_scopes SEC(".maps");

// fwd_cidrs: a forwarding leg's allowed remote source prefixes (issue #6,
// VPCBinding.forwardingCIDRs). Scoped-LPM keyed by {veth ifindex, family, source
// prefix}; a bare presence (value 1) means "this source is a sanctioned foreign
// source for this leg". Consulted in from_pod's anti-spoof check ONLY for a
// port carrying PORT_F_FWD_SCOPED — an unscoped forwarding leg admits any
// foreign source as before. Node-local: the CNI programs it for the leg's own
// veth at ADD.
struct fwd_cidr_key {
	__u32 prefixlen; // 64 (ifindex + family) + address prefix bits
	__u32 scope_net; // full host-veth ifindex, not a VNI
	__u32 family;    // actual packet family: 4 or 6
	struct addr128 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct fwd_cidr_key);
	__type(value, __u8);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} fwd_cidrs SEC(".maps");

// bridges: fabric IP (unique, from the node pod CIDR — network byte order) ->
// the pod's (network id, VPC IP). A plain /32 route sends the fabric IP to the
// pod's veth; to_pod NATs it fabric->vpc and masquerades the client to the
// gateway. Replaces the per-pod iptables DNAT + fwmark policy routing.
struct bridge_ep {
	__u32 net;
	__u32 pad;
	struct addr128 vpc_ip; // network byte order
};

// Userspace deletion witness only: packet delivery keeps using bridges.
struct bridge_owner {
	__u32 ifindex;
	__u8 sandbox[32];
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, struct addr128);
	__type(value, struct bridge_owner);
} bridge_owners SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, struct bridge_ep);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} bridges SEC(".maps");

// floating: externally-routable IP (network order) -> the bound pod's {net, VPC
// IP} (reusing struct bridge_ep). The bridges map turned outward: instead of a
// fabric IP from the node pod CIDR, the key is a public address. EVERY node
// programs it, not just the pod's host: the node that attracts the traffic and
// the node that hosts the pod are decided separately (docs/floating-ha.md), so
// from_uplink must be able to resolve a floating address on a node that has no
// local pod for it and forward it over the overlay. from_uplink redirects (or
// encapsulates) an inbound packet into the pod's veth; to_pod DNATs public->VPC
// (keeping the client's source), and from_pod SNATs the pod's egress the other
// way — straight out the host's own uplink, so the reply never returns via the
// announcer. A true public IP: the same address inbound and outbound, no
// masquerade, no gateway, no conntrack.
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

// ---------------------------------------------------------------------------
// The VPC NAT gateway (docs/north-south.md § increment 2): a VPC's many-to-one
// egress, SNATed in eBPF to an address the TENANT owns, drawn from its pool.
//
// It replaces the per-VPC gateway POD, and the reason that pod existed is the
// reason this is not simply masq_snat with another address: masq_snat identifies
// a default-network pod by its ADDRESS (is_masq_src), at the uplink. That is
// impossible for a VPC — tenant CIDRs overlap by design, so a source address at
// the uplink names no one. The tenant is knowable only at the pod's veth, where
// ports[ifindex] gives the net. So the SNAT happens there, which means the
// connection state lives on the POD's node while the reply comes back to whichever
// node attracts the NAT address.
//
// Hence the sharding: one address per VPC, and each node draws its masquerade
// ports from its OWN range. A reply is demuxed by port -> owning node and, if that
// is not us, forwarded over the overlay to the node holding the ct entry. Egress
// stays distributed (no hairpin, no per-VPC single point of failure — tenet 1: the
// gateway is a boundary, not a hop), and the VPC still leaves the cluster wearing
// exactly one address of its own (tenet 8).
//
// Ports need no carve-out around the host's ranges the way MASQ_PORT_* does: the
// source address is the VPC's, never the node's, so a VPC flow can never collide
// with one of the node's own connections.
#define NAT_PORT_BASE  1024
#define NAT_SHARD_SPAN 4032  // concurrent flows per node, per VPC
#define NAT_SHARDS     16    // ... across up to this many nodes (1024 + 16*4032 = 65536)

struct vpc_nat {
	struct addr128 ip;  // the VPC's v4 egress identity (NAT64 form, network order)
	struct addr128 ip6; // the VPC's v6 egress identity (network order); zero = none
	__u32 port_base;    // THIS node's shard, shared across families (the ct tables
	__u32 port_span;    // are addr128-keyed, so a v4 and v6 flow can share a port)
};

// vpc_nat: net -> this node's shard of the VPC's NAT address. Written by the agent.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, struct vpc_nat);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_nat SEC(".maps");

// nat_of: a VPC NAT address -> its net. How an inbound reply learns whose it is.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, __u32); // net
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_of SEC(".maps");

struct nat_shard_key {
	struct addr128 ip;
	__u16 shard;
	__u16 pad;
};

// nat_owner: {NAT address, port shard} -> the Geneve endpoint of the node whose
// ct_rev holds those flows. The demux that keeps egress distributed.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct nat_shard_key);
	__type(value, __u32); // node IP, host order (as remotes stores it)
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} nat_owner SEC(".maps");

// vpc_ingress: net (VNI) -> 1, present only for a VPC whose gateway admits
// LoadBalancer ingress (docs/north-south.md, tenet 7 — "nothing crosses by
// default"). Absent means a Service type=LoadBalancer must NOT be able to open a
// door into that tenant's VPC, however it was created and by whom.
//
// This is the one place the boundary is fail-closed rather than merely observed:
// before it, a Service in ANY namespace naming a VPC pod as its backend got a
// free ride — the platform attracted it, the platform's uplink hook delivered it,
// and the tenant's own networking was never consulted. Now the VPC's gateway has
// to say yes. (It admits the traffic to the boundary; the destination's
// SecurityGroups still decide which pods and ports answer.)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, __u8);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_ingress SEC(".maps");

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
#define CFG_MASQ_IP        5 // v4 cluster-egress SNAT source (network order).
                             // The default-route link's own address, so the
                             // masqueraded packet is valid for the interface it
                             // leaves by — which need not be the node's InternalIP
                             // (Geneve/DNS handle, CFG_NODE_IP) on a multi-NIC
                             // node. A spoof-guarding underlay (OCI) drops a
                             // packet whose source is not its egress VNIC's IP.
#define CFG_FLOAT_IFINDEX  6 // the floating uplink: the link carrying the
                             // floating-IP range when it differs from the
                             // default-route uplink (an OCI L2 VLAN). 0 = same
                             // link as CFG_UPLINK_IFINDEX (single-NIC default).
                             // Read only by the v6 egress sites and lb_return's
                             // v6/DSR fallback now; v4 selects per address
                             // through ext_links.
#define CFG_FLOAT_NH       7 // VESTIGIAL: no program reads it; ext_egress.nh carries
                             // the per-link next-hop now. Still written, like
                             // uplink_mac, because dropping a pinned cell's
                             // writer is its own change
                             // out the floating uplink — the L2 fabric's virtual
                             // router. Needed because the kernel FIB routes
                             // off-subnet destinations via the *default* uplink,
                             // whose neighbour would be wrong for this link.
                             // 0 = resolve via the FIB (single-NIC default).
#define CFG_GENEVE_PORT    8 // host order; the overlay's UDP port, so the host
                             // firewall can never sever the datapath's own
                             // transport (docs/host-firewall.md).
#define CFG_HF_ENABLED     9 // 0 disabled, 1 complete rules, 2 updating/failed:
                             // the hf_ingress tail calls and the hf_ct pin
                             // writes. Mode 2 denies new gated flows.
#define CFG_HF_EG_ENABLED 10 // Same modes for a selecting HostFirewall declaring
                             // policyTypes: Egress — the node's OWN new flows
                             // are default-deny (node->node and node->local-pod
                             // stay exempt; docs/host-firewall.md).
#define CFG_FLOW_ENABLED  11 // 1 while flow observability is armed: every
                             // flow_emit site pays one params lookup when it is
                             // not (docs/observability.md).
#define CFG_NP_UPDATING   12 // deny new NP-gated flows during/after failed sync
#define CFG_SG_UPDATING   13 // deny new SG-gated flows during/after failed sync

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
	__uint(max_entries, 16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} params SEC(".maps");

// Host isolation survives recreation of the general-purpose params map.
// Cells 0/1 carry ingress/egress mode; cell 2 is Go's initialized witness.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 3);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_modes SEC(".maps");

static __always_inline __u32 cfg(__u32 idx);

// uplink_mac holds the node uplink's MAC (index 0), so from_uplink can put it in
// the floating-IP ARP replies it crafts. Written by the agent at attach time.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cozy_mac);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} uplink_mac SEC(".maps");

// ext_links: which of this node's links can source a given external address —
// a floating IP, a VPC NAT identity, an LB frontend on a reply. Keyed by the
// address, so an LPM lookup on the one being stamped names the link to leave by:
// a host key per external address, plus each link's subnet behind it. An address
// routed to the node sits OUTSIDE its link's subnet, which is why the host key
// exists and why the entry count follows addresses, not links.
//
// This replaces CFG_FLOAT_IFINDEX for v4 egress selection. That cell held one
// answer for the node, and a node can carry external addresses on two links at
// once (an L2 VLAN with an announced pool, plus cloud-NAT'd node addresses) —
// whichever link won the cell, the other link's traffic left the wrong segment
// with a source the fabric drops. The v6 paths still fall back to the cell,
// because nothing writes v6 entries yet. See docs/lb-ingress.md § "The egress
// link is a property of the address".
//
// A miss means no link claims the address: a routed pool, delivered to us from
// elsewhere. The default uplink with a plain FIB lookup is the answer then, as
// it always was.
struct ext_egress {
	__u32 ifindex;
	__be32 nh;   // the link's router, for destinations off its subnet; 0 = ask the FIB
	__be32 base; // the link's subnet, to tell those destinations apart
	__be32 mask;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, struct ext_egress);
	// Two keys per external address, so this follows the address budget rather
	// than the link count; `floating` holds 65536 of the same population.
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ext_links SEC(".maps");

// float_uplink_mac: the *floating* uplink's MAC, when floating traffic rides a
// different link than the default route (CFG_FLOAT_IFINDEX set) — e.g. an OCI
// L2 VLAN carrying the floating range, while the default route (and the
// cluster-egress masquerade) stays on the native, spoof-guarded NIC. Vestigial,
// like uplink_mac above. A separate one-cell map (not
// uplink_mac[1]) so the pinned uplink_mac keeps its shape across upgrades.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct cozy_mac);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} float_uplink_mac SEC(".maps");

// float_net: the floating uplink's v4 subnet (base and mask, network order).
// VESTIGIAL: no program reads it. ext_egress.base/mask carry the same on- vs
// off-subnet test, per link instead of per node. Still written, like uplink_mac,
// because dropping a PIN_BY_NAME map strands a pin on every upgraded node.
struct float_net {
	__be32 base;
	__be32 mask;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct float_net);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} float_net SEC(".maps");

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

// vpc_counters meters traffic per VPC (net), the metering/billing foundation
// (#2). PERCPU so the hooks never contend — the agent sums across CPUs when it
// reads. tx/rx count EAST-WEST (from_pod egress / to_pod ingress); ns_* count
// every crossing of the VPC's NORTH-SOUTH boundary, split by the door it went
// through (docs/north-south.md).
//
// The north-south half exists because the boundary was, until now, unaccounted:
// a tenant could pull terabytes out through a floating address or a LoadBalancer
// Service and cozyplane could not say that it happened. In a real cloud that
// traffic crosses your IGW or NAT gateway and lands on your bill. Counting it is
// not a reporting feature — it is the test of whether the boundary is real
// (north-south.md, tenet 6: if a path cannot be counted, it is not a sanctioned
// path). The default network (net 0) is never metered: it is the platform's, not
// a tenant's.
#define NS_GW  0 // the VPC's egress gateway
#define NS_EIP 1 // a floating address: 1:1, and the only egress today that
                 // carries an identity the TENANT owns rather than the node's
#define NS_LB  2 // LoadBalancer/NodePort ingress landing on a VPC backend —
                 // the door that rides the platform's stack all the way in
#define NS_APPLIANCE 3 // a per-VPC route table entry (issue #6): traffic leaving
                 // through a tenant appliance leg (a VPN endpoint, a router)
                 // rather than the NAT gateway. Metered apart so a VPC running a
                 // tunnel does not read as gateway egress.
#define NS_MECH_MAX 4

struct vpc_counter {
	__u64 tx_packets;
	__u64 tx_bytes;
	__u64 rx_packets;
	__u64 rx_bytes;
	__u64 ns_packets[NS_MECH_MAX][2]; // [door][in]
	__u64 ns_bytes[NS_MECH_MAX][2];
	// Packets REFUSED at the boundary, per door. Kept apart from the crossing
	// counters on purpose: a refused packet did not cross, so folding it into the
	// byte meter would corrupt the one number the boundary exists to produce. It
	// still has to be visible — "the tenant's LoadBalancer does not work" is
	// answered by this counter being non-zero.
	__u64 ns_denied[NS_MECH_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, struct vpc_counter);
	__uint(max_entries, 4096);
	// NO_PREALLOC, and it matters more here than anywhere: this is a PERCPU map,
	// so every preallocated entry costs sizeof(vpc_counter) * nr_cpus — and the
	// value grew when north-south metering landed. The agent creates one entry per
	// VPC and the datapath only ever increments an existing one, so nothing is
	// lost by allocating on demand.
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} vpc_counters SEC(".maps");

// count_dir bumps one direction's counters for a net (no-op for net 0). The
// PERCPU value is this CPU's private copy, so the ++ needs no atomics.
//
// Deliberately NOT inlined and stack-free. Two verifier constraints shaped it:
// inlining at the top of the large from_pod program pushed path exploration
// past the 1M-instruction complexity budget (rejected on a 6.12 kernel, though
// the CI's 6.8 verifier accepted it — so it only showed on the dev cluster); and as a
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

// count_ns meters one crossing of a VPC's north-south boundary, attributed to the
// door it went through. Unlike count_dir this is __always_inline, and it has to
// be: every door's EGRESS leaves through from_pod, which hosts no BPF-to-BPF
// callee at all (its frame is already ~496 of the 512-byte combined-stack limit —
// the very reason count_dir lives in to_pod and east-west is metered there). That
// constraint is why north-south went unmetered for so long; the way past it is to
// inline, on the narrow terminal paths only, so the verifier's path exploration
// stays cheap.
//
// mech/in are compile-time constants at every call site, so the indexing folds
// away; the bounds check costs nothing and keeps the verifier happy if it ever
// doesn't. Like count_dir, the entry is never created here — the agent pre-seeds
// one per VPC net.
static __always_inline void count_ns(__u32 net, __u32 len, int mech, int in)
{
	if (!net || mech < 0 || mech >= NS_MECH_MAX || in < 0 || in > 1)
		return;
	struct vpc_counter *c = bpf_map_lookup_elem(&vpc_counters, &net);
	if (!c)
		return;
	c->ns_packets[mech][in]++;
	c->ns_bytes[mech][in] += len;
}

// count_ns_denied records a packet the boundary REFUSED, per door.
static __always_inline void count_ns_denied(__u32 net, int mech)
{
	if (!net || mech < 0 || mech >= NS_MECH_MAX)
		return;
	struct vpc_counter *c = bpf_map_lookup_elem(&vpc_counters, &net);
	if (!c)
		return;
	c->ns_denied[mech]++;
}

// Security groups (intra-VPC policy, #7). Enforcement is destination-side, in
// to_pod — the one delivery hook every east-west path already traverses, so it
// is placement-independent with no Geneve TLV yet. A port's membership is a
// bitmap of group ids; bit 0 marks unresolved selected groups (no rule grants).
// A zero bitmap = "no groups" = legacy
// allow-all intra-VPC), real ids run 1..SG_WORLD-1, and SG_WORLD (63) is the
// reserved pseudo-group for north-south (bridge/floating) sources matched by a
// cidr rule — so the same "allowed & srcmap" test covers both source kinds.
#define SG_WORLD 63

struct sg_member {
	__u64 groups;
	__u64 owner[4];
};

// sg_members: (net, VPC IP) -> bitmap + Port/sandbox witness. Explicit zero proves a
// resolved unselected Port. A missing registered local VPC identity is pending.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct local_key);
	__type(value, struct sg_member);
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

// sg_egress is the mirror of sg_rules keyed from the SOURCE side (v2 egress):
// (src-net, dst-net, src-group, proto, dst-port) -> the bitmap of destination
// groups (in dst-net's id space) that source group may reach. Grouping makes a
// pod's east-west egress default-deny too, so a flow A->B is delivered only when
// B's ingress admits A (sg_rules) AND A's egress admits B (sg_egress).
struct sg_egress_key {
	__u32 src_net; // source net
	__u32 dst_net; // destination net (peer VNI for a peer egress rule)
	__u16 group;   // source group id
	__u16 port;    // destination port, network order; 0 = any port
	__u8 proto;    // IPPROTO_TCP / IPPROTO_UDP
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct sg_egress_key);
	__type(value, __u64);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_egress SEC(".maps");

// sg_drops meters policy drops per VPC (net), PERCPU and agent-seeded like
// vpc_counters — the observability the #2 metering foundation wants.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32); // net (VNI)
	__type(value, __u64);
	__uint(max_entries, 4096);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_drops SEC(".maps");

// sg_cidr admits north-south (bridge/floating) callers by a specific source CIDR
// (security groups v2 stage 2). LPM on the client address, with the destination
// (net, proto, port) fully specified ahead of it — the same composite-LPM shape
// as `remotes`/`networks` (a fully-matched entry has prefixlen 64 + client
// prefix). The value is the bitmap of destination groups that admit the matched
// CIDR for that (net, proto, port); the datapath ANDs it with the pod's own
// group bitmap. The all-addresses CIDR keeps its stage-1 SG_WORLD path.
struct sg_cidr_key {
	__u32 prefixlen; // 64 (net+port+proto) + client prefix bits
	__u32 net;       // destination net
	__u16 port;      // destination port, network order
	__u16 proto;     // low byte = L4 protocol, high byte = family (4/6)
	struct addr128 client;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct sg_cidr_key);
	__type(value, __u64);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_cidr SEC(".maps");

// sg_egress_cidr is the egress twin of sg_cidr (v2 north-south egress): a grouped
// pod's off-VPC (gateway) egress is default-deny, and a `to: {cidr}` rule opens
// specific external destinations. LPM on the DESTINATION address, with
// {src_net, proto, dst_port} fully specified ahead of it; the value is the
// bitmap of SOURCE groups that may egress to that CIDR. Enforced source-side in
// from_pod (the destination is off-VPC — no to_pod to check at).
struct sg_egress_cidr_key {
	__u32 prefixlen; // 64 (src_net+port+proto) + destination prefix bits
	__u32 src_net;   // source net
	__u16 port;      // destination port, network order
	__u16 proto;     // low byte = L4 protocol, high byte = family (4/6)
	struct addr128 dest;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct sg_egress_cidr_key);
	__type(value, __u64);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} sg_egress_cidr SEC(".maps");

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

// --- NetworkPolicy at net 0 (docs/network-policy.md) ---
//
// The default network's own policy maps: the SecurityGroups enforcement shape
// (destination-side in to_pod, TCP SYN-gate), but NOT the SG maps — NP needs
// per-direction isolation, label-follows membership, and an identity space a
// 62-id bitmap can't hold. Identities are u64 label-set hashes computed by the
// agent; they never cross the wire (the destination node resolves the source's
// identity from its own np_ident), so no TLV and no allocation coordination.

#define NP_ING_ISOLATED 1
#define NP_EG_ISOLATED 2 /* increment 2 (egress) — fed, not yet enforced */

#define NP_DIR_IN 0
#define NP_DIR_EG 1 /* increment 2 */

// Reserved source identities (real hashes are remapped off 0-7 by the agent):
// NP_SRC_ANY admits any source, external included (an empty `from:` rule);
// NP_SRC_ANY_POD admits any source that resolves in np_ident (a
// `namespaceSelector: {}` peer) — so the common allow-broadly policies cost
// O(subjects) entries instead of O(subjects x peers).
//
// The ENTITY peers (docs/policy-layers.md § entities) are the vocabulary
// upstream NetworkPolicy lacks, compiled from a reserved namespaceSelector
// label:
//   NP_SRC_NODES      any cluster node address (an np_nodes hit). Needed
//                     because the node exemption below narrowed to the LOCAL
//                     node: remote-node sources (apiserver -> webhook) are
//                     gated like anything else once a pod is isolated.
//   NP_SRC_LOCAL_PODS a net-0 pod co-scheduled on the subject's node (a
//                     `locals` hit at net 0). Author-declared placement
//                     dependence — tenet 6 forbids ENFORCEMENT from silently
//                     depending on co-location, not the author from naming it.
//   NP_SRC_LOCAL_NODE the subject's own node. Compiled but NOT probed: the
//                     structural local-node exemption in np_ingress already
//                     admits it. The rows are the forward path to a strict
//                     mode that drops the exemption.
#define NP_SRC_ANY 0
#define NP_SRC_ANY_POD 1
#define NP_SRC_NODES 2
#define NP_SRC_LOCAL_PODS 3
#define NP_SRC_LOCAL_NODE 4

// np_nodes value bits.
#define NP_NODE_LOCAL 1 /* this node's own address */

// np_ident: fabric IP -> {identity, isolation flags}. Every net-0 pod the
// agent knows lands here; absence (an external client, a node) means "no pod
// identity". The whole-snapshot update guard also covers missing identity rows
// while synchronization is incomplete, including after overflow.
struct np_ident_val {
	__u64 id;
	__u32 flags;
	__u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, struct np_ident_val);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_ident SEC(".maps");

// np_allow: {direction, proto, dst identity, src identity} + a big-endian
// PORT SUFFIX, as an LPM -> present = allowed. An exact port is a /16
// suffix, the any-port rule is /0, and an endPort range decomposes into
// maximal aligned prefixes (increment 3) — so a range costs O(log) entries
// and the datapath pays ONE probe per peer id (LPM finds the longest of
// exact/range/any). Sized generously and NO_PREALLOC; the agent screams
// (metric + log) if a policy's entries don't fit — never a silent cap, and
// a failed sync retains CFG_NP_UPDATING until the whole snapshot fits.
struct np_allow_key {
	__u32 prefixlen; // 160 (dir+proto+pad+ids) + port prefix bits (0..16)
	__u8 dir;
	__u8 proto;
	__u16 pad;
	__u64 dst_id;
	__u64 src_id;
	__u16 port; // network order (big-endian, so prefixes nest)
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct np_allow_key);
	__type(value, __u8);
	__uint(max_entries, 524288);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_allow SEC(".maps");

// np_ct: the UDP reply-pin. Upstream NetworkPolicy is stateful in practice —
// an isolated pod's DNS reply must come home — and UDP has no SYN to gate on,
// so an isolated pod's *outbound* UDP (from_pod, on the pod's own node: the
// reply is checked there too) pins {pod, peer, ports} and the reply direction
// admits on the pin. TCP needs none of this (SYN-gate). LRU: eviction of an
// idle pseudo-flow just means the next query re-pins.
struct np_ct_key {
	struct addr128 pod; // the isolated pod
	struct addr128 peer;
	__u16 pport; // the pod's port, network order
	__u16 rport; // the peer's port
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct np_ct_key);
	__type(value, __u8);
	__uint(max_entries, 131072);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_ct SEC(".maps");

// np_cidr: ipBlock rules, both directions (increment 2). LPM on the queried
// address (the SOURCE for an ingress rule, the DESTINATION for egress) with
// {dir, proto, port, identity} fully specified ahead of it — the composite-LPM
// shape of sg_cidr. The value distinguishes allow (1) from deny (0): an
// ipBlock `except` is a longer deny prefix, and longest-prefix-match makes it
// win over the enclosing allow. Port 0 = any-port, probed second.
struct np_cidr_key {
	__u32 prefixlen; // 96 (dir+proto+port+id) + address prefix bits
	__u8 dir;        // NP_DIR_* | family tag (IPv4 0x40, IPv6 0x80)
	__u8 proto;
	__u16 port; // network order; 0 = any
	__u64 id;   // the isolated pod's identity (dst for IN, src for EG)
	struct addr128 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct np_cidr_key);
	__type(value, __u8);
	__uint(max_entries, 65536);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_cidr SEC(".maps");

// np_nodes: node addresses (all nodes, both families, agent-fed from Node
// objects); the value carries NP_NODE_LOCAL for THIS node's own addresses.
// Local-node origin — kubelet probes, same-node hostNetwork pods — bypasses
// ingress policy unconditionally (invariant #7: the K8s contract is plumbing,
// not revocable policy). Remote-node origin is GATED, admitted by the
// NP_SRC_NODES entity (docs/policy-layers.md § trust model: this narrowing
// shrinks the address-minting attack surface from "any node address in the
// cluster" to "this node's own"). Presence alone still answers "is this a
// node?" for from_pod's egress exemption and the host firewall.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, __u8);
	__uint(max_entries, 4096);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_nodes SEC(".maps");

// np_drops: policy-drop counters by direction (PERCPU_ARRAY: pre-allocated,
// nothing to seed). Exposed as cozyplane_np_drops_total.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32); // NP_DIR_*
	__type(value, __u64);
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} np_drops SEC(".maps");

static __attribute__((noinline)) void count_np_drop(__u32 dir)
{
	__u64 *d = bpf_map_lookup_elem(&np_drops, &dir);
	if (d)
		(*d)++;
}

// np_scratch holds the query and both lookup keys per CPU: to_pod sits at
// 432 bytes of its own frame and from_pod at 496 — neither can afford ~100
// bytes of key-building on the stack (the combined-call-stack fights,
// docs/lb-ingress.md). Fields are written with explicit stores and a compiler
// barrier before every map call: clang provably elides "dead" stores to
// per-CPU map values (same doc).
struct np_query {
	struct addr128 src;
	struct addr128 dst;
	__u16 dport; // network order
	__u16 sport; // network order; only read for UDP
	__u8 proto;
	__u8 pad[3]; // [0] TCP flags, [1] actual packet family (4/6)
};

struct np_scratch_val {
	struct np_query q;
	struct np_allow_key ak;
	struct np_ct_key ck;
	struct np_cidr_key cd;
	struct local_key lk; // the local-pods entity probe (never on the stack:
	                     // to_pod(432) + np_ingress must stay under the 512
	                     // combined-stack limit — the 544 lesson)
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct np_scratch_val);
	__uint(max_entries, 1);
} np_scratch SEC(".maps");

// --- Host firewall (docs/host-firewall.md) ---
//
// Ingress policy for the node ITSELF — the delivery target NetworkPolicy and
// SecurityGroups deliberately leave alone. Enforcement lives in the
// tail-called cozyplane_hf_ingress (lb_prog slot 2), reached from every
// fall-through that hands a packet to the host stack; these maps are its
// state. Armed by CFG_HF_ENABLED (set only while a HostFirewall selects this
// node), so the disabled cost is one params lookup per fall-through packet.

// hf_self: this node's own addresses (the same set the agent feeds np_nodes
// for itself) — "is this packet host-destined". Broadcast/multicast/transit
// destinations miss and stay ungated.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct addr128);
	__type(value, __u8);
	__uint(max_entries, 64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_self SEC(".maps");

// hf_allow: {proto, port} + source-CIDR LPM. Unlike np_allow the port cannot
// be an LPM suffix (the address is the variable tail here), so it sits exact
// in the fixed bits: 0 = the any-port row, and endPort ranges expand to
// per-port entries (capped in the compiler — node services don't span wide
// ranges). A v4 source is NAT64-form: prefixlen 32+96+n; v6 is 32+n. Value:
// 1 = allow, 0 = deny (an `except` — a longer prefix masking its rule's
// allow). Fail-closed by construction: isolation is the CFG_HF_ENABLED flag,
// this map holds only admissions.
struct hf_allow_key {
	__u32 prefixlen;
	__u8 proto;
	__u8 pad; // actual packet family (4/6); legacy zero cannot authorize
	__u16 port; // network order; 0 = any-port row
	struct addr128 src;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct hf_allow_key);
	__type(value, __u8);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_allow SEC(".maps");

// hf_eallow: the egress twin of hf_allow — {proto, port} + DESTINATION-CIDR
// LPM, armed by CFG_HF_EG_ENABLED. Same value semantics (allow 1 / except 0).
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct hf_allow_key); // .src holds the DESTINATION here
	__type(value, __u8);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_eallow SEC(".maps");

// hf_ct: replies to node-ORIGINATED UDP (host DNS/NTP; hostNetwork pods
// resolving cluster DNS) — the np_ct shape with pod := the node's own
// address. Written wherever the outbound query crosses the datapath: the
// hf_ingress tail call itself (uplink egress, off-cluster peers), from_pod's
// remotes-hit encap (remote-pod peers), and to_pod (local-pod peers).
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct np_ct_key);
	__type(value, __u8);
	__uint(max_entries, 65536);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_ct SEC(".maps");

// hf_drops: exposed as cozyplane_hf_drops_total, by direction (NP_DIR_IN /
// NP_DIR_EG — the same encoding np_drops uses).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} hf_drops SEC(".maps");

// hf_gate probes one direction's rule map: exact port, then the any-port row.
// A deny hit (an `except`) masks only its own port level, so cross-policy
// unions stay monotone. Always-inline: both callers are already tail-called
// programs with their own fresh stacks.
static __always_inline int hf_gate(void *rules, __u8 proto, __u16 port, struct addr128 *addr, __u8 is_v6)
{
	struct hf_allow_key ak = {
		.prefixlen = 32 + 128,
		.proto = proto,
		.pad = is_v6 ? 6 : 4,
		.port = port,
		.src = *addr,
	};
	__u8 *v = bpf_map_lookup_elem(rules, &ak);
	if (v && *v)
		return 1;
	if (v && !*v)
		return 0; // an except at the longest match: denied
	ak.port = 0;
	v = bpf_map_lookup_elem(rules, &ak);
	return v && *v;
}

static __always_inline void hf_count_drop(__u32 dir)
{
	__u64 *d = bpf_map_lookup_elem(&hf_drops, &dir);
	if (d)
		(*d)++;
}

// np_cidr_check probes the ipBlock LPM for one direction (the queried address
// pre-copied into s->cd.addr): exact port then any-port. Returns 1 on an
// allow match; a deny match (an `except`) or no match returns 0 — the deny
// only needs to mask the allow, and longest-prefix-match already did that.
static __always_inline int np_cidr_check(struct np_scratch_val *s, __u8 dir, __u64 self)
{
	s->cd.prefixlen = 96 + 128;
	s->cd.dir = dir | (s->q.pad[1] == 4 ? 0x40 : 0x80);
	s->cd.proto = s->q.proto;
	s->cd.id = self;
	s->cd.port = s->q.dport;
	asm volatile("" ::: "memory");
	__u8 *v = bpf_map_lookup_elem(&np_cidr, &s->cd);
	if (v)
		return *v;
	s->cd.port = 0;
	asm volatile("" ::: "memory");
	v = bpf_map_lookup_elem(&np_cidr, &s->cd);
	return v ? *v : 0;
}

// np_pin_check probes the UDP reply-pin: the destination asked first, so the
// reply is sanctioned past BOTH directions — the pin lives on the
// initiator's node, which is exactly where the reply is policy-checked.
static __always_inline int np_pin_check(struct np_scratch_val *s)
{
	if (s->q.proto != IPPROTO_UDP)
		return 0;
	s->ck.pod = s->q.dst;
	s->ck.peer = s->q.src;
	s->ck.pport = s->q.dport;
	s->ck.rport = s->q.sport;
	s->ck.proto = IPPROTO_UDP;
	s->ck.pad[0] = 0;
	s->ck.pad[1] = 0;
	s->ck.pad[2] = 0;
	asm volatile("" ::: "memory");
	return bpf_map_lookup_elem(&np_ct, &s->ck) != NULL;
}

// np_ingress / np_egress decide one direction each of a gated net-0 delivery
// (query pre-filled in scratch); a flow is delivered only if both admit —
// the sg_admit/sg_egress_admit composition on the NP maps. TWO lean sibling
// callees instead of one fat one: to_pod sits at 432 bytes of frame, and the
// combined-call-stack limit is per CHAIN — sibling frames don't stack, but a
// single callee holding both directions' spilled state blew 512 on the 6.8
// verifier (544) while a newer kernel accepted it. Straight-line unrolled
// probes, every key in scratch, single map-value pointer arg (the sg_admit
// shape). Each returns 1 to admit.
static __attribute__((noinline)) int np_ingress(struct np_scratch_val *s)
{
	s->lk.net = CFG_NP_UPDATING;
	__u32 *updating = bpf_map_lookup_elem(&params, &s->lk.net);
	if (updating && *updating) {
		__u8 *node = bpf_map_lookup_elem(&np_nodes, &s->q.src);
		return (node && (*node & NP_NODE_LOCAL)) || np_pin_check(s);
	}
	struct np_ident_val *di = bpf_map_lookup_elem(&np_ident, &s->q.dst);
	if (!di)
		return 1; // not a pod the agent knows: not isolated
	if (!(di->flags & NP_ING_ISOLATED))
		return 1;

	// The node exemption, narrowed (docs/policy-layers.md): only the LOCAL
	// node is unconditionally exempt — kubelet probes are plumbing and must
	// never be revocable. A REMOTE node (apiserver -> webhook) falls through
	// and is gated, admissible via the NP_SRC_NODES entity below.
	__u8 *nn = bpf_map_lookup_elem(&np_nodes, &s->q.src);
	if (nn && (*nn & NP_NODE_LOCAL))
		return 1; // invariant #7

	struct np_ident_val *si = bpf_map_lookup_elem(&np_ident, &s->q.src);

	// One LPM probe per peer id: the entry's own prefixlen distinguishes
	// exact port, range prefix, and any-port — the lookup key is always
	// fully specified (/176).
	s->ak.prefixlen = 160 + 16;
	s->ak.dst_id = di->id;
	s->ak.dir = NP_DIR_IN;
	s->ak.proto = s->q.proto;
	s->ak.pad = 0;
	s->ak.port = s->q.dport;
	if (si) {
		s->ak.src_id = si->id;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&np_allow, &s->ak))
			return 1;
		s->ak.src_id = NP_SRC_ANY_POD;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&np_allow, &s->ak))
			return 1;
		// The local-pods entity: source is a net-0 pod on THIS node (the
		// subject is local by construction — to_pod is its delivery hook).
		// Key via scratch; this frame has no room (see np_scratch_val).
		s->lk.net = 0;
		s->lk.ip = s->q.src;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&locals, &s->lk)) {
			s->ak.src_id = NP_SRC_LOCAL_PODS;
			asm volatile("" ::: "memory");
			if (bpf_map_lookup_elem(&np_allow, &s->ak))
				return 1;
		}
	}
	// The nodes entity: any cluster node address. Only a REMOTE node reaches
	// here (the local node returned above), which is exactly the traffic the
	// narrowed exemption newly gates.
	if (nn) {
		s->ak.src_id = NP_SRC_NODES;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&np_allow, &s->ak))
			return 1;
	}
	s->ak.src_id = NP_SRC_ANY;
	asm volatile("" ::: "memory");
	if (bpf_map_lookup_elem(&np_allow, &s->ak))
		return 1;

	s->cd.addr = s->q.src;
	if (np_cidr_check(s, NP_DIR_IN, di->id))
		return 1;
	return np_pin_check(s);
}

static __always_inline int np_egress_impl(struct np_scratch_val *s)
{
	s->lk.net = CFG_NP_UPDATING;
	__u32 *updating = bpf_map_lookup_elem(&params, &s->lk.net);
	if (updating && *updating) {
		__u8 *node = bpf_map_lookup_elem(&np_nodes, &s->q.src);
		return (node && (*node & NP_NODE_LOCAL)) || np_pin_check(s);
	}
	struct np_ident_val *si = bpf_map_lookup_elem(&np_ident, &s->q.src);
	if (!si)
		return 1;
	if (!(si->flags & NP_EG_ISOLATED))
		return 1;

	struct np_ident_val *di = bpf_map_lookup_elem(&np_ident, &s->q.dst);

	s->ak.prefixlen = 160 + 16;
	s->ak.src_id = si->id;
	s->ak.dir = NP_DIR_EG;
	s->ak.proto = s->q.proto;
	s->ak.pad = 0;
	s->ak.port = s->q.dport;
	if (di) {
		s->ak.dst_id = di->id;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&np_allow, &s->ak))
			return 1;
		s->ak.dst_id = NP_SRC_ANY_POD;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&np_allow, &s->ak))
			return 1;
		// local-pods as an egress `to` peer: the destination is a net-0 pod
		// on this node. (nodes/local-node are refused in egress by the
		// compiler — node-destined egress is HostFirewall's contract.)
		s->lk.net = 0;
		s->lk.ip = s->q.dst;
		asm volatile("" ::: "memory");
		if (bpf_map_lookup_elem(&locals, &s->lk)) {
			s->ak.dst_id = NP_SRC_LOCAL_PODS;
			asm volatile("" ::: "memory");
			if (bpf_map_lookup_elem(&np_allow, &s->ak))
				return 1;
		}
	}
	s->ak.dst_id = NP_SRC_ANY;
	asm volatile("" ::: "memory");
	if (bpf_map_lookup_elem(&np_allow, &s->ak))
		return 1;

	s->cd.addr = s->q.dst;
	if (np_cidr_check(s, NP_DIR_EG, si->id))
		return 1;
	return np_pin_check(s);
}

static __attribute__((noinline)) int np_egress(struct np_scratch_val *s)
{
	return np_egress_impl(s);
}

// hf_pin_local: the host firewall's UDP reply-pin for node→LOCAL-pod flows
// (docs/host-firewall.md) — their only datapath crossing is the destination's
// to_pod, so the pin is written here (a sibling callee: frames don't stack;
// the np_ingress/np_egress precedent). Scratch is pre-filled by to_pod's NP
// block; self-sourced only.
static __attribute__((noinline)) void hf_pin_local(struct np_scratch_val *s)
{
	if (!bpf_map_lookup_elem(&hf_self, &s->q.src))
		return;
	s->ck.pod = s->q.src;
	s->ck.peer = s->q.dst;
	s->ck.pport = s->q.sport;
	s->ck.rport = s->q.dport;
	s->ck.proto = IPPROTO_UDP;
	s->ck.pad[0] = 0;
	s->ck.pad[1] = 0;
	s->ck.pad[2] = 0;
	__u8 one = 1;
	asm volatile("" ::: "memory");
	bpf_map_update_elem(&hf_ct, &s->ck, &one, BPF_ANY);
}

// sg_query is the fully-initialized argument to sg_admit: a single query pointer
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
static __always_inline __u64 sg_membership(struct local_key *key)
{
	struct sg_member *member = bpf_map_lookup_elem(&sg_members, key);
	if (key->net) {
		struct endpoint *ep = bpf_map_lookup_elem(&locals, key);
		if (ep) {
			if (!member)
				return 1;
			if (!(ep->sg_owner[0] | ep->sg_owner[1] | ep->sg_owner[2] | ep->sg_owner[3]) ||
			    ep->sg_owner[0] != member->owner[0] || ep->sg_owner[1] != member->owner[1] ||
			    ep->sg_owner[2] != member->owner[2] || ep->sg_owner[3] != member->owner[3])
				return 1;
		}
	}
	return member ? member->groups : 0;
}

static __attribute__((noinline)) int sg_admit(struct sg_query *q)
{
	struct sg_rule_key rk = { .net = CFG_SG_UPDATING, .src_net = q->src_net, .proto = q->proto };
	__u32 *updating = bpf_map_lookup_elem(&params, &rk.net);
	if (updating && *updating)
		return 0;
	rk.net = q->dst.net;
	__u64 dstmap = sg_membership(&q->dst);
	if (!dstmap)
		return 1; // destination is in no group -> legacy allow
	__u64 allowed = 0;
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

// sg_egress_query is the argument to sg_egress_admit: the source's groups (to
// iterate) and the destination's groups (to intersect the rules against).
struct sg_egress_query {
	__u32 src_net;
	__u32 dst_net;
	__u64 srcmap; // source's group bitmap (the subject)
	__u64 dstmap; // destination's group bitmap
	__u16 dport;
	__u8 proto;
	__u8 pad[5];
};

// Receive query/key scratch avoids growing to_pod's combined call stack.
// One non-sleepable TC execution owns this CPU's slot until it returns.
struct sg_scratch_val {
	struct sg_query q;
	struct sg_cidr_key ck;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct sg_scratch_val);
	__uint(max_entries, 1);
} sg_scratch SEC(".maps");

// sg_egress_admit is the mirror of sg_admit for the egress direction: it iterates
// the SOURCE's groups and admits if one of their egress rules names a group the
// destination is in. An ungrouped source is unrestricted (legacy allow), like an
// ungrouped destination is for ingress. Same noinline/one-key shape as sg_admit.
static __attribute__((noinline)) int sg_egress_admit(struct sg_egress_query *q)
{
	struct sg_egress_key rk = { .src_net = CFG_SG_UPDATING, .dst_net = q->dst_net, .proto = q->proto };
	__u32 *updating = bpf_map_lookup_elem(&params, &rk.src_net);
	if (updating && *updating)
		return 0;
	rk.src_net = q->src_net;
	if (!q->srcmap)
		return 1; // ungrouped source -> egress unrestricted
	__u64 allowed = 0;
#pragma unroll
	for (int g = 1; g < SG_WORLD; g++) {
		if (!(q->srcmap & (1ULL << g)))
			continue;
		rk.group = g;
		rk.port = q->dport;
		__u64 *r = bpf_map_lookup_elem(&sg_egress, &rk);
		if (r)
			allowed |= *r;
		rk.port = 0; // any-port rule for this (group, proto)
		__u64 *r0 = bpf_map_lookup_elem(&sg_egress, &rk);
		if (r0)
			allowed |= *r0;
	}
	return (allowed & q->dstmap) ? 1 : 0;
}

// sg_l4 reads the destination port and decides whether a packet should be gated
// by security-group rules. TCP is gated only on a *new* connection (SYN set,
// ACK clear): the reply direction of an admitted flow carries ACK and passes
// without a connection table, giving AWS-stateful-shaped semantics for TCP with
// no conntrack. UDP is always gated (stateless — intra-VPC UDP between grouped
// pods needs symmetric rules). SCTP is gated too: unsupported allow rules must
// not bypass isolation. Other protocols retain their plumbing contract. l4off is
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
	if (proto == IPPROTO_UDP || proto == IPPROTO_SCTP) {
		if (bpf_skb_load_bytes(skb, l4off + 2, dport, 2) < 0)
			return 0;
		return 1;
	}
	return 0;
}

static __always_inline __u16 cidr_proto(__u8 proto, int is_v6)
{
	return proto | ((is_v6 ? 6 : 4) << 8);
}

// ns_sg_check decides whether a north-south (bridge/floating) TCP/UDP packet to
// a grouped VPC pod is permitted (security groups v2, from.cidr). Grouping makes
// north-south default-deny like east-west; a `from: {cidr}` rule reopens it. The
// source identity is the reserved SG_WORLD pseudo-group (0.0.0.0/0), so a
// `from: {cidr: 0.0.0.0/0}` rule (which the agent compiles to the SG_WORLD bit)
// admits it. An ungrouped pod always passes (sg_admit short-circuits on an empty
// member bitmap). The caller gates on NS_MARK, so node-originated plumbing
// (kubelet probes — invariant #7), which never carries the mark, is never
// reached. dport is network order.
static __attribute__((noinline)) int ns_sg_check(struct sg_scratch_val *s)
{
	// The all-addresses CIDR (stage 1): sg_admit with the SG_WORLD pseudo-group.
	// Returns 1 for an ungrouped pod too, so the specific-CIDR path below only
	// runs for a grouped pod with no 0.0.0.0/0 rule.
	__u32 key = CFG_SG_UPDATING;
	__u32 *updating = bpf_map_lookup_elem(&params, &key);
	if (updating && *updating)
		return 0; // CIDR fallback must not override the update guard.
	if (sg_admit(&s->q))
		return 1;

	// Specific ranges (stage 2): an sg_cidr LPM entry whose group bitmap
	// intersects the pod's own groups admits this client. Two lookups: the exact
	// destination port and the any-port (0) rule.
	__u64 dstmap = sg_membership(&s->q.dst);
	__u64 *b = bpf_map_lookup_elem(&sg_cidr, &s->ck);
	if (b && (*b & dstmap))
		return 1;
	s->ck.port = 0;
	asm volatile("" ::: "memory");
	b = bpf_map_lookup_elem(&sg_cidr, &s->ck);
	if (b && (*b & dstmap))
		return 1;
	return 0;
}

static __always_inline int ns_sg_admit(__u32 net, const struct addr128 *vpc_ip, const struct addr128 *client, __u16 proto, __u16 dport)
{
	__u32 zero = 0;
	struct sg_scratch_val *s = bpf_map_lookup_elem(&sg_scratch, &zero);
	if (!s)
		return 0;
	s->q.dst.net = net;
	s->q.dst.ip = *vpc_ip;
	s->q.src_net = net;
	s->q.srcmap = (1ULL << SG_WORLD);
	s->q.dport = dport;
	s->q.proto = (__u8)proto;
	s->q.pad[0] = 0;
	s->ck.prefixlen = 64 + 128;
	s->ck.net = net;
	s->ck.port = dport;
	s->ck.proto = proto;
	s->ck.client = *client;
	asm volatile("" ::: "memory");
	return ns_sg_check(s);
}

// ns_egress_ok decides whether a grouped source pod may egress off-VPC to p->dst
// (v2 north-south egress). Default-deny for a grouped pod; a `to: {cidr}` rule
// (an sg_egress_cidr entry whose group bitmap intersects the pod's groups) opens
// it. Ungrouped pods and non-gated packets (a reply — TCP with ACK — or a
// non-TCP/UDP packet) pass. Inlined and loop-free (one sg_members lookup + up to
// two LPM lookups) because from_pod cannot host a BPF-to-BPF call.
static __always_inline int ns_egress_ok(struct __sk_buff *skb, __u32 srcnet, int is_v6, __u8 proto, struct addr128 src, struct addr128 dst)
{
	// Reuse the map key's first word for params: from_pod has no spare stack
	// for another inlined cfg key in every NAT/egress branch.
	struct local_key sk = { .net = CFG_SG_UPDATING, .ip = src };
	__u32 *updating = bpf_map_lookup_elem(&params, &sk.net);
	if (updating && *updating) {
		__u16 port;
		return !sg_l4(skb, proto, is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20), &port);
	}
	sk.net = srcnet;
	__u64 srcmap = sg_membership(&sk);
	if (!srcmap)
		return 1; // ungrouped source -> egress unrestricted
	__u16 dport;
	__u32 l4off = is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
	if (!sg_l4(skb, proto, l4off, &dport))
		return 1; // a reply or non-TCP/UDP -> not gated
	struct sg_egress_cidr_key ck = { .prefixlen = 64 + 128, .src_net = srcnet, .port = dport, .proto = cidr_proto(proto, is_v6), .dest = dst };
	__u64 *b = bpf_map_lookup_elem(&sg_egress_cidr, &ck);
	if (b && (*b & srcmap))
		return 1;
	ck.port = 0;
	b = bpf_map_lookup_elem(&sg_egress_cidr, &ck);
	if (b && (*b & srcmap))
		return 1;
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
// The LB DSR option (docs/lb-ingress.md, etp: Cluster): the ingress node
// DNAT'd an LB/NodePort flow to a REMOTE backend and encapsulated it; this
// option carries the frontend identity {lbIP, port} so the backend's node can
// pin svc_rev (lb=1) and the reply leaves THAT node already answering as the
// LB IP — DSR, the client source preserved end to end.
#define LB_OPT_TYPE 2
struct lb_geneve_opt {
	__be16 opt_class; // SG_OPT_CLASS: one private class, types discriminate
	__u8 type;
	__u8 length; // 4-byte units of opt_data: 20 bytes -> 5
	struct addr128 vip;
	__be16 vport;
	__u16 pad;
} __attribute__((packed));

#define SVC_F_AFFINITY 1
// SVC_F_SRC_RANGES: the Service declares loadBalancerSourceRanges — admit the
// client only on an lb_src LPM hit (checked at the DNAT point in lb_ingress,
// before any flow state exists). LB rows only.
#define SVC_F_SRC_RANGES 2

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
// lb_src admits LoadBalancer clients by loadBalancerSourceRanges: LPM on the
// client address with the frontend (LB IP) fully specified ahead of it — the
// composite-LPM shape of sg_cidr. Addresses are the 16-byte NAT64 form, so a
// v4 /24 range is prefixlen 128 + 96 + 24. kpr feeds it beside the LB rows.
struct lb_src_key {
	__u32 prefixlen; // 128 (LB IP) + client prefix bits
	struct addr128 vip;
	struct addr128 client;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lb_src_key);
	__type(value, __u8);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lb_src SEC(".maps");

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
	__u16 lb; // 1: DNAT'd at from_uplink (LB ingress) — the client is external
	          // and the reply exits by the uplink at the backend's from_pod
	// The link the request arrived on, so the reply leaves by the same one.
	// CFG_FLOAT_IFINDEX cannot answer this: it holds ONE link for the node, and
	// a node can carry external addresses on two (an L2 VLAN with a MetalLB
	// pool on one, cloud-NAT'd node addresses on the other) — the reply then
	// left the wrong segment with a source the fabric drops. 0 when the arrival
	// link is not a usable answer (the DSR path arrives over the overlay).
	__u32 ifindex;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct svc_rev_key);
	__type(value, struct svc_rev_val);
	__uint(max_entries, 262144);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} svc_rev SEC(".maps");

// HF_ARMED: the host firewall is live in either direction. The tail calls at
// every host-stack fall-through cost a mode lookup when it is not.
#define HF_ARMED() (cfg(CFG_HF_ENABLED) || cfg(CFG_HF_EG_ENABLED))

static __always_inline __u32 cfg(__u32 idx)
{
	if (idx == CFG_HF_ENABLED || idx == CFG_HF_EG_ENABLED) {
		idx -= CFG_HF_ENABLED;
		__u32 *mode = bpf_map_lookup_elem(&hf_modes, &idx);
		return mode ? *mode : 0;
	}
	__u32 *v = bpf_map_lookup_elem(&params, &idx);
	return v ? *v : 0;
}

// ---- Flow observability (docs/observability.md) ----------------------------
// Per-flow events with verdicts and reasons, streamed to the agent through the
// repo's first ring buffer. Off by default: every emission site is guarded by
// one params lookup (the CFG_HF_ENABLED idiom). Emission never blocks and
// never drops a packet — a full ring loses the EVENT and bumps flow_lost.

// Verdicts.
#define FE_V_ALLOW 0
#define FE_V_DENY  1

// Reasons — every deny names the gate that refused it. FR_MALFORMED/FR_INFRA
// are reserved for the v2 classes so the ABI never shifts under them.
#define FR_ALLOW       0
#define FR_SG_INGRESS  1  // east-west SecurityGroup deny (to_pod, lb_dsr, TLV)
#define FR_SG_EGRESS   2  // north-south SG egress deny (ns_egress_ok)
#define FR_SG_NS       3  // north-south SG ingress deny (ns_sg_admit)
#define FR_NP_INGRESS  4
#define FR_NP_EGRESS   5
#define FR_HF_INGRESS  6
#define FR_HF_EGRESS   7
#define FR_ISOLATION   8  // the isolation checks — entirely silent before this
#define FR_SPOOF       9  // source-RPF/anti-spoof, at last distinct from SG
#define FR_LB_CLOSED   10 // vpc_ingress door not opened (tenet 7)
#define FR_LB_SRCRANGE 11 // loadBalancerSourceRanges refused the client
#define FR_NO_GATEWAY  12 // closed island: off-VPC egress with no gateway
#define FR_MALFORMED   13 // reserved (v2)
#define FR_INFRA       14 // reserved (v2)

// Hooks — which program observed the flow.
#define FE_FROM_POD     0
#define FE_TO_POD       1
#define FE_FROM_OVERLAY 2
#define FE_FROM_UPLINK  3
#define FE_LB_INGRESS   4
#define FE_LB_DSR       5
#define FE_HF_INGRESS   6
#define FE_HF_EGRESS    7

// Event flags.
#define FE_F_SYN 0x1
#define FE_F_FWD 0x2 // a granted forwarding leg handed this packet on
#define FE_F_NS  0x4 // carried NS_MARK (pod-originated north-south)

#define FE_NO_DOOR 0xff

// The wire record: 64 bytes, fixed layout, mirrored by datapath/flowevent.go
// (a unit test pins size and offsets). Padding is zeroed explicitly —
// bpf_ringbuf_reserve memory is not, and an unwritten byte would leak kernel
// memory to the reader.
struct flow_event {
	__u64 ts;           // bpf_ktime_get_ns (CLOCK_MONOTONIC)
	struct addr128 src; // NAT64-mapped, as everywhere in the datapath
	struct addr128 dst;
	__u32 srcnet;       // VNI (0 = default/fabric network)
	__u32 dstnet;
	__u16 sport;        // network order; 0 where the site never parsed L4
	__u16 dport;
	__u8 proto;
	__u8 verdict;
	__u8 reason;
	__u8 hook;
	__u8 door;          // NS door when applicable, FE_NO_DOOR otherwise
	__u8 flags;
	// L4 detail, carried only by ADMITTED flows (the allow path fills them from
	// the trigger packet — per-flow, so tcp_flags is SYN-dominated; a deny event
	// leaves them 0). tcp_flags is the raw TCP flags byte; icmp_type/icmp_code
	// the ICMP/ICMPv6 first two bytes. Zero for other protocols / on denies.
	__u8 tcp_flags;
	__u8 icmp_type;
	__u8 icmp_code;
	// Explicit tail padding to the 8-byte-aligned 64: an implicit hole would
	// go out unzeroed (ring memory is not cleared on reserve).
	__u8 _pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB, ~65k events
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_events SEC(".maps");

// Events lost to a full ring, per CPU. One cell; the agent sums it and serves
// cozyplane_flow_events_lost_total.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_lost SEC(".maps");

// Argument packing: a BPF-to-BPF call carries at most five arguments, and the
// stack-heavy programs afford no locals for more — so the scalars ride packed
// words. nets = srcnet<<32 | dstnet; ports = sport<<16 | dport (both network
// order); meta = FE_META(...).
#define FE_META(verdict, reason, hook, door, flags, proto)                     \
	((__u64)(verdict) | ((__u64)(reason) << 8) | ((__u64)(hook) << 16) |   \
	 ((__u64)(door) << 24) | ((__u64)(flags) << 32) | ((__u64)(proto) << 40))
#define FE_NETS(srcnet, dstnet) (((__u64)(srcnet) << 32) | (__u32)(dstnet))
#define FE_PORTS(sport, dport) (((__u32)(__u16)(sport) << 16) | (__u16)(dport))

// flow_emit_core writes one event. Stack-free by construction: the record is
// built directly in ring memory behind the pointer bpf_ringbuf_reserve hands
// back (the 544 lesson — from_pod's 496-byte frame affords no event struct).
// __always_inline so from_pod's terminal paths can use it without a callee.
// l4 packs the admitted-flow L4 detail: tcp_flags | icmp_type<<8 | icmp_code<<16
// (0 on denies and non-TCP/ICMP).
static __always_inline void flow_emit_core(const struct addr128 *src,
					   const struct addr128 *dst,
					   __u64 nets, __u32 ports, __u64 meta, __u32 l4)
{
	if (!cfg(CFG_FLOW_ENABLED))
		return;
	struct flow_event *e = bpf_ringbuf_reserve(&flow_events, sizeof(struct flow_event), 0);
	if (!e) {
		__u32 z = 0;
		__u64 *l = bpf_map_lookup_elem(&flow_lost, &z);
		if (l)
			(*l)++;
		return;
	}
	e->ts = bpf_ktime_get_ns();
	e->src = *src;
	e->dst = *dst;
	e->srcnet = nets >> 32;
	e->dstnet = (__u32)nets;
	e->sport = ports >> 16;
	e->dport = (__u16)ports;
	e->proto = (meta >> 40) & 0xff;
	e->verdict = meta & 0xff;
	e->reason = (meta >> 8) & 0xff;
	e->hook = (meta >> 16) & 0xff;
	e->door = (meta >> 24) & 0xff;
	e->flags = (meta >> 32) & 0xff;
	e->tcp_flags = l4 & 0xff;
	e->icmp_type = (l4 >> 8) & 0xff;
	e->icmp_code = (l4 >> 16) & 0xff;
	e->_pad[0] = 0;
	e->_pad[1] = 0;
	e->_pad[2] = 0;
	bpf_ringbuf_submit(e, 0);
}

// flow_emit is the BPF-to-BPF form for programs that afford a callee (to_pod
// and everything tail-called): one call instruction per site instead of an
// inlined body — the count_dir/count_sg_drop discipline. Deny events carry no
// L4 detail (l4 = 0).
static __attribute__((noinline)) void flow_emit(const struct addr128 *src,
						const struct addr128 *dst,
						__u64 nets, __u32 ports, __u64 meta)
{
	flow_emit_core(src, dst, nets, ports, meta, 0);
}

// ---- Allow verdicts: per FLOW, never per packet ----------------------------
// flow_seen dedups admitted flows: an allow event is emitted when the packet
// is a fresh TCP SYN or when its tuple misses this LRU; either way the tuple
// is (re)inserted. Eviction is the TTL — a long-lived flow re-announces itself
// when evicted, which is a feature. Subsequent packets cost one lookup (which
// also marks the entry referenced, protecting active flows from eviction).
struct flow_key {
	__u32 srcnet;
	__u32 dstnet;
	struct addr128 src;
	struct addr128 dst;
	__u16 sport; // network order, 0 for port-less protocols
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, __u64); // first-seen bpf_ktime_get_ns
	__uint(max_entries, 131072);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} flow_seen SEC(".maps");

// Per-CPU scratch for the flow key — the np_scratch idiom: the stack-heavy
// programs afford no 48-byte local.
struct flow_scratch_val {
	struct flow_key k;
	__u8 fl; // TCP flags byte
	__u8 pad[7];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct flow_scratch_val);
	__uint(max_entries, 1);
} flow_scratch SEC(".maps");

// flow_allow_core emits one allow event per flow. The L4 offset rides meta's
// top 16 bits (FE_L4OFF below) because a sixth argument does not exist.
// Stack-free: key in per-CPU scratch, record in ring memory. __always_inline
// for from_pod's terminal paths; to_pod calls the noinline twin below.
#define FE_L4OFF(l4off) ((__u64)(__u16)(l4off) << 48)
static __always_inline void flow_allow_core(struct __sk_buff *skb,
					    const struct addr128 *src,
					    const struct addr128 *dst,
					    __u64 nets, __u64 meta)
{
	if (!cfg(CFG_FLOW_ENABLED))
		return;
	__u32 z = 0;
	struct flow_scratch_val *fs = bpf_map_lookup_elem(&flow_scratch, &z);
	if (!fs)
		return;
	__u32 l4off = (meta >> 48) & 0xffff;
	__u8 proto = (meta >> 40) & 0xff;
	fs->k.srcnet = nets >> 32;
	fs->k.dstnet = (__u32)nets;
	fs->k.src = *src;
	fs->k.dst = *dst;
	fs->k.proto = proto;
	fs->k.sport = 0;
	fs->k.dport = 0;
	fs->k.pad[0] = 0;
	fs->k.pad[1] = 0;
	fs->k.pad[2] = 0;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		bpf_skb_load_bytes(skb, l4off, &fs->k.sport, 2);
		bpf_skb_load_bytes(skb, l4off + 2, &fs->k.dport, 2);
	}
	int syn_new = 0;
	__u32 l4 = 0; // tcp_flags | icmp_type<<8 | icmp_code<<16 for the record
	if (proto == IPPROTO_TCP) {
		fs->fl = 0;
		bpf_skb_load_bytes(skb, l4off + 13, &fs->fl, 1);
		syn_new = (fs->fl & 0x02) && !(fs->fl & 0x10);
		l4 = fs->fl;
	} else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6) {
		__u8 tc[2] = {0, 0};
		bpf_skb_load_bytes(skb, l4off, tc, 2); // type, code
		l4 = ((__u32)tc[0] << 8) | ((__u32)tc[1] << 16);
	}
	asm volatile("" ::: "memory");
	if (!syn_new && bpf_map_lookup_elem(&flow_seen, &fs->k))
		return; // a known flow: one lookup and out
	__u64 now = bpf_ktime_get_ns();
	bpf_map_update_elem(&flow_seen, &fs->k, &now, BPF_ANY);
	if (syn_new)
		meta |= (__u64)FE_F_SYN << 32;
	flow_emit_core(src, dst, nets, FE_PORTS(fs->k.sport, fs->k.dport),
		       meta & 0xffffffffffffULL, l4);
}

static __attribute__((noinline)) void flow_allow(struct __sk_buff *skb,
						 const struct addr128 *src,
						 const struct addr128 *dst,
						 __u64 nets, __u64 meta)
{
	flow_allow_core(skb, src, dst, nets, meta);
}

// A fully-specified scoped LPM lookup: 32 scope bits + 128 address bits.
#define LPM_FULL 160

// ext_link_of returns the entry for an external source address, or NULL when no
// link claims it. The value points into the map, so callers copy what they need
// before any packet store: a store invalidates it.
static __always_inline struct ext_egress *ext_link_of(const struct addr128 *src)
{
	struct lpm_key k = { .prefixlen = LPM_FULL, .scope_net = 0, .addr = *src };
	return bpf_map_lookup_elem(&ext_links, &k);
}

// ext_redirect sends a packet out an external link. ON that link's subnet the
// destination is its own neighbour and the FIB resolves it; OFF it the link's
// router must be named, because a plain lookup would return the DEFAULT link's
// gateway — the wrong neighbour for this one. nh 0 means no router is known
// (a routed pool on the default uplink), so the FIB answers.
static __always_inline int ext_redirect(struct __sk_buff *skb, __u32 uplink,
					__be32 nh, __be32 base, __be32 mask)
{
	if (!nh)
		return bpf_redirect_neigh(uplink, NULL, 0, 0);
	__be32 dip = 0;
	bpf_skb_load_bytes(skb, IP_DADDR_OFF, &dip, 4);
	if (mask && (dip & mask) == base)
		return bpf_redirect_neigh(uplink, NULL, 0, 0);
	struct bpf_redir_neigh rn = { .nh_family = AF_INET };
	rn.ipv4_nh = nh;
	return bpf_redirect_neigh(uplink, &rn, sizeof(rn), 0);
}

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

// route_of resolves an off-VPC destination against the source VPC's route table
// (vpc_routes): the longest-prefix next-hop for `addr` in `scope`, or NULL for
// no route (fall through to NAT/gateway). LPM, so a fully-specified query key
// matches the widest covering prefix.
static __always_inline struct route_entry *route_of(__u32 scope, struct addr128 addr)
{
	struct lpm_key key = { .prefixlen = LPM_FULL, .scope_net = scope, .addr = addr };
	return bpf_map_lookup_elem(&vpc_routes, &key);
}

// node_remote_of returns the Geneve underlay IP of the node that owns `addr`
// (any of its interface addresses), or NULL if `addr` is not a known node.
static __always_inline __u32 *node_remote_of(struct addr128 addr)
{
	return bpf_map_lookup_elem(&node_remotes, &addr);
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

// Keep this lookup off the already stack-heavy receive program. Unknown local
// state retains staged-target plumbing; a known different owner never delivers.
static __noinline int receiving_owner(struct __sk_buff *skb, __u32 net, struct addr128 *dst)
{
	struct local_key key = { .net = net, .ip = *dst };
	// A native VPC IP may equal a global fabric/public alias in another VNI.
	// Only the global delivery path may project that alias onto its owner.
	if (!(skb->mark & VPC_MARK)) {
		struct bridge_ep *owner = bpf_map_lookup_elem(&bridges, dst);
		if (!owner)
			owner = bpf_map_lookup_elem(&floating, dst);
		if (owner) {
			if (owner->net != net)
				return 0;
			key.ip = owner->vpc_ip;
		}
	}
	struct endpoint *active = bpf_map_lookup_elem(&locals, &key);
	return !active || active->ifindex == skb->ifindex;
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

// A NIC hands up a frame that missed its receive buffer with only the Ethernet
// header in the linear area (virtio_net page_to_skb copies ETH_HLEN and leaves the
// rest in page frags). GRO pulls the headers of what it aggregates (TCP), never
// those of an ICMP or plain UDP frame, so direct packet access missed them and
// fail-closed paths dropped the packet: large pings and VPN datagrams vanished
// intermittently. Every entry program pulls the headers it parses first, before
// any packet pointer exists (the helper invalidates them).
#define PULL_HEADERS_LEN 128
static __always_inline void pull_headers(struct __sk_buff *skb)
{
	__u32 want = skb->len < PULL_HEADERS_LEN ? skb->len : PULL_HEADERS_LEN;
	__u64 data, end;
	// Opaque loads: plain reads let LLVM keep the field offsets in callee-saved
	// registers across the helper call and rebuild ctx+off for the caller's own
	// reads, which the verifier rejects ("dereference of modified ctx ptr").
	asm volatile("%0 = *(u32 *)(%1 + %2)" : "=r"(data) : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, data)));
	asm volatile("%0 = *(u32 *)(%1 + %2)" : "=r"(end) : "r"(skb), "i"(__builtin_offsetof(struct __sk_buff, data_end)));
	if ((long)end - (long)data < (long)want)
		bpf_skb_pull_data(skb, want);
}

// Policy/NAT helpers use fixed L4 offsets. Never send an IP header they cannot
// interpret down a permissive kernel fallback: options, fragments and IPv6
// extension chains could hide a TCP SYN or UDP destination port from policy.
static __always_inline int unsupported_ip_header(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > end)
		return 1;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > end)
			return 1;
		return ip->version != 4 || ip->ihl != 5 ||
		       (ip->frag_off & bpf_htons(0x3fff)); // MF or nonzero offset
	}
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > end || ip6->version != 6)
			return 1;
		return ip6->nexthdr == 0 || ip6->nexthdr == 43 ||
		       ip6->nexthdr == 44 || ip6->nexthdr == 51 ||
		       ip6->nexthdr == 60 || ip6->nexthdr == 135;
	}
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

// route_next_hop picks one active next-hop from the immutable inner packet.
// The hash deliberately does not depend on skb metadata so source and
// destination nodes make the same decision before and after Geneve.
static __always_inline struct gw_entry *route_next_hop(struct route_entry *route, const struct pkt *p)
{
	if (!route || route->count == 0 || route->count > ROUTE_NH_MAX)
		return NULL;
	__u32 src, dst;
	__builtin_memcpy(&src, &p->src.b[12], sizeof(src));
	__builtin_memcpy(&dst, &p->dst.b[12], sizeof(dst));
	__u32 hash = src ^ (dst << 1) ^ p->proto;
	hash *= 2654435761u;
	hash ^= hash >> 16;
	if (route->count == 1 || !(hash & 1))
		return &route->next_hops[0];
	return &route->next_hops[1];
}

static __always_inline int routes_blocked(__u32 scope)
{
	__u32 zero = 0;
	__u32 *blocked = bpf_map_lookup_elem(&route_guard, &zero);
	if (!blocked || *blocked)
		return 1;
	__u32 cell = scope >> 12;
	struct route_scope_guard *scopes = bpf_map_lookup_elem(&route_scopes, &cell);
	return !scopes || (scopes->blocked[(scope >> 5) & 127] & (1U << (scope & 31)));
}

// tcp_mss_clamp caps an advertised MSS on a bare TCP SYN before a path that
// may add Geneve plus VPN or north-south encapsulation. It never inserts an
// option, never changes a non-SYN, and leaves an absent/smaller MSS untouched.
// The checksum change covers only TCP's option bytes, so no pseudo-header flag
// is needed. IPv6 extension headers intentionally miss: parse_ip treats only a
// direct TCP next-header as a datapath TCP flow too.
// Keep the bounded parser/clamp as one BPF subprogram. Inlining it into every
// large tc entry point pushes LLVM's 16-bit conditional-branch displacement
// over its architectural range as the datapath grows.
// Global, not static: the verifier checks a global subprogram once, against an
// unknown ctx, instead of re-walking the 40-step option loop for every distinct
// caller state. As a static subprogram it pushed the tc entry points past the
// 1M processed-instruction limit.
__noinline int tcp_mss_clamp_packet(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;

	__u32 l4off;
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + ETH_HLEN;
		if ((void *)(ip + 1) > data_end || ip->version != 4 || ip->ihl < 5 ||
		    ip->protocol != IPPROTO_TCP)
			return 0;
		l4off = ETH_HLEN + ((__u32)ip->ihl << 2);
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = data + ETH_HLEN;
		if ((void *)(ip6 + 1) > data_end || ip6->nexthdr != IPPROTO_TCP)
			return 0;
		l4off = L4_OFF6;
	} else {
		return 0;
	}

	__u8 *tcp = data + l4off;
	if ((void *)(tcp + TCP_MIN_HLEN) > data_end)
		return 0;
	__u8 doff = tcp[12] >> 4;
	__u8 flags = tcp[13];
	if (doff < 5 || !(flags & TCP_SYN) || (flags & TCP_ACK))
		return 0;
	__u32 end = l4off + ((__u32)doff << 2);
	if (data + end > data_end)
		return 0;
	skb->cb[0] = l4off;
	skb->cb[1] = end;
	skb->cb[2] = l4off + TCP_MIN_HLEN;

	for (int i = 0; i < 40; i++) {
		__u32 off = skb->cb[2];
		end = skb->cb[1];
		if (off >= end)
			return 0;
		__u32 option = 0;
		if (bpf_skb_load_bytes(skb, off, &option, sizeof(option)) < 0)
			return 0;
		__u8 kind = option & 0xff;
		if (kind == TCP_OPT_EOL)
			return 0;
		if (kind == TCP_OPT_NOP) {
			skb->cb[2] = off + 1;
			continue;
		}
		__u8 len = (option >> 8) & 0xff;
		if (len < 2 || off + len > end)
			return 0;
		if (kind == TCP_MSS_KIND && len == TCP_MSS_LEN) {
			__u16 old_host = (((option >> 16) & 0xff) << 8) | (option >> 24);
			if (old_host <= TCP_MSS_CLAMP)
				return 0;
			__be16 old = bpf_htons(old_host);
			__be16 new = bpf_htons(TCP_MSS_CLAMP);
			if (bpf_l4_csum_replace(skb, skb->cb[0] + 16, old, new, 2) < 0)
				return 0;
			bpf_skb_store_bytes(skb, off + 2, &new, sizeof(new), 0);
			return 0;
		}
		skb->cb[2] = off + len;
	}
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
struct tunnel_scratch {
	struct bpf_tunnel_key key;
	struct sg_geneve_opt option;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct tunnel_scratch);
	__uint(max_entries, 1);
} tunnel_scratch SEC(".maps");

static __always_inline int encap_sg(struct __sk_buff *skb, __u32 dstnet, __u32 node_ip, __u32 tunflags, __u32 srcnet, __u64 srcmap)
{
	tcp_mss_clamp_packet(skb);
	__u32 geneve = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve)
		return TC_ACT_SHOT; // selected overlay delivery must never egress bare
	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;
	__u32 zero = 0;
	struct tunnel_scratch *s = bpf_map_lookup_elem(&tunnel_scratch, &zero);
	if (!s) return TC_ACT_SHOT;
	__builtin_memset(&s->key, 0, sizeof(s->key));
	s->key.tunnel_id = (dstnet ? dstnet : cfg(CFG_VNI)) | tunflags;
	s->key.remote_ipv4 = node_ip;
	if (bpf_skb_set_tunnel_key(skb, &s->key, sizeof(s->key), BPF_F_ZERO_CSUM_TX) < 0)
		return TC_ACT_SHOT;
	// Stamp the source pod's authoritative group identity (stage B), but only
	// for a grouped source — the common ungrouped case pays nothing.
	if (srcmap) {
		s->option.opt_class = bpf_htons(SG_OPT_CLASS);
		s->option.type = SG_OPT_TYPE;
		s->option.length = 3;
		s->option.src_net = srcnet;
		s->option.srcmap = srcmap;
		asm volatile("" ::: "memory");
		if (bpf_skb_set_tunnel_opt(skb, &s->option, sizeof(s->option)) < 0)
			return TC_ACT_SHOT;
	}
	return bpf_redirect(geneve, 0);
}

// encap without a security-group TLV (gateway, default-network, migration
// re-encap — no tenant source identity to vouch for).
static __always_inline int encap(struct __sk_buff *skb, __u32 dstnet, __u32 node_ip, __u32 tunflags)
{
	return encap_sg(skb, dstnet, node_ip, tunflags, 0, 0);
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

// Two u64 compares folded into one branch, not a byte loop: an early-return
// loop leaves the verifier a separate fall-through state per byte, and each one
// re-explores everything after the call. memcpy because addr128 is byte-aligned.
static __always_inline int addr128_eq(const struct addr128 *a, const struct addr128 *b)
{
	__u64 a0, a1, b0, b1;
	__builtin_memcpy(&a0, a->b, 8);
	__builtin_memcpy(&a1, a->b + 8, 8);
	__builtin_memcpy(&b0, b->b, 8);
	__builtin_memcpy(&b1, b->b + 8, 8);
	return ((a0 ^ b0) | (a1 ^ b1)) == 0;
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

	// North-south security groups (v2): a grouped pod is default-deny to
	// pod/external north-south, reopened by a from.cidr rule. Only NS_MARK'd
	// (eBPF-redirected, pod-originated) traffic is gated; host-originated
	// kubelet probes reach here via the kernel /32 route unmarked and stay
	// exempt (invariant #7). Checked before the ct_fwd allocation so a denied
	// packet leaves no connection state.
	if ((skb->mark & NS_MARK) && !ns_sg_admit(net, &vpc_ip, &client128, cidr_proto(proto, 0), pport)) {
		count_sg_drop(net);
		flow_emit(&client128, &vpc_ip, FE_NETS(0, net), FE_PORTS(cport, pport),
			  FE_META(FE_V_DENY, FR_SG_NS, FE_TO_POD, FE_NO_DOOR, FE_F_NS, proto));
		return TC_ACT_SHOT;
	}

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
	// A *remote node* client (hostNetwork — e.g. an apiserver probing a VPC
	// pod's fabric IP): encapsulate the reply to that node, for the same reason
	// as from_pod's node_remotes leg — the kernel path would emit it with the
	// pod's fabric source, which a spoof-guarding underlay (OCI) drops. The
	// node's own addresses are never in the map (watchNodes skips self), so
	// same-node replies still go up the local stack.
	__u32 *nnode = node_remote_of(dst);
	if (nnode)
		return encap(skb, 0, *nnode, 0);
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
	// North-south security groups (v2), the v6 twin of bridge_forward: only
	// NS_MARK'd pod-originated traffic is gated; kubelet stays exempt.
	if ((skb->mark & NS_MARK) && !ns_sg_admit(net, &vpc_ip, &p->src, cidr_proto(proto, 1), pport)) {
		count_sg_drop(net);
		flow_emit(&p->src, &vpc_ip, FE_NETS(0, net), FE_PORTS(cport, pport),
			  FE_META(FE_V_DENY, FR_SG_NS, FE_TO_POD, FE_NO_DOOR, FE_F_NS, proto));
		return TC_ACT_SHOT;
	}
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
			return net ? TC_ACT_SHOT : TC_ACT_OK;
		if (icmp6_err(type))
			return bridge_reverse6_icmp_err(skb, p, net);
		if (type != ICMP6_ECHO_REPLY)
			return net ? TC_ACT_SHOT : TC_ACT_OK;
		struct ct_rev_key rk = {
			.proto = proto,
			.gw_port = gw_id,
			.net = net,
			.vpc_ip = p->src,
		};
		struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
		if (!rv)
			return net ? TC_ACT_SHOT : TC_ACT_OK;
		nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &rv->fabric_ip);
		nat_addr6(skb, proto, IP6_DADDR_OFF, &gw, &rv->client_ip);
		nat_icmp6_id(skb, gw_id, rv->client_port);
		return deliver_net0(skb, rv->client_ip);
	}
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP)
		return net ? TC_ACT_SHOT : TC_ACT_OK;
	__u16 pport, gw_port;
	if (l4_ports6(skb, &pport, &gw_port) < 0)
		return net ? TC_ACT_SHOT : TC_ACT_OK;
	struct ct_rev_key rk = {
		.proto = proto,
		.gw_port = gw_port,
		.net = net,
		.vpc_ip = p->src,
		.pod_port = pport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return net ? TC_ACT_SHOT : TC_ACT_OK;
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
	// North-south security groups (v2): a floating IP is a deliberate external
	// surface, so it is gated unconditionally (external clients are never
	// kubelet/node-originated — the fabric IP carries those). Default-deny for a
	// grouped pod, reopened by a from.cidr rule. TCP is gated on a NEW connection
	// only (SYN, no ACK), as at every other SG gate: the reply to a flow the pod
	// opened through its public IP (admitted by its egress rules) carries ACK and
	// must come back. UDP stays gated per packet.
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 sp, dp, gated;
		struct addr128 client128;
		v4_to_128(&client128, ip->saddr);
		if (sg_l4(skb, proto, L4_OFF, &gated) && l4_ports(skb, &sp, &dp) == 0 &&
		    !ns_sg_admit(net, &vpc_ip, &client128, cidr_proto(proto, 0), dp)) {
			count_sg_drop(net);
			flow_emit(&client128, &vpc_ip, FE_NETS(0, net), FE_PORTS(sp, dp),
				  FE_META(FE_V_DENY, FR_SG_NS, FE_TO_POD, NS_EIP, 0, proto));
			return TC_ACT_SHOT;
		}
	}
	nat_addr(skb, proto, IP_DADDR_OFF, ip->daddr, vpc);
	// The EIP door, inbound (docs/north-south.md).
	count_ns(net, skb->len, NS_EIP, 1);
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
	struct bridge_ep *peer = float_of(dst128);
	int peer_float = 0;
	__u32 peer_net = 0;
	struct addr128 peer_ip = {};
	if (peer) {
		peer_float = 1;
		peer_net = peer->net;
		peer_ip = peer->vpc_ip;
	}
	// Cluster-internal destinations normally stay on the VPC gateway path.
	// A FloatingIP is the deliberate exception: VPN peers commonly reach each
	// other through two addresses from the same in-cluster LoadBalancer pool.
	// Let that packet keep its EIP SNAT and hairpin through the floating uplink;
	// the destination FloatingIP will apply its normal inbound DNAT/SG checks.
	if (is_internal(dst128) && !peer_float)
		return FLOAT_MISS; // internal non-FloatingIP: gateway proxy/deny
	// SecurityGroup egress applies to a floating pod's off-VPC traffic too
	// (docs/security-groups.md § floating egress): a grouped floating pod is
	// gated by its to:{cidr} rules, exactly like a gateway'd pod — closing the
	// gap where floating egress returned before the isolation block's gate.
	// Ungrouped pods, replies (SYN-gated) and ICMP pass inside ns_egress_ok.
	if (!ns_egress_ok(skb, net, 0, proto, src128, dst128))
		return TC_ACT_SHOT;
	// Floating egress leaves by the link that carries the public address — only
	// there is that source valid for the wire.
	__u32 uplink;
	__be32 xnh = 0, xbase = 0, xmask = 0;
	struct ext_egress *xl = ext_link_of(public_ip);
	if (xl) {
		uplink = xl->ifindex;
		xnh = xl->nh;
		xbase = xl->base;
		xmask = xl->mask; // copied: a packet store invalidates the map value
	} else {
		uplink = cfg(CFG_UPLINK_IFINDEX); // no link claims it: a routed pool
	}
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
	// The EIP door, outbound: the packet is now leaving the VPC as the tenant's
	// own public address (docs/north-south.md).
	count_ns(net, skb->len, NS_EIP, 0);
	// A peer FloatingIP may be announced by this same node. Sending it out the
	// physical link relies on switch hairpin behaviour and loses the packet on
	// common L2 fabrics. Deliver the still-public-destination packet straight to
	// the peer Port instead; to_pod performs its usual FloatingIP DNAT and SG
	// admission, so local and cross-node peers share exactly the inbound path.
	if (peer_float) {
		struct endpoint *l = local_of(peer_net, peer_ip);
		if (l)
			return deliver_local(skb, l);
		__u32 *node_ip = remote_of(peer_net, peer_ip);
		if (node_ip)
			return encap(skb, peer_net, *node_ip, 0);
		return TC_ACT_SHOT; // configured FloatingIP without a live target
	}
	// Pick the neighbour for the redirect. ON the floating subnet the
	// destination is its own neighbour (the FIB's on-link route resolves it);
	// OFF it the agent-supplied virtual router is — the FIB would route via
	// the *default* link's gateway, the wrong neighbour for this uplink, and
	// the virtual router won't hairpin intra-subnet traffic back in.
	return ext_redirect(skb, uplink, xnh, xbase, xmask);
}

// encap_lb: encapsulate an LB/NodePort flow to a remote backend's node at
// net 0, stamping the DSR option (the frontend identity the reply assumes).
// Mirrors encap/encap_sg; vip/vport point into the caller's scratch.
static __always_inline int encap_lb(struct __sk_buff *skb, __u32 node_ip,
				    const struct addr128 *vip, __u16 vport)
{
	tcp_mss_clamp_packet(skb);
	__u32 geneve = cfg(CFG_GENEVE_IFINDEX);
	if (!geneve)
		return TC_ACT_SHOT;
	__u8 dmac[6] = OVERLAY_DMAC;
	if (bpf_skb_store_bytes(skb, 0, dmac, sizeof(dmac), 0) < 0)
		return TC_ACT_SHOT;
	struct bpf_tunnel_key tkey = {};
	tkey.tunnel_id = cfg(CFG_VNI);
	tkey.remote_ipv4 = node_ip;
	if (bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), BPF_F_ZERO_CSUM_TX) < 0)
		return TC_ACT_SHOT;
	struct lb_geneve_opt opt = {
		.opt_class = bpf_htons(SG_OPT_CLASS),
		.type = LB_OPT_TYPE,
		.length = 5,
		.vip = *vip,
		.vport = vport,
	};
	if (bpf_skb_set_tunnel_opt(skb, (void *)&opt, sizeof(opt)) < 0)
		return TC_ACT_SHOT;
	return bpf_redirect(geneve, 0);
}

#define NAT_MISS -1

// vpc_nat_snat: a VPC pod's off-VPC egress, SNATed to the VPC's own address
// (docs/north-south.md § increment 2). Run in from_pod at the POD's veth — the
// only place the tenant is identifiable, since VPC CIDRs overlap and a source
// address at the uplink names no one.
//
// The tenant->system boundary the gateway pod's netns firewall used to enforce is
// preserved here: cluster-internal destinations are refused (is_internal), and the
// SecurityGroup egress gate applies exactly as it does on the gateway path. DNS
// never reaches this point — dns_steer already sent it to the split-horizon
// resolver, for every VPC pod alike.
//
// The ct_fwd/ct_rev machinery is masq_snat's, unchanged: the same problem with
// `net` set and a per-VPC address in place of the node's. Ports come from THIS
// node's shard, so a reply can be demuxed back to the node holding the state.
static __always_inline int vpc_nat_snat(struct __sk_buff *skb, struct pkt *p, __u32 net)
{
	struct vpc_nat *nat = bpf_map_lookup_elem(&vpc_nat, &net);
	if (!nat)
		return NAT_MISS; // no gateway, or no NAT identity: a closed island
	if (is_internal(p->dst))
		return NAT_MISS; // the tenant->system boundary: not ours to open
	if (p->is_v6)
		return NAT_MISS; // v6 VPC NAT: with the v6 pool work
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP && p->proto != IPPROTO_ICMP)
		return NAT_MISS;
	if (!ns_egress_ok(skb, net, 0, p->proto, p->src, p->dst))
		return TC_ACT_SHOT; // SG egress, the same gate the gateway path applies

	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > end || ip->ihl != 5)
		return NAT_MISS;
	__u32 osrc = ip->saddr;
	__u8 proto = ip->protocol;

	// The link that can source this address, not a node-wide guess.
	__u32 uplink;
	__be32 xnh = 0, xbase = 0, xmask = 0;
	struct ext_egress *xl = ext_link_of(&nat->ip);
	if (xl) {
		uplink = xl->ifindex;
		xnh = xl->nh;
		xbase = xl->base;
		xmask = xl->mask; // copied: a packet store invalidates the map value
	} else {
		uplink = cfg(CFG_UPLINK_IFINDEX); // no link claims it: a routed pool
	}
	if (!uplink)
		return NAT_MISS;

	if (proto == IPPROTO_ICMP) {
		__u8 type;
		__u16 id;
		if (icmp_echo(skb, &type, &id) < 0 || type != ICMP_ECHO_REQUEST)
			return NAT_MISS;
		struct ct_fwd_key fk = {
			.proto = proto, .net = net,
			.client_ip = p->src, .fabric_ip = p->dst,
			.client_port = id,
		};
		__u16 gw_id;
		__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
		if (have) {
			gw_id = *have;
		} else {
			gw_id = alloc_gw_port_in(proto, net, p->dst, 0, p->src, p->src, id,
						 nat->port_base, nat->port_span);
			if (!gw_id)
				return NAT_MISS; // shard full: better unmasqueraded than dropped
			bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
		}
		nat_addr(skb, proto, IP_SADDR_OFF, osrc, v4_of_128(&nat->ip));
		nat_icmp_id(skb, id, gw_id);
		count_ns(net, skb->len, NS_GW, 0);
		return ext_redirect(skb, uplink, xnh, xbase, xmask);
	}

	__u16 sport, dport;
	if (l4_ports(skb, &sport, &dport) < 0)
		return NAT_MISS;
	struct ct_fwd_key fk = {
		.proto = proto, .net = net,
		.client_ip = p->src, .fabric_ip = p->dst,
		.client_port = sport, .pod_port = dport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port_in(proto, net, p->dst, dport, p->src, p->src, sport,
					   nat->port_base, nat->port_span);
		if (!gw_port)
			return NAT_MISS;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}
	nat_addr(skb, proto, IP_SADDR_OFF, osrc, v4_of_128(&nat->ip));
	nat_port(skb, proto, L4_SPORT_OFF, sport, gw_port);
	// The VPC's egress, through its own boundary, wearing its own address.
	count_ns(net, skb->len, NS_GW, 0);
	return ext_redirect(skb, uplink, xnh, xbase, xmask);
}

// vpc_nat_reverse: the reply half. A packet addressed to a VPC's NAT address
// arrives at whichever node ATTRACTS that address — which is not necessarily the
// node whose ct_rev holds the flow, because the SNAT happened at the pod's veth.
// The port says who owns it: shard = (port - NAT_PORT_BASE) / NAT_SHARD_SPAN, and
// nat_owner maps that to the owning node.
//
// Owned here  -> un-NAT from ct_rev and deliver straight into the pod's veth.
// Owned there -> Geneve it to that node untouched, where from_overlay's probe
//                does exactly the same thing with its own ct_rev.
//
// Returns NAT_MISS when the packet is not for a VPC NAT address at all.
static __always_inline int vpc_nat_reverse(struct __sk_buff *skb, struct pkt *p)
{
	__u32 *netp = bpf_map_lookup_elem(&nat_of, &p->dst);
	if (!netp)
		return NAT_MISS;
	__u32 net = *netp;

	void *data = (void *)(long)skb->data, *end = (void *)(long)skb->data_end;
	struct iphdr *ip = data + ETH_HLEN;
	if ((void *)(ip + 1) > end || ip->ihl != 5)
		return NAT_MISS;
	__u8 proto = ip->protocol;
	__u32 odst = ip->daddr;

	__u16 gw_port = 0;
	__u16 sport = 0, dport = 0;
	__u8 type = 0;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		if (l4_ports(skb, &sport, &dport) < 0)
			return NAT_MISS;
		gw_port = dport;
	} else if (proto == IPPROTO_ICMP) {
		if (icmp_echo(skb, &type, &gw_port) < 0 || type != ICMP_ECHO_REPLY)
			return NAT_MISS;
	} else {
		return NAT_MISS;
	}

	// Whose shard is this port in?
	__u16 h = bpf_ntohs(gw_port);
	if (h < NAT_PORT_BASE)
		return NAT_MISS;
	struct nat_shard_key sk = { .ip = p->dst, .shard = (h - NAT_PORT_BASE) / NAT_SHARD_SPAN };
	__u32 *owner = bpf_map_lookup_elem(&nat_owner, &sk);
	if (!owner)
		return NAT_MISS;
	// nat_owner stores the node's Geneve endpoint the way `remotes` does — a
	// HOST-order integer, which is what encap()/bpf_skb_set_tunnel_key want.
	// CFG_NODE_IP holds the same address as raw network-order bytes (it is compared
	// against packet fields elsewhere), so it has to be swapped to compare. Getting
	// this wrong makes every reply "belong to someone else" and encapsulate into a
	// loop.
	if (*owner != bpf_ntohl(cfg(CFG_NODE_IP)))
		return encap(skb, net, *owner, 0); // the state lives on that node

	struct ct_rev_key rk = {
		.proto = proto, .gw_port = gw_port, .net = net,
		.vpc_ip = p->src, .pod_port = (proto == IPPROTO_ICMP) ? 0 : sport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return NAT_MISS; // no such flow: not a reply we masqueraded

	struct endpoint *l = local_of(net, rv->fabric_ip);
	if (!l)
		return NAT_MISS; // the pod went away under the flow

	nat_addr(skb, proto, IP_DADDR_OFF, odst, v4_of_128(&rv->fabric_ip));
	if (proto == IPPROTO_ICMP)
		nat_icmp_id(skb, gw_port, rv->client_port);
	else
		nat_port(skb, proto, L4_DPORT_OFF, gw_port, rv->client_port);
	// This IS gateway-forwarded ingress — the VPC's gateway, now in eBPF — and it
	// has to say so, or to_pod throws the reply away on the pod's own doorstep.
	// Two gates there care: the isolation check refuses srcnet==0 -> dstnet!=0
	// except for GW_MARK, and the SG ingress gate re-judges anything unmarked. The
	// reply is neither unsolicited nor unjudged: the pod opened the flow, the SG
	// EGRESS gate ran at the SNAT, and ct_rev proves it.
	//
	// ASSIGNED, not OR'd: the isolation escape tests `skb->mark == GW_MARK` for
	// exact equality, so an extra bit is as good as no mark at all.
	skb->mark = GW_MARK;
	count_ns(net, skb->len, NS_GW, 1);
	return deliver_local(skb, l);
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
	__u32 node_ip = cfg(CFG_MASQ_IP);
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
	__u32 node_ip = cfg(CFG_MASQ_IP);
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
	// North-south security groups (v2), the v6 twin of floating_forward: gated
	// unconditionally (external surface, never node-originated), TCP on a new
	// connection only so the replies of the pod's own flows come back.
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__u16 sp, dp, gated;
		if (sg_l4(skb, proto, L4_OFF6, &gated) && l4_ports6(skb, &sp, &dp) == 0 &&
		    !ns_sg_admit(net, &vpc_ip, &p->src, cidr_proto(proto, 1), dp)) {
			count_sg_drop(net);
			flow_emit(&p->src, &vpc_ip, FE_NETS(0, net), FE_PORTS(sp, dp),
				  FE_META(FE_V_DENY, FR_SG_NS, FE_TO_POD, NS_EIP, 0, proto));
			return TC_ACT_SHOT;
		}
	}
	nat_addr6(skb, proto, IP6_DADDR_OFF, &p->dst, &vpc_ip);
	// The EIP door, inbound — v6 twin (docs/north-south.md).
	count_ns(net, skb->len, NS_EIP, 1);
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
	// SG egress gates a floating pod's off-VPC traffic (the v4 twin's rationale).
	if (!ns_egress_ok(skb, net, 1, proto, p->src, p->dst))
		return TC_ACT_SHOT;
	// The link that can source this address. ext_links is v4-only today:
	// EnsureFloatingUplink returns early for a v6 address, so nothing writes a
	// v6 entry, which leaves the node-wide cell as the v6 answer until v6
	// floating-uplink selection exists. Dropping straight to the default uplink
	// here would move v6 egress off a secondary link that currently carries it.
	// No v6 next-hop cell either: the FIB resolves the neighbour on that link.
	struct ext_egress *xl = ext_link_of(public_ip);
	__u32 uplink = xl ? xl->ifindex : cfg(CFG_FLOAT_IFINDEX);
	if (!uplink)
		uplink = cfg(CFG_UPLINK_IFINDEX);
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
	// The EIP door, outbound — v6 twin (docs/north-south.md).
	count_ns(net, skb->len, NS_EIP, 0);
	return bpf_redirect_neigh(uplink, NULL, 0, 0);
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

// vpc_nat_snat6 / vpc_nat_reverse6: the v6 twins of vpc_nat_snat / vpc_nat_reverse
// (docs/north-south.md §6a). A dual-stack VPC wears a v4 identity for its v4 egress
// and a v6 identity for its v6 egress — one boundary, one vpc_nat entry, two
// addresses. The port shards, ct tables (addr128-keyed), nat_of and nat_owner are
// all shared: a v4 and a v6 flow are disambiguated by the NAT address family in
// nat_of/nat_owner and by the peer address in the ct keys, exactly as the v4/v6
// cluster masquerade already shares MASQ_PORT_BASE and the ct tables.
static __always_inline int vpc_nat_snat6(struct __sk_buff *skb, struct pkt *p, __u32 net)
{
	struct vpc_nat *nat = bpf_map_lookup_elem(&vpc_nat, &net);
	if (!nat)
		return NAT_MISS; // no gateway, or no NAT identity: a closed island
	struct addr128 natip = nat->ip6, zero = {};
	if (addr128_eq(&natip, &zero))
		return NAT_MISS; // no v6 identity: this VPC's v6 egress still uses the pod
	if (is_internal(p->dst))
		return NAT_MISS; // the tenant->system boundary: not ours to open
	if (v6_link_scoped(&p->dst))
		return NAT_MISS; // NDP and friends are link-local, not egress
	__u8 proto = p->proto;
	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP && proto != IPPROTO_ICMPV6)
		return NAT_MISS;
	if (!ns_egress_ok(skb, net, 1, proto, p->src, p->dst))
		return TC_ACT_SHOT; // SG egress, the same gate the gateway path applies
	__u32 pb = nat->port_base, ps = nat->port_span;

	// The link that can source this address. ext_links is v4-only today:
	// EnsureFloatingUplink returns early for a v6 address, so nothing writes a
	// v6 entry, which leaves the node-wide cell as the v6 answer until v6
	// floating-uplink selection exists. Dropping straight to the default uplink
	// here would move v6 egress off a secondary link that currently carries it.
	// No v6 next-hop cell either: the FIB resolves the neighbour on that link.
	struct ext_egress *xl = ext_link_of(&natip);
	__u32 uplink = xl ? xl->ifindex : cfg(CFG_FLOAT_IFINDEX);
	if (!uplink)
		uplink = cfg(CFG_UPLINK_IFINDEX);
	if (!uplink)
		return NAT_MISS;

	if (proto == IPPROTO_ICMPV6) {
		__u8 type;
		__u16 id;
		if (icmp6_echo(skb, &type, &id) < 0 || type != ICMP6_ECHO_REQUEST)
			return NAT_MISS;
		struct ct_fwd_key fk = {
			.proto = proto, .net = net,
			.client_ip = p->src, .fabric_ip = p->dst,
			.client_port = id,
		};
		__u16 gw_id;
		__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
		if (have) {
			gw_id = *have;
		} else {
			gw_id = alloc_gw_port_in(proto, net, p->dst, 0, p->src, p->src, id, pb, ps);
			if (!gw_id)
				return NAT_MISS; // shard full: better unmasqueraded than dropped
			bpf_map_update_elem(&ct_fwd, &fk, &gw_id, BPF_ANY);
		}
		nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &natip);
		nat_icmp6_id(skb, id, gw_id);
		count_ns(net, skb->len, NS_GW, 0);
		return bpf_redirect_neigh(uplink, NULL, 0, 0);
	}

	__u16 sport, dport;
	if (l4_ports6(skb, &sport, &dport) < 0)
		return NAT_MISS;
	struct ct_fwd_key fk = {
		.proto = proto, .net = net,
		.client_ip = p->src, .fabric_ip = p->dst,
		.client_port = sport, .pod_port = dport,
	};
	__u16 gw_port;
	__u16 *have = bpf_map_lookup_elem(&ct_fwd, &fk);
	if (have) {
		gw_port = *have;
	} else {
		gw_port = alloc_gw_port_in(proto, net, p->dst, dport, p->src, p->src, sport, pb, ps);
		if (!gw_port)
			return NAT_MISS;
		bpf_map_update_elem(&ct_fwd, &fk, &gw_port, BPF_ANY);
	}
	nat_addr6(skb, proto, IP6_SADDR_OFF, &p->src, &natip);
	nat_port6(skb, proto, L4_SPORT_OFF6, sport, gw_port);
	// The VPC's v6 egress, through its own boundary, wearing its own address.
	count_ns(net, skb->len, NS_GW, 0);
	return bpf_redirect_neigh(uplink, NULL, 0, 0);
}

static __always_inline int vpc_nat_reverse6(struct __sk_buff *skb, struct pkt *p)
{
	__u32 *netp = bpf_map_lookup_elem(&nat_of, &p->dst);
	if (!netp)
		return NAT_MISS;
	__u32 net = *netp;
	__u8 proto = p->proto;
	struct addr128 odst = p->dst;

	__u16 gw_port = 0, sport = 0, dport = 0;
	__u8 type = 0;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		if (l4_ports6(skb, &sport, &dport) < 0)
			return NAT_MISS;
		gw_port = dport;
	} else if (proto == IPPROTO_ICMPV6) {
		if (icmp6_echo(skb, &type, &gw_port) < 0 || type != ICMP6_ECHO_REPLY)
			return NAT_MISS;
	} else {
		return NAT_MISS;
	}

	__u16 h = bpf_ntohs(gw_port);
	if (h < NAT_PORT_BASE)
		return NAT_MISS;
	struct nat_shard_key sk = { .ip = p->dst, .shard = (h - NAT_PORT_BASE) / NAT_SHARD_SPAN };
	__u32 *owner = bpf_map_lookup_elem(&nat_owner, &sk);
	if (!owner)
		return NAT_MISS;
	if (*owner != bpf_ntohl(cfg(CFG_NODE_IP)))
		return encap(skb, net, *owner, 0); // the state lives on that node

	struct ct_rev_key rk = {
		.proto = proto, .gw_port = gw_port, .net = net,
		.vpc_ip = p->src, .pod_port = (proto == IPPROTO_ICMPV6) ? 0 : sport,
	};
	struct ct_rev_val *rv = bpf_map_lookup_elem(&ct_rev, &rk);
	if (!rv)
		return NAT_MISS;
	struct endpoint *l = local_of(net, rv->fabric_ip);
	if (!l)
		return NAT_MISS;
	struct addr128 pod = rv->fabric_ip;

	nat_addr6(skb, proto, IP6_DADDR_OFF, &odst, &pod);
	if (proto == IPPROTO_ICMPV6)
		nat_icmp6_id(skb, gw_port, rv->client_port);
	else
		nat_port6(skb, proto, L4_DPORT_OFF6, gw_port, rv->client_port);
	// Gateway-forwarded ingress: assigned, not OR'd (to_pod's isolation escape
	// tests skb->mark == GW_MARK for exact equality). Same as the v4 twin.
	skb->mark = GW_MARK;
	count_ns(net, skb->len, NS_GW, 1);
	return deliver_local(skb, l);
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
		// (found live on the dev cluster). The high 32 bits of the 64-bit product carry
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
	// net 0 included: a default-network ClusterIP (kpr-fed, KPR increment 3)
	// reply must un-DNAT backend->vip too. A non-service reply simply misses the
	// svc_rev lookup below and returns SVC_MISS, so this is safe for all net-0
	// traffic — just one extra hash lookup on the reply path.
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

// lb_return: the reply half of LoadBalancer/NodePort ingress
// (docs/lb-ingress.md), at the BACKEND's from_pod — the client is external,
// so the reply cannot ride a client-node to_pod the way ClusterIP/ServiceVIP
// replies do. A svc_rev hit whose entry from_uplink wrote (rv->lb) restores
// backend:tport -> lbIP:port with the client untouched (source preservation
// end to end) and exits by the public uplink, mirroring the floating exits:
// v4 picks the neighbour like floating_egress_snat (on the floating subnet
// the destination is its own neighbour, off it the agent-supplied virtual
// router); v6 resolves via the FIB like floating_egress_snat6. Works for
// net-0 and VPC-pod backends alike — the pinned reply identity is whatever
// address the pod answers from. Non-LB traffic misses (one LRU lookup) or
// hits with lb==0 (a same-node ClusterIP flow) and is left to the normal
// path.
#define LB_MISS -1

static __always_inline int lb_return(struct __sk_buff *skb, struct pkt *p, __u32 srcnet)
{
	if (p->proto != IPPROTO_TCP && p->proto != IPPROTO_UDP)
		return LB_MISS;
	if (!p->is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			return LB_MISS;
	}
	__u16 sport, dport;
	if (p->is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		     : l4_ports(skb, &sport, &dport) < 0)
		return LB_MISS;

	struct svc_rev_key rk = { .net = 0, .proto = p->proto, .cport = dport,
				  .backend = p->src, .client = p->dst, .tport = sport };
	struct svc_rev_val *rv = bpf_map_lookup_elem(&svc_rev, &rk);
	if (!rv || !rv->lb)
		return LB_MISS;
	// The LoadBalancer door, outbound: a VPC backend answering an external
	// client as the LB frontend. srcnet is 0 for a default-network backend, and
	// count_ns ignores net 0 — that traffic is the platform's, not a tenant's
	// (docs/north-south.md).
	count_ns(srcnet, skb->len, NS_LB, 0);

	// The flow's own arrival link is the most exact answer: it is right even for
	// an address no link's subnet covers. A DSR flow arrived over the overlay
	// and has none, so it falls back to the frontend address's own link — which
	// is the first correct answer those flows have had.
	__u32 uplink = rv->ifindex;
	__be32 xnh = 0, xbase = 0, xmask = 0;
	struct ext_egress *xl = ext_link_of(&rv->vip);
	if (xl) {
		if (!uplink)
			uplink = xl->ifindex;
		// The router belongs to that link; name it only if we leave by it.
		if (uplink == xl->ifindex) {
			xnh = xl->nh;
			xbase = xl->base;
			xmask = xl->mask; // copied: a packet store invalidates the value
		}
	}
	// The node-wide cell before the default uplink, matching the v6 egress
	// sites: lb_return serves both families, ext_links has no v6 entries, and a
	// v6 DSR reply has no arrival link either — dropping straight to the default
	// uplink would move it off a secondary link that currently carries it.
	if (!uplink)
		uplink = cfg(CFG_FLOAT_IFINDEX);
	if (!uplink)
		uplink = cfg(CFG_UPLINK_IFINDEX);
	if (!uplink)
		return TC_ACT_OK;

	if (p->is_v6) {
		struct addr128 vip = rv->vip;
		nat_addr6(skb, p->proto, IP6_SADDR_OFF, &p->src, &vip);
		if (sport != rv->vport)
			nat_port6(skb, p->proto, L4_SPORT_OFF6, sport, rv->vport);
		return bpf_redirect_neigh(uplink, NULL, 0, 0);
	}

	nat_addr(skb, p->proto, IP_SADDR_OFF, v4_of_128(&p->src), v4_of_128(&rv->vip));
	if (sport != rv->vport)
		nat_port(skb, p->proto, L4_SPORT_OFF, sport, rv->vport);

	return ext_redirect(skb, uplink, xnh, xbase, xmask);
}

// Per-CPU scratch for lb_ingress: the svc/ct keys and values are ~200 bytes
// of struct building that must not live on the stack — from_uplink (352
// bytes) + an lb_ingress that builds them locally exceeded the verifier's
// 512-byte combined call-stack limit (found live: 640).
struct lb_scratch {
	struct svc_fwd_key fk;
	struct svc_rev_key rk;
	struct svc_fwd_val fv;
	struct svc_rev_val rv;
	struct svc_key sk;
	struct addr128 backend; // the row backend (a pod/fabric address)
	struct addr128 dst;     // the delivered identity (VPC IP when bridged)
	struct lb_src_key lk;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct lb_scratch);
	__uint(max_entries, 1);
} lb_scratch SEC(".maps");

// lb_prog holds the LB-ingress program for the tail call out of from_uplink.
// A tail-callee gets a FRESH 512-byte stack and its own 1M-insn verification
// budget — the structural end of the combined-stack fights (from_pod is 496
// bytes, from_uplink 352; any BPF-to-BPF callee of theirs re-fights the
// limit). The agent re-populates slot 0 on every load; an unpopulated slot
// makes the tail call fall through to TC_ACT_OK (LB delivery off, nothing
// else affected).
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	// Retain the userspace reference that prevents the kernel from clearing
	// tail-call entries when the agent exits while pinned programs stay live.
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 6); // 0: lb_ingress (from_uplink), 1: lb_dsr
	                        // (from_overlay), 2: hf_ingress (host firewall,
	                        // every host-stack fall-through), 3: hf_egress
	                        // (node -> remote pod, from_pod's remotes hit)
	__type(key, __u32);
	__type(value, __u32);
} lb_prog SEC(".maps");

// lb_ingress: the inbound half at from_uplink (docs/lb-ingress.md) — dst may
// be a Service LB IP or this node's own address on a NodePort. kpr filled
// svc_vips at net 0 with THIS node's ready backends only (etp: Local as a
// per-node table filter): admit by loadBalancerSourceRanges when the row is
// flagged, select a local backend (lockstep with svc_forward — avalanched
// multiply-shift), pin the flow (lb=1 -> the reply exits via lb_return at
// the backend's from_pod), DNAT with the client source preserved, deliver
// locally. A VPC-pod backend is a second, bridge-shaped hop: the row carries
// the pod's FABRIC address, `bridges` maps it to {net, VPC IP}, the DNAT
// goes straight to the VPC IP (no client masquerade — source preservation is
// the point and the reply exits this same node), and SecurityGroups gate
// unconditionally, as on every deliberate external surface (the floating
// rule). A mis-attracted node has no row: the probe misses and the packet
// falls to the kernel — Local's contract (do not serve).
//
// Reached by TAIL CALL from from_uplink's tail (lb_prog): inlined there it
// blew the 1M-insn verification budget, and as a BPF-to-BPF callee its frame
// had to fit in 512 minus from_uplink's 352 bytes — the SG gate alone broke
// that. A tail-callee is its own program: fresh stack, own budget. The
// per-CPU scratch (above) still carries the key building; the clang
// store-elision hazard it guards against is position-independent.
SEC("tc")
int cozyplane_lb_ingress(struct __sk_buff *skb)
{
	pull_headers(skb);
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_NEXT;
	if (p.proto != IPPROTO_TCP && p.proto != IPPROTO_UDP)
		return TC_ACT_NEXT;
	if (!p.is_v6) {
		struct iphdr *ip;
		if (parse_ipv4(skb, &ip) < 0 || ip->ihl != 5)
			goto miss; // IP options: not an LB row, but maybe host-destined
	}
	__u16 sport, dport;
	if (p.is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		    : l4_ports(skb, &sport, &dport) < 0)
		return TC_ACT_NEXT;

	__u32 zero = 0;
	struct lb_scratch *s = bpf_map_lookup_elem(&lb_scratch, &zero);
	if (!s)
		return TC_ACT_NEXT;
	// Every field written explicitly, pads included — NO memset. Found live:
	// clang folded a memset-then-overwrite sequence on this per-CPU value
	// into dropping the overwrites (fwd keys landed with proto/cport/client
	// zeroed), and the barriers before each map call keep the stores from
	// being elided or sunk past the reader.
	s->fk.net = 0;
	s->fk.proto = p.proto;
	s->fk.pad = 0;
	s->fk.cport = sport;
	s->fk.client = p.src;
	s->fk.vip = p.dst;
	s->fk.vport = dport;
	s->fk.pad2 = 0;

	s->sk.net = 0;
	s->sk.proto = p.proto;
	s->sk.pad = 0;
	s->sk.port = dport;
	s->sk.vip = p.dst;
	asm volatile("" ::: "memory");
	struct svc_val *sv = bpf_map_lookup_elem(&svc_vips, &s->sk);
	if (!sv || !sv->n)
		goto miss;

	if (sv->flags & SVC_F_SRC_RANGES) {
		s->lk.prefixlen = 256; // full vip + full client: longest possible match
		s->lk.vip = p.dst;
		s->lk.client = p.src;
		asm volatile("" ::: "memory");
		if (!bpf_map_lookup_elem(&lb_src, &s->lk)) {
			// declared ranges, no match: firewall drop
			flow_emit(&p.src, &p.dst, 0, FE_PORTS(sport, dport),
				  FE_META(FE_V_DENY, FR_LB_SRCRANGE, FE_LB_INGRESS, NS_LB, 0, p.proto));
			return TC_ACT_SHOT;
		}
	}

	__u16 tport;
	asm volatile("" ::: "memory");
	struct svc_fwd_val *pin = bpf_map_lookup_elem(&svc_fwd, &s->fk);
	if (pin) {
		s->backend = pin->backend;
		tport = pin->tport;
	} else {
		__u32 n = sv->n;
		if (n > SVC_MAX_BACKENDS)
			n = SVC_MAX_BACKENDS;
		// Lockstep with svc_forward: ClientIP affinity drops the source
		// port; Knuth multiplicative hash + fold, multiply-shift reduce.
		__u16 hport = (sv->flags & SVC_F_AFFINITY) ? 0 : sport;
		__u32 h = svc_hash(&p, hport, dport);
		__u32 idx = (__u32)(((__u64)h * n) >> 32);
		asm volatile("%0 &= %1" : "+r"(idx) : "i"(SVC_MAX_BACKENDS - 1));
		s->backend = sv->be[idx].ip;
		tport = sv->be[idx].port;
	}

	// A VPC-pod backend: the row's address is the pod's fabric handle; the
	// tenant identity is one bridges hop away (bridges is node-local, so this
	// resolves only when the backend lives HERE — a remote VPC backend takes
	// the DSR path below and is bridged on its own node). The DNAT target and
	// the pinned reply identity are the VPC IP.
	struct bridge_ep *be = bridge_of(s->backend);
	struct endpoint *l;
	// `remote` is a SCALAR on purpose: spelling this as `!be && !l` lets
	// clang fuse the two null tests into a pointer OR (`r1 |= r0`), which
	// the verifier prohibits ("bitwise operator |= on pointer").
	int remote = 0;
	if (be) {
		s->dst = be->vpc_ip;
		// Tenet 7: ingress into a VPC is something the VPC's own boundary admits.
		// No gateway with ingress.loadBalancer, no door — whoever created the
		// Service (docs/north-south.md).
		if (!bpf_map_lookup_elem(&vpc_ingress, &be->net)) {
			count_ns_denied(be->net, NS_LB);
			flow_emit(&p.src, &s->dst, FE_NETS(0, be->net), FE_PORTS(sport, tport),
				  FE_META(FE_V_DENY, FR_LB_CLOSED, FE_LB_INGRESS, NS_LB, 0, p.proto));
			return TC_ACT_SHOT;
		}
		if (!ns_sg_admit(be->net, &be->vpc_ip, &s->fk.client, cidr_proto(p.proto, p.is_v6), tport)) {
			count_sg_drop(be->net);
			flow_emit(&p.src, &s->dst, FE_NETS(0, be->net), FE_PORTS(sport, tport),
				  FE_META(FE_V_DENY, FR_SG_NS, FE_LB_INGRESS, NS_LB, 0, p.proto));
			return TC_ACT_SHOT;
		}
		// The LoadBalancer door, inbound: a Service frontend the PLATFORM
		// attracted, delivered by the platform's uplink hook, landing on a
		// TENANT's pod — the crossing that today rides the platform's stack all
		// the way in without the VPC being involved (docs/north-south.md §1).
		// Counted here and only here: this node attracted the packet, and every
		// LB packet for a VPC backend passes this program exactly once, whether
		// the backend turns out to be local or is DSR'd onward.
		count_ns(be->net, skb->len, NS_LB, 1);
		l = local_of(be->net, be->vpc_ip);
	} else {
		s->dst = s->backend;
		l = local_of(0, s->backend);
		remote = (l == NULL);
	}

	if (!pin) {
		// The flow pin lives at the ingress node either way — stickiness for
		// every later packet of the flow, local or DSR'd.
		s->fv.backend = s->backend; // the ROW backend: re-resolved per packet
		s->fv.tport = tport;
		s->fv.hairpin = 0; // client is external, never a backend
		asm volatile("" ::: "memory");
		bpf_map_update_elem(&svc_fwd, &s->fk, &s->fv, BPF_ANY);
	}

	// Remote backend (etp: Cluster rows carry the cluster-wide set): DNAT to
	// the backend, keep the client source, and DSR-encapsulate to its node —
	// remotes at net 0 maps pod addresses to nodes. The reply identity is
	// pinned THERE (lb_dsr, from the Geneve option), because the reply exits
	// that node's uplink. No svc_rev pin here: the reply never passes us.
	if (remote) {
		__u32 *node_ip = remote_of(0, s->backend);
		if (!node_ip)
			return TC_ACT_SHOT; // a row backend with no home is misprogrammed
		s->rv.vip = p.dst; // scratch: carries {vip, vport} into encap_lb
		s->rv.vport = dport;
		if (p.is_v6) {
			nat_addr6(skb, p.proto, IP6_DADDR_OFF, &p.dst, &s->dst);
			if (dport != tport)
				nat_port6(skb, p.proto, L4_DPORT_OFF6, dport, tport);
		} else {
			nat_addr(skb, p.proto, IP_DADDR_OFF, v4_of_128(&p.dst), v4_of_128(&s->dst));
			if (dport != tport)
				nat_port(skb, p.proto, L4_DPORT_OFF, dport, tport);
		}
		return encap_lb(skb, *node_ip, &s->rv.vip, s->rv.vport);
	}

	if (!pin) {
		s->rk.net = 0;
		s->rk.proto = p.proto;
		s->rk.pad = 0;
		s->rk.cport = sport;
		s->rk.backend = s->dst; // the DELIVERED identity: what the reply carries
		s->rk.client = p.src;
		s->rk.tport = tport;
		s->rk.pad2 = 0;
		s->rv.vip = p.dst;
		s->rv.vport = dport;
		s->rv.lb = 1;
		s->rv.ifindex = skb->ingress_ifindex;
		asm volatile("" ::: "memory");
		bpf_map_update_elem(&svc_rev, &s->rk, &s->rv, BPF_ANY);
	}

	if (p.is_v6) {
		nat_addr6(skb, p.proto, IP6_DADDR_OFF, &p.dst, &s->dst);
		if (dport != tport)
			nat_port6(skb, p.proto, L4_DPORT_OFF6, dport, tport);
	} else {
		nat_addr(skb, p.proto, IP_DADDR_OFF, v4_of_128(&p.dst), v4_of_128(&s->dst));
		if (dport != tport)
			nat_port(skb, p.proto, L4_DPORT_OFF, dport, tport);
	}
	if (be)
		return l ? deliver_local(skb, l) : TC_ACT_OK;
	return l ? deliver_local(skb, l) : deliver_net0(skb, s->dst);

miss:
	// No LB row claimed it: this is host-destined (or transit) traffic on
	// its way to the kernel — the host firewall sees it first
	// (docs/host-firewall.md).
	if (HF_ARMED())
		bpf_tail_call(skb, &lb_prog, 2);
	return TC_ACT_NEXT;
}

// cozyplane_hf_ingress: the host firewall (docs/host-firewall.md), lb_prog
// slot 2 — tail-called (only under CFG_HF_ENABLED) from every fall-through
// that hands a packet to this node's host stack: from_uplink / lb_ingress
// miss (external and node→node), from_overlay's net-0 exit (cross-node
// pod→node via the node_remotes encap), and from_pod's final exit (same-node
// pod→node; at the uplink egress the same call carries node-ORIGINATED
// traffic, which only feeds the UDP reply-pin). A tail call means a fresh
// 512-byte stack and its own verifier budget — the policy from_pod's
// 496-byte frame could never host inline.
SEC("tc")
int cozyplane_hf_ingress(struct __sk_buff *skb)
{
	pull_headers(skb);
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;
	if (p.proto != IPPROTO_TCP && p.proto != IPPROTO_UDP && p.proto != IPPROTO_SCTP)
		return TC_ACT_OK; // ICMP/ARP/NDP are never gated (PMTU, ping, ND)
	__u16 sport, dport;
	if (p.is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		    : l4_ports(skb, &sport, &dport) < 0)
		return TC_ACT_OK;

	if (!bpf_map_lookup_elem(&hf_self, &p.dst)) {
		// Not host-destined (broadcast/multicast/transit stay ungated).
		// NODE-ORIGINATED traffic passing the uplink-egress fall-through:
		// the egress half (docs/host-firewall.md). (A forged self-sourced
		// packet could seed pins from outside, but the same forgery already
		// rides the np_nodes exemption below — the node-address trust model
		// is the underlay's anti-spoofing; path-trust is the fix, see
		// docs/policy-layers.md.)
		if (!bpf_map_lookup_elem(&hf_self, &p.src))
			return TC_ACT_OK;

		// node -> node stays exempt, always: kubelet<->apiserver, etcd, and
		// the agent's own API access ride it. This is what makes egress
		// isolation impossible to self-lock-out with.
		if (bpf_map_lookup_elem(&np_nodes, &p.dst))
			return TC_ACT_OK;

		if (cfg(CFG_HF_EG_ENABLED)) {
			int gate = 1;
			if (p.proto == IPPROTO_TCP) {
				__u8 flags = 0;
				__u32 l4o = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
				bpf_skb_load_bytes(skb, l4o + 13, &flags, 1);
				gate = (flags & 0x02) && !(flags & 0x10);
			}
			if (gate && (cfg(CFG_HF_EG_ENABLED) == 2 ||
				     !hf_gate(&hf_eallow, p.proto, dport, &p.dst, p.is_v6))) {
				hf_count_drop(NP_DIR_EG);
				flow_emit(&p.src, &p.dst, 0, FE_PORTS(sport, dport),
					  FE_META(FE_V_DENY, FR_HF_EGRESS, FE_HF_INGRESS, FE_NO_DOOR, 0, p.proto));
				return TC_ACT_SHOT;
			}
		}
		// Admitted (or egress not isolated): pin the UDP reply so it passes
		// the INGRESS gate on the way back.
		if (p.proto == IPPROTO_UDP) {
			struct np_ct_key ck = {
				.pod = p.src,
				.peer = p.dst,
				.pport = sport,
				.rport = dport,
				.proto = IPPROTO_UDP,
			};
			__u8 one = 1;
			bpf_map_update_elem(&hf_ct, &ck, &one, BPF_ANY);
		}
		return TC_ACT_OK;
	}

	// Host-destined. Baseline exemptions first (docs/host-firewall.md): the
	// firewall must not be able to kill the cluster it runs on.
	if (bpf_map_lookup_elem(&np_nodes, &p.src))
		return TC_ACT_OK; // node-sourced: kubelet/apiserver plumbing, Geneve outers
	if (p.proto == IPPROTO_TCP) {
		__u8 flags = 0;
		__u32 l4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
		bpf_skb_load_bytes(skb, l4off + 13, &flags, 1);
		if (!(flags & 0x02) || (flags & 0x10))
			return TC_ACT_OK; // not a bare SYN: established, or a reply
	} else if (p.proto == IPPROTO_UDP) {
		if (dport == bpf_htons((__u16)cfg(CFG_GENEVE_PORT)))
			return TC_ACT_OK; // never sever the overlay's own transport
		struct np_ct_key ck = {
			.pod = p.dst,
			.peer = p.src,
			.pport = dport,
			.rport = sport,
			.proto = IPPROTO_UDP,
		};
		if (bpf_map_lookup_elem(&hf_ct, &ck))
			return TC_ACT_OK; // the reply to a node-originated flow
	}

	if (!cfg(CFG_HF_ENABLED))
		return TC_ACT_OK; // egress-only object: ingress is not isolated

	if (cfg(CFG_HF_ENABLED) == 2 || !hf_gate(&hf_allow, p.proto, dport, &p.src, p.is_v6)) {
		hf_count_drop(NP_DIR_IN);
		flow_emit(&p.src, &p.dst, 0, FE_PORTS(sport, dport),
			  FE_META(FE_V_DENY, FR_HF_INGRESS, FE_HF_INGRESS, FE_NO_DOOR, 0, p.proto));
		return TC_ACT_SHOT;
	}
	// Admitted inbound UDP: pin the node's REPLY so it passes the egress
	// gate (statefulness is symmetric — the key is the one just computed).
	if (p.proto == IPPROTO_UDP) {
		struct np_ct_key ck = {
			.pod = p.dst,   // the node
			.peer = p.src,  // the client
			.pport = dport,
			.rport = sport,
			.proto = IPPROTO_UDP,
		};
		__u8 one = 1;
		bpf_map_update_elem(&hf_ct, &ck, &one, BPF_ANY);
	}
	return TC_ACT_OK;
}

// cozyplane_hf_egress: the host firewall's egress half for node -> REMOTE POD
// (docs/host-firewall.md) — the one node-originated path that never reaches a
// fall-through, because from_pod's remotes-hit encapsulates it. Tail-called
// from there (lb_prog slot 3) for node-sourced TCP/UDP/SCTP; a tail call never
// returns, so on admit this program performs the encap itself. An unpopulated
// slot falls through to from_pod's inline encap: fail-OPEN on delivery, never
// a black hole.
SEC("tc")
int cozyplane_hf_egress(struct __sk_buff *skb)
{
	pull_headers(skb);
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;
	__u16 sport, dport;
	if (p.is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		    : l4_ports(skb, &sport, &dport) < 0)
		return TC_ACT_OK;

	// node -> local pod never gets here (it is delivered, not encapsulated);
	// node -> node is exempt at the call site. This is node -> remote pod.
	//
	// The gate runs ONLY when egress is isolated: this program is reached
	// whenever EITHER direction is armed (one tail call serves both), so an
	// ingress-only firewall must fall straight through to the encap — gating
	// against an empty hf_eallow here would drop every node->remote-pod flow
	// (hostNetwork cluster DNS among them).
	if (cfg(CFG_HF_EG_ENABLED)) {
		int gate = 1;
		if (p.proto == IPPROTO_TCP) {
			__u8 flags = 0;
			__u32 l4o = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
			bpf_skb_load_bytes(skb, l4o + 13, &flags, 1);
			gate = (flags & 0x02) && !(flags & 0x10);
		}
		if (gate && (cfg(CFG_HF_EG_ENABLED) == 2 ||
			     !hf_gate(&hf_eallow, p.proto, dport, &p.dst, p.is_v6))) {
			hf_count_drop(NP_DIR_EG);
			flow_emit(&p.src, &p.dst, 0, FE_PORTS(sport, dport),
				  FE_META(FE_V_DENY, FR_HF_EGRESS, FE_HF_EGRESS, FE_NO_DOOR, 0, p.proto));
			return TC_ACT_SHOT;
		}
	}
	if (p.proto == IPPROTO_UDP) {
		struct np_ct_key ck = {
			.pod = p.src,
			.peer = p.dst,
			.pport = sport,
			.rport = dport,
			.proto = IPPROTO_UDP,
		};
		__u8 one = 1;
		bpf_map_update_elem(&hf_ct, &ck, &one, BPF_ANY);
	}

	// Admitted: re-resolve the destination and do the encap from_pod would
	// have done (net 0 — a node source is never in a VPC).
	__u32 *node_ip = remote_of(0, p.dst);
	if (!node_ip)
		return TC_ACT_OK; // raced with a remotes update: let the kernel try
	return encap(skb, 0, *node_ip, 0);
}

// cozyplane_lb_dsr: the receiving half of etp: Cluster (docs/lb-ingress.md),
// tail-called from from_overlay when a net-0 decap carries the LB option.
// The ingress node already DNAT'd to the backend and preserved the client;
// this node — where the backend lives and where the reply will exit — pins
// the frontend identity from the option (svc_rev, lb=1, lookup-first so
// steady-state packets don't rewrite the LRU), takes the bridges hop for a
// VPC-pod backend (SG-gated here, where the pod is local), and delivers.
SEC("tc")
int cozyplane_lb_dsr(struct __sk_buff *skb)
{
	pull_headers(skb);
	struct lb_geneve_opt lopt;
	if (bpf_skb_get_tunnel_opt(skb, (void *)&lopt, sizeof(lopt)) < (int)sizeof(lopt) ||
	    lopt.opt_class != bpf_htons(SG_OPT_CLASS) || lopt.type != LB_OPT_TYPE)
		return TC_ACT_SHOT; // tail-called on a match; anything else is malformed
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_SHOT;
	if (p.proto != IPPROTO_TCP && p.proto != IPPROTO_UDP)
		return TC_ACT_SHOT;
	__u16 sport, dport;
	if (p.is_v6 ? l4_ports6(skb, &sport, &dport) < 0
		    : l4_ports(skb, &sport, &dport) < 0)
		return TC_ACT_SHOT;

	__u32 zero = 0;
	struct lb_scratch *s = bpf_map_lookup_elem(&lb_scratch, &zero);
	if (!s)
		return TC_ACT_SHOT;

	struct bridge_ep *be = bridge_of(p.dst);
	struct endpoint *l;
	if (be) {
		s->dst = be->vpc_ip;
		if (!ns_sg_admit(be->net, &be->vpc_ip, &p.src, cidr_proto(p.proto, p.is_v6), dport)) {
			count_sg_drop(be->net);
			flow_emit(&p.src, &s->dst, FE_NETS(0, be->net), FE_PORTS(sport, dport),
				  FE_META(FE_V_DENY, FR_SG_INGRESS, FE_LB_DSR, NS_LB, 0, p.proto));
			return TC_ACT_SHOT;
		}
		l = local_of(be->net, be->vpc_ip);
	} else {
		s->dst = p.dst;
		l = local_of(0, p.dst);
	}

	// Pin the reply identity (explicit stores + barriers: the clang
	// store-elision hazard on per-CPU values, see lb_ingress).
	s->rk.net = 0;
	s->rk.proto = p.proto;
	s->rk.pad = 0;
	s->rk.cport = sport;
	s->rk.backend = s->dst;
	s->rk.client = p.src;
	s->rk.tport = dport;
	s->rk.pad2 = 0;
	asm volatile("" ::: "memory");
	if (!bpf_map_lookup_elem(&svc_rev, &s->rk)) {
		s->rv.vip = lopt.vip;
		s->rv.vport = lopt.vport;
		s->rv.lb = 1;
		// Arrived encapsulated: ingress_ifindex is the geneve device, not an
		// uplink, so leave it unset and fall back to the node-wide slot.
		s->rv.ifindex = 0;
		asm volatile("" ::: "memory");
		bpf_map_update_elem(&svc_rev, &s->rk, &s->rv, BPF_ANY);
	}

	if (be) {
		// The second, bridge-shaped DNAT: fabric -> VPC IP.
		if (p.is_v6) {
			nat_addr6(skb, p.proto, IP6_DADDR_OFF, &p.dst, &s->dst);
		} else {
			nat_addr(skb, p.proto, IP_DADDR_OFF, v4_of_128(&p.dst), v4_of_128(&s->dst));
		}
	}
	return l ? deliver_local(skb, l) : TC_ACT_OK;
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

// One branch, not sixteen -- see addr128_eq.
static __always_inline int addr128_zero(const struct addr128 *a)
{
	__u64 a0, a1;
	__builtin_memcpy(&a0, a->b, 8);
	__builtin_memcpy(&a1, a->b + 8, 8);
	return (a0 | a1) == 0;
}

// Socket LB may already have replaced the resolver's Service IP with an
// internal backend. Both boundary plumbing and steering must recognize it;
// the continuation still redirects the query, never delivering to that backend.
static __always_inline int dns_destination(struct pkt *p)
{
	__u32 fam = p->is_v6 ? 1 : 0;
	struct addr128 *dns = bpf_map_lookup_elem(&dns_ips, &fam);
	return dns && !addr128_zero(dns) &&
		(addr128_eq(dns, &p->dst) || is_internal(p->dst));
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
	if (!dns_destination(p))
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

// Managed VPC boundaries have their own maps and state. They are deliberately
// separate from additive tenant SGs and run before any NAT/Service return path.
struct boundary_policy { __u64 revision; __u64 identity; __u32 internet; __u32 pad; };
struct boundary_rule { __u64 revision; __u32 net; __u32 peer; __u16 port; __u8 proto; __u8 direction; __u32 pad; };
struct boundary_flow {
	struct addr128 src; struct addr128 dst;
	__u32 local; __u32 peer;
	__u16 sport; __u16 dport; __u8 proto; __u8 hook; __u16 pad;
};
struct boundary_flow_value { __u64 local_rev; __u64 peer_rev; __u64 local_id; __u64 peer_id; __u64 expires; };
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __type(key, __u32); __type(value, struct boundary_policy);
	__uint(max_entries, 16384); __uint(pinning, LIBBPF_PIN_BY_NAME);
} boundary_policy SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __type(key, struct boundary_rule); __type(value, __u8);
	__uint(max_entries, 131072); __uint(pinning, LIBBPF_PIN_BY_NAME);
} boundary_rules SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH); __type(key, struct boundary_flow); __type(value, struct boundary_flow_value);
	__uint(max_entries, 262144); __uint(pinning, LIBBPF_PIN_BY_NAME);
} boundary_ct SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH); __type(key, struct local_key); __type(value, __u8);
	__uint(max_entries, 65536); __uint(pinning, LIBBPF_PIN_BY_NAME);
} boundary_primary SEC(".maps");
struct boundary_cidr { __u32 prefixlen; struct addr128 addr; };
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE); __type(key, struct boundary_cidr); __type(value, __u8);
	__uint(max_entries, 32768); __uint(map_flags, BPF_F_NO_PREALLOC); __uint(pinning, LIBBPF_PIN_BY_NAME);
} boundary_cidrs SEC(".maps");
struct boundary_scratch {
	struct pkt packet;
	struct boundary_flow key; struct boundary_flow reverse;
	struct boundary_flow_value value; struct boundary_rule rule;
	struct boundary_cidr cidr; struct local_key endpoint;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __type(key, __u32); __type(value, struct boundary_scratch);
	__uint(max_entries, 1);
} boundary_scratch SEC(".maps");

// Only ordinary unfragmented IP is supported by the managed L4 boundary.
// Reject options/extension chains and fragments rather than reading guessed L4.
static __always_inline int boundary_l4(struct __sk_buff *skb, struct boundary_scratch *s)
{
	__u32 off = ETH_HLEN + (s->packet.is_v6 ? 40 : 20);
	if (!s->packet.is_v6) {
		__u8 vihl; __u16 frag;
		if (bpf_skb_load_bytes(skb, ETH_HLEN, &vihl, 1) < 0 || vihl != 0x45 ||
		    bpf_skb_load_bytes(skb, ETH_HLEN + 6, &frag, 2) < 0 ||
		    (bpf_ntohs(frag) & 0x3fff)) return 0;
	}
	s->key.proto = s->packet.proto;
	if (s->packet.proto == IPPROTO_TCP || s->packet.proto == IPPROTO_UDP) {
		if (bpf_skb_load_bytes(skb, off, &s->key.sport, 2) < 0 ||
		    bpf_skb_load_bytes(skb, off + 2, &s->key.dport, 2) < 0) return 0;
		return 1;
	}
	if (s->packet.proto == IPPROTO_ICMP || s->packet.proto == IPPROTO_ICMPV6) {
		// Keep the exact type/code in the CT tuple and rule key. Echo also
		// carries its identifier, preventing one ping from admitting another.
		if (bpf_skb_load_bytes(skb, off, &s->key.dport, 2) < 0 ||
		    bpf_skb_load_bytes(skb, off + 4, &s->key.sport, 2) < 0) return 0;
		return 1;
	}
	return 0;
}

// Error quotations are not fresh initiations. Only the opposite hook's existing
// flow may admit one; inspecting a quote must never create or refresh flow state.
// Returns -1 for a non-error message, otherwise an exact related-flow verdict.
static __attribute__((noinline)) int boundary_related_error(struct __sk_buff *skb,
							   struct boundary_scratch *s)
{
	__u16 tc = bpf_ntohs(s->key.dport);
	__u8 type = tc >> 8, code = tc & 0xff;
	if (s->key.proto == IPPROTO_ICMP && !s->packet.is_v6) {
		if (type != 3 && type != 11 && type != 12) return -1;
		if ((type == 3 && code > 15) || (type == 11 && code > 1) ||
		    (type == 12 && code > 2)) return 0;
	} else if (s->key.proto == IPPROTO_ICMPV6 && s->packet.is_v6) {
		if (type >= 128) return -1;
		// RFC 4443's four error formats and their defined codes.
		if (type < 1 || type > 4 || (type == 1 && code > 6) ||
		    (type == 2 && code) || (type == 3 && code > 1) ||
		    (type == 4 && code > 2)) return 0;
	} else return -1;

	__u32 quoted = ETH_HLEN + (s->packet.is_v6 ? 40 : 20) + 8;
	__u8 version, proto, l4[8];
	if (bpf_skb_load_bytes(skb, quoted, &version, 1) < 0) return 0;
	s->reverse = s->key;
	s->reverse.hook = !s->key.hook;
	if (s->packet.is_v6) {
		if ((version >> 4) != 6 ||
		    bpf_skb_load_bytes(skb, quoted + 6, &proto, 1) < 0 ||
		    bpf_skb_load_bytes(skb, quoted + 8, &s->reverse.src, 16) < 0 ||
		    bpf_skb_load_bytes(skb, quoted + 24, &s->reverse.dst, 16) < 0)
			return 0;
		quoted += 40;
	} else {
		__u16 frag;
		__u32 src, dst;
		if (version != 0x45 ||
		    bpf_skb_load_bytes(skb, quoted + 6, &frag, 2) < 0 ||
		    (bpf_ntohs(frag) & 0x3fff) ||
		    bpf_skb_load_bytes(skb, quoted + 9, &proto, 1) < 0 ||
		    bpf_skb_load_bytes(skb, quoted + 12, &src, 4) < 0 ||
		    bpf_skb_load_bytes(skb, quoted + 16, &dst, 4) < 0)
			return 0;
		v4_to_128(&s->reverse.src, src);
		v4_to_128(&s->reverse.dst, dst);
		quoted += 20;
	}
	// An error belongs to the quoted sender, never another endpoint in its VPC.
	if (!addr128_eq(&s->reverse.src, &s->packet.dst) ||
	    bpf_skb_load_bytes(skb, quoted, l4, sizeof(l4)) < 0) return 0;
	s->reverse.proto = proto;
	if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
		__builtin_memcpy(&s->reverse.sport, l4, 2);
		__builtin_memcpy(&s->reverse.dport, l4 + 2, 2);
	} else if ((!s->packet.is_v6 && proto == IPPROTO_ICMP &&
		    (l4[0] == 8 || l4[0] == 0) && !l4[1]) ||
		   (s->packet.is_v6 && proto == IPPROTO_ICMPV6 &&
		    (l4[0] == 128 || l4[0] == 129) && !l4[1])) {
		__builtin_memcpy(&s->reverse.dport, l4, 2);
		__builtin_memcpy(&s->reverse.sport, l4 + 4, 2);
	} else return 0; // no extension chains, fragments or nested error quotations
	struct boundary_flow_value *ct = bpf_map_lookup_elem(&boundary_ct, &s->reverse);
	if (!ct || ct->local_rev != s->value.local_rev ||
	    ct->peer_rev != s->value.peer_rev || ct->local_id != s->value.local_id ||
	    ct->peer_id != s->value.peer_id || ct->expires <= bpf_ktime_get_ns()) return 0;
	return 1;
}

static __attribute__((noinline)) int boundary_gate(struct __sk_buff *skb, struct boundary_scratch *s)
{
	struct boundary_policy *local = bpf_map_lookup_elem(&boundary_policy, &s->key.local);
	struct boundary_policy *peer = bpf_map_lookup_elem(&boundary_policy, &s->key.peer);
	// Materialize scalar presence: LLVM must not combine map pointers with OR,
	// an operation forbidden by the kernel verifier.
	volatile __u8 local_present = local != 0;
	volatile __u8 peer_present = peer != 0;
	if (!local_present && !peer_present) return 1; // legacy VPCs retain existing behavior
	if (!local || !local->revision) return 0;
	if (s->key.local == s->key.peer) return 1; // tenant SGs govern within a VPC
	if (!boundary_l4(skb, s)) return 0;
	if (!s->key.peer) {
		// North-south delivery keeps existing ingress gates. Outbound Internet
		// requires both a VPC grant and an authenticated primary attachment.
		if (s->key.hook) return 1;
		s->cidr.prefixlen = 128; s->cidr.addr = s->packet.dst;
		if (bpf_map_lookup_elem(&boundary_cidrs, &s->cidr)) return 0;
		s->endpoint.net = s->key.local; s->endpoint.ip = s->packet.src;
		return local->internet && bpf_map_lookup_elem(&boundary_primary, &s->endpoint);
	}
	if (!peer || !peer->revision) return 0;
	s->value.local_rev = local->revision; s->value.peer_rev = peer->revision;
	s->value.local_id = local->identity; s->value.peer_id = peer->identity;
	if (s->key.proto == IPPROTO_ICMP || s->key.proto == IPPROTO_ICMPV6) {
		int related = boundary_related_error(skb, s);
		if (related >= 0) return related;
	}
	struct boundary_flow_value *ct = bpf_map_lookup_elem(&boundary_ct, &s->key);
	__u64 now = bpf_ktime_get_ns();
	if (ct && ct->local_rev == s->value.local_rev && ct->peer_rev == s->value.peer_rev &&
	    ct->local_id == s->value.local_id && ct->peer_id == s->value.peer_id && ct->expires > now) {
		ct->expires = now + 30000000000ULL;
		return 1;
	}
	// ACK/data without tracked authorization cannot initiate a TCP flow.
	if (s->key.proto == IPPROTO_TCP) {
		__u8 flags;
		__u32 off = ETH_HLEN + (s->packet.is_v6 ? 40 : 20);
		if (bpf_skb_load_bytes(skb, off + 13, &flags, 1) < 0 ||
		    !(flags & 2) || (flags & (0x10 | 0x04 | 0x01))) return 0;
	}
	s->rule.revision = s->value.local_rev; s->rule.net = s->key.local;
	s->rule.peer = s->key.peer; s->rule.proto = s->key.proto;
	s->rule.port = s->key.dport; s->rule.direction = s->key.hook;
	if (!bpf_map_lookup_elem(&boundary_rules, &s->rule)) return 0;
	s->rule.revision = s->value.peer_rev; s->rule.net = s->key.peer;
	s->rule.peer = s->key.local; s->rule.direction = !s->key.hook;
	if (!bpf_map_lookup_elem(&boundary_rules, &s->rule)) return 0;
	s->value.expires = now + 30000000000ULL;
	if (bpf_map_update_elem(&boundary_ct, &s->key, &s->value, BPF_ANY) < 0) return 0;
	s->reverse = s->key; s->reverse.src = s->key.dst; s->reverse.dst = s->key.src;
	s->reverse.hook = !s->key.hook;
	if (s->key.proto == IPPROTO_TCP || s->key.proto == IPPROTO_UDP) {
		s->reverse.sport = s->key.dport; s->reverse.dport = s->key.sport;
	} else {
		__u16 tc = bpf_ntohs(s->key.dport);
		if (s->key.proto == IPPROTO_ICMP && tc == 0x0800) s->reverse.dport = 0;
		else if (s->key.proto == IPPROTO_ICMPV6 && tc == 0x8000) s->reverse.dport = bpf_htons(0x8100);
		else return 1; // only echo has a defined automatic reply pair
	}
	return bpf_map_update_elem(&boundary_ct, &s->reverse, &s->value, BPF_ANY) == 0;
}

// Only local NS/NA control frames bypass source RPF. Their source can be
// link-local or unspecified (DAD), not an authoritative VPC endpoint. The
// kernel validates the checksum/options on this veth; nothing enters overlay.
static __always_inline int boundary_neighbor_discovery(struct __sk_buff *skb)
{
	__u8 version, target_first;
	__u16 payload, protocol_hop, type_code;
	struct addr128 dst;
	if (bpf_skb_load_bytes(skb, ETH_HLEN + 6, &protocol_hop, sizeof(protocol_hop)) < 0 ||
	    protocol_hop != bpf_htons((IPPROTO_ICMPV6 << 8) | 255) ||
	    bpf_skb_load_bytes(skb, ETH_HLEN, &version, sizeof(version)) < 0 ||
	    (version >> 4) != 6 ||
	    bpf_skb_load_bytes(skb, ETH_HLEN + 4, &payload, sizeof(payload)) < 0 ||
	    bpf_ntohs(payload) < 24 || skb->len < ETH_HLEN + 40 + bpf_ntohs(payload) ||
	    bpf_skb_load_bytes(skb, ETH_HLEN + 24, &dst, sizeof(dst)) < 0 ||
	    !v6_link_scoped(&dst) || (dst.b[0] == 0xff && (dst.b[1] & 0x0f) != 2) ||
	    bpf_skb_load_bytes(skb, L4_OFF6, &type_code, sizeof(type_code)) < 0 ||
	    (type_code != bpf_htons(135 << 8) && type_code != bpf_htons(136 << 8)) ||
	    bpf_skb_load_bytes(skb, NDP_TARGET_OFF, &target_first, sizeof(target_first)) < 0 ||
	    target_first == 0xff)
		return 0;
	return 1;
}

// A guest has no authoritative VPC source while acquiring its pinned IPv6
// address. Admit only local RS/DHCPv6 client frames to the veth responder;
// neither path can enter the overlay or carry ordinary link-local data.
static __attribute__((noinline)) int boundary_guest_config(struct __sk_buff *skb)
{
	struct pkt p;
	__u16 payload;
	if (parse_ip(skb, &p) < 0 || !p.is_v6 ||
	    bpf_skb_load_bytes(skb, ETH_HLEN + 4, &payload, 2) < 0 ||
	    skb->len < ETH_HLEN + 40 + bpf_ntohs(payload)) return 0;
	struct addr128 gw = LINK_LOCAL_GW6;
	int link_source = p.src.b[0] == 0xfe && (p.src.b[1] & 0xc0) == 0x80;
	if (p.proto == IPPROTO_ICMPV6) {
		struct addr128 zero = {}, routers = {{0xff, 2, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 2}};
		__u8 hop;
		__u16 type_code;
		return (link_source || addr128_eq(&p.src, &zero)) &&
			(addr128_eq(&p.dst, &routers) || addr128_eq(&p.dst, &gw)) &&
			bpf_ntohs(payload) >= 8 &&
			bpf_skb_load_bytes(skb, ETH_HLEN + 7, &hop, 1) == 0 && hop == 255 &&
			bpf_skb_load_bytes(skb, L4_OFF6, &type_code, 2) == 0 &&
			type_code == bpf_htons(133 << 8);
	}
	if (p.proto == IPPROTO_UDP && link_source) {
		struct addr128 servers = {{0xff, 2, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 1, 0, 2}};
		__u16 ports[2], length;
		return (addr128_eq(&p.dst, &servers) || addr128_eq(&p.dst, &gw)) &&
			bpf_ntohs(payload) >= 12 &&
			bpf_skb_load_bytes(skb, L4_OFF6, ports, sizeof(ports)) == 0 &&
			ports[0] == bpf_htons(546) && ports[1] == bpf_htons(547) &&
			bpf_skb_load_bytes(skb, L4_OFF6 + 4, &length, 2) == 0 && length == payload;
	}
	return 0;
}

SEC("tc")
int cozyplane_from_pod(struct __sk_buff *skb)
{
	pull_headers(skb);
	__u32 origin = skb->ifindex;
	__u32 *state = bpf_map_lookup_elem(&ports, &origin);
	if (state && *state == PORT_QUARANTINE) return TC_ACT_SHOT;
	if (unsupported_ip_header(skb)) return TC_ACT_SHOT;
	// ARP already passes in the continuation. Keep management neighbour
	// discovery independent of tail-call readiness; IP still fails closed.
	__u16 ether_type;
	if (bpf_skb_load_bytes(skb, 12, &ether_type, sizeof(ether_type)) == 0) {
		if (ether_type == bpf_htons(ETH_P_ARP) ||
		    (ether_type == bpf_htons(ETH_P_IPV6) &&
		     (boundary_neighbor_discovery(skb) || boundary_guest_config(skb))))
			return TC_ACT_OK;
	}
	__u32 zero = 0, net = 0;
	__u32 ifindex = skb->ifindex;
	__u32 *port = bpf_map_lookup_elem(&ports, &ifindex);
	if (port) net = PORT_NET(*port);
	struct boundary_scratch *s = bpf_map_lookup_elem(&boundary_scratch, &zero);
	if (!s) return TC_ACT_SHOT;
	__builtin_memset(s, 0, sizeof(*s));
	if (net && parse_ip(skb, &s->packet) == 0) {
		s->key.local = net; s->key.peer = net_of(&networks, net, s->packet.dst);
		s->key.src = s->packet.src; s->key.dst = s->packet.dst;
		struct boundary_policy *bp = bpf_map_lookup_elem(&boundary_policy, &net);
		struct boundary_policy *peer_policy = bpf_map_lookup_elem(&boundary_policy, &s->key.peer);
		if (!bp && peer_policy) return TC_ACT_SHOT;
		if (bp && !(port && (*port & PORT_F_GATEWAY))) {
			struct endpoint *self = local_of(net, s->packet.src);
			if (!self || self->ifindex != skb->ifindex) return TC_ACT_SHOT;
			struct addr128 gw4, gw6 = LINK_LOCAL_GW6;
			v4_to_128(&gw4,bpf_htonl(LINK_LOCAL_GW));
			int plumbing = addr128_eq(&s->packet.dst, &gw4) || addr128_eq(&s->packet.dst, &gw6) ||
				(s->packet.is_v6 && v6_link_scoped(&s->packet.dst));
			if (!plumbing && !s->key.peer && cfg(CFG_RESOLVER_PORT) && dns_destination(&s->packet) &&
			    (s->packet.proto == IPPROTO_TCP || s->packet.proto == IPPROTO_UDP) && boundary_l4(skb, s) &&
			    s->key.dport == bpf_htons(53)) plumbing = 1;
			if (!plumbing && !boundary_gate(skb, s)) return TC_ACT_SHOT;
		}
	}
	bpf_tail_call(skb, &lb_prog, 4);
	return TC_ACT_SHOT; // no continuation means no enforcement-ready dataplane
}

static __always_inline int from_pod(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	__u32 *sp = bpf_map_lookup_elem(&ports, &ifindex);
	// Revocation dominates every protocol and every sanctioned NAT bypass.
	if (sp && *sp == PORT_QUARANTINE)
		return TC_ACT_SHOT;
	// A pod can set SO_MARK with CAP_NET_RAW on current kernels. Private marks
	// are proof only when assigned by this host after crossing the origin veth.
	if (ifindex != cfg(CFG_UPLINK_IFINDEX))
		skb->mark &= ~(GW_MARK | SG_OK | NS_MARK | FWD_MARK | VPC_MARK);
	if (unsupported_ip_header(skb))
		return TC_ACT_SHOT;
	// The boundary wrapper has finished before this tail call. Reuse its
	// per-CPU packet scratch to keep the continuation plus MSS callee below
	// the kernel's combined stack budget; there is no suspended caller.
	__u32 packet_zero = 0;
	struct boundary_scratch *packet_scratch = bpf_map_lookup_elem(&boundary_scratch, &packet_zero);
	if (!packet_scratch) return TC_ACT_SHOT;
	struct pkt *p = __builtin_assume_aligned(&packet_scratch->packet, 8);
	if (parse_ip(skb, p) < 0)
		return TC_ACT_OK;

	__u32 srcnet = 0, is_gw = 0, is_fwd = 0, is_fwd_scoped = 0, foreign_src = 0;
	if (sp) {
		srcnet = PORT_NET(*sp);
		is_gw = *sp & PORT_F_GATEWAY;
		is_fwd = *sp & PORT_F_FORWARD;
		is_fwd_scoped = *sp & PORT_F_FWD_SCOPED;
	}

	// At the uplink-egress attachment only: bpf cluster-egress masquerade
	// (#10). A kernel-forwarded pod packet leaving the cluster gets SNAT'd
	// here instead of by an iptables MASQUERADE rule. Everything else (node
	// traffic, geneve encap, floated egress with its public source) misses.
	if (ifindex == cfg(CFG_UPLINK_IFINDEX)) {
		int m = p->is_v6 ? masq_snat6(skb, p) : masq_snat(skb, p);
		if (m != MASQ_MISS)
			return m;
	}

	// Only neighbour discovery and DHCPv6 may precede source authentication.
	// General link-local traffic and bridge replies are not identity proof.
	if (p->is_v6 && v6_link_scoped(&p->dst)) {
		if (p->proto == IPPROTO_ICMPV6) {
			__u8 type = 0, code = 1, hops = 0;
			bpf_skb_load_bytes(skb, ETH_HLEN + 40, &type, 1);
			bpf_skb_load_bytes(skb, ETH_HLEN + 41, &code, 1);
			bpf_skb_load_bytes(skb, ETH_HLEN + 7, &hops, 1);
			if (hops == 255 && !code && (type == 133 || type == 135 || type == 136))
				return TC_ACT_OK;
		}
		if (p->proto == IPPROTO_UDP) {
			__u16 sport = 0, dport = 0;
			bpf_skb_load_bytes(skb, ETH_HLEN + 40, &sport, 2);
			bpf_skb_load_bytes(skb, ETH_HLEN + 42, &dport, 2);
			if (sport == bpf_htons(546) && dport == bpf_htons(547))
				return TC_ACT_OK;
		}
	}

	// Source-address RPF (docs/security-groups.md § anti-spoof). A VPC pod's
	// SecurityGroup identity is keyed on its source IP (sg_members[{net,src}]),
	// so a pod forging a co-VPC neighbour's address would inherit that
	// neighbour's groups — on every path, since the cross-node TLV's srcmap is
	// itself computed from this (spoofable) p->src. Authenticate it here, at the
	// origin veth: the source must own the address it claims — locals[{srcnet,
	// p->src}] must resolve to THIS veth. A forged co-VPC IP maps to a different
	// veth (or nothing); drop it before it can influence any downstream
	// identity decision. Gateway legs are exempt (they forward off-VPC sources).
	// Inline, no callee (from_pod's 496-byte frame; the 544 lesson); the drop
	// counts against the per-VPC sg_drops counter.
	if (sp && !is_gw && ifindex != cfg(CFG_UPLINK_IFINDEX)) {
		// These are host-generated NAT identities. A forwarding grant, or a
		// local record in a conflicting CIDR, cannot authorize impersonation.
		if (!p->is_v6 && (v4_of_128(&p->src) == bpf_htonl(LINK_LOCAL_GW) ||
		                  v4_of_128(&p->src) == bpf_htonl(SVC_LOOPBACK)))
			return TC_ACT_SHOT;
		struct endpoint *self = local_of(srcnet, p->src);
		if (!self || self->ifindex != ifindex) {
			// A forwarding leg (VPCBinding.allowForwarding) is permitted to
			// emit a source it does not own — that IS routing. Everything
			// else is a spoof. Record that the source is foreign, because
			// only such a packet gets FWD_MARK: the router's OWN traffic
			// must keep taking the ordinary east-west path, groups and all.
			//
			// A SCOPED forwarding leg (VPCBinding.forwardingCIDRs, issue #6)
			// admits a foreign source ONLY within its declared prefixes —
			// anti-spoofing stays on for everything else, closing the blanket
			// impersonation an unscoped grant allows. An unscoped leg (no
			// PORT_F_FWD_SCOPED) keeps the legacy all-foreign behaviour.
			int fwd_ok = is_fwd;
			if (is_fwd && is_fwd_scoped) {
				struct fwd_cidr_key fk = { .prefixlen = 64 + 128, .scope_net = ifindex,
					.family = p->is_v6 ? 6 : 4, .addr = p->src };
				fwd_ok = bpf_map_lookup_elem(&fwd_cidrs, &fk) != NULL;
			}
			if (!fwd_ok) {
				__u64 *d = bpf_map_lookup_elem(&sg_drops, &srcnet);
				if (d)
					(*d)++;
				flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, 0), 0,
					       FE_META(FE_V_DENY, FR_SPOOF, FE_FROM_POD, FE_NO_DOOR, 0, p->proto), 0);
				return TC_ACT_SHOT;
			}
			foreign_src = 1;
		}
	}

	// A v6 VPC pod's reply to fe80::1 is the return half of the v6 fabric bridge:
	// un-NAT it and deliver on the default network. Tested before the link-scoped
	// bypass below because it is *unicast* to the gateway, whereas NDP is to the
	// solicited-node multicast — so the two never collide.
	struct addr128 gw6 = LINK_LOCAL_GW6;
	if (p->is_v6 && addr128_eq(&p->dst, &gw6))
		return bridge_reverse6(skb, p, srcnet);

	// A self-dialled ServiceVIP's reply half answers to the hairpin loopback;
	// like fe80::1 above, checked before the link-scoped bypass.
	struct addr128 svclp6 = SVC_LOOPBACK6;
	if (p->is_v6 && addr128_eq(&p->dst, &svclp6))
		return svc_hairpin_reverse(skb, p, srcnet);

	// v6 link-local / multicast (the pod resolving its on-link gateway via NDP,
	// router solicitations, …) is link-scoped: hand it to the kernel so the host
	// veth answers, never overlay-deliver it or subject it to isolation.
	if (p->is_v6 && v6_link_scoped(&p->dst))
		return srcnet ? TC_ACT_SHOT : TC_ACT_OK;

	// A failed source-node membership sync must not stamp an omitted identity
	// as "ungrouped" and let a healthy destination apply legacy egress allow.
	// Reply NAT/plumbing above remains available; new workload flows stop here.
	if (srcnet && !is_gw && cfg(CFG_SG_UPDATING)) {
		__u16 port;
		if (sg_l4(skb, p->proto, p->is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20), &port))
			return TC_ACT_SHOT;
	}

	// The destination's network, resolved within the source's scope: its own
	// CIDR or a peer's. Overlapping CIDRs in other VPCs are invisible here.
	// Family-agnostic — the addresses are already 128-bit map keys.
	__u32 dstnet = net_of(&networks, srcnet, p->dst);

	// An explicit per-VPC route is the first off-VPC decision. VPN prefixes
	// must win before specialised DNS, LB-return and FloatingIP processing.
	if (srcnet && !dstnet && !is_gw) {
		if (routes_blocked(srcnet))
			return TC_ACT_SHOT;
		struct route_entry *route = route_of(srcnet, p->dst);
		struct gw_entry *rt = route_next_hop(route, p);
		if (route && !rt)
			return TC_ACT_SHOT; // unresolved explicit route, not a NAT miss
		if (rt) {
			if (!ns_egress_ok(skb, srcnet, p->is_v6, p->proto, p->src, p->dst)) {
				flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, 0), 0,
					       FE_META(FE_V_DENY, FR_SG_EGRESS, FE_FROM_POD, NS_APPLIANCE, 0, p->proto), 0);
				return TC_ACT_SHOT;
			}
			count_ns(srcnet, skb->len, NS_APPLIANCE, 0);
			flow_allow_core(skb, &p->src, &p->dst, FE_NETS(srcnet, 0),
					FE_META(FE_V_ALLOW, FR_ALLOW, FE_FROM_POD, NS_APPLIANCE, 0, p->proto) |
					FE_L4OFF(p->is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20)));
			// This SYN enters the VPN appliance whether its Port is local or
			// remote. Clamp before either the direct veth delivery or Geneve.
			tcp_mss_clamp_packet(skb);
			if (!rt->node_ip) {
				struct endpoint *rl = local_of(srcnet, rt->gw_ip);
				if (rl)
					return deliver_local(skb, rl);
				return TC_ACT_SHOT;
			}
			return encap(skb, srcnet, rt->node_ip, 0);
		}
	}

	// VPC DNS: a pod's off-VPC query to the cluster DNS address is steered to
	// the node-local split-horizon resolver — checked before the floating/
	// gateway/isolation logic so every VPC pod (floating, gateway'd, or plain)
	// gets DNS the same way, and only when the destination resolved off-VPC,
	// so a tenant whose CIDR covers the service range shadows it (sovereignty).
	if (srcnet && !is_gw && !dstnet) {
		int d = dns_steer(skb, p, srcnet);
		if (d != DNS_MISS)
			return d;
	}

	// LoadBalancer/NodePort reply (docs/lb-ingress.md): a backend — net-0 pod
	// or VPC pod — answering the external client whose flow from_uplink
	// DNAT'd. Checked before the floating/gateway/masquerade paths would
	// claim the reply (the client must see the LB IP: a floating backend's
	// own EIP SNAT or the node masquerade would rewrite it wrong). Pod-veth
	// attachment only, external destinations only (!dstnet); costs one LRU
	// miss on other off-net egress.
	if (!is_gw && !dstnet && ifindex != cfg(CFG_UPLINK_IFINDEX)) {
		int lr = lb_return(skb, p, srcnet);
		if (lr != LB_MISS)
			return lr;
	}

	// Enforce egress at the authenticated origin, before any bridge/service
	// redirect can bypass the destination-side default-network hook. Reuse
	// the same peer/CIDR/reply decisions as that hook and pin only AFTER admit.
	if (!srcnet && sp && ifindex != cfg(CFG_UPLINK_IFINDEX) &&
	    (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP)) {
		__u32 zero = 0;
		struct np_scratch_val *s = bpf_map_lookup_elem(&np_scratch, &zero);
		if (!s)
			return TC_ACT_SHOT;
		s->q.src = p->src;
		s->q.dst = p->dst;
		s->q.proto = p->proto;
		s->q.pad[1] = p->is_v6 ? 6 : 4;
		__u32 l4off = p->is_v6 ? ETH_HLEN + 40 : ETH_HLEN + 20;
		if (bpf_skb_load_bytes(skb, l4off, &s->q.sport, 2) < 0 ||
		    bpf_skb_load_bytes(skb, l4off + 2, &s->q.dport, 2) < 0)
			return TC_ACT_SHOT;
		int gate = 1;
		if (p->proto == IPPROTO_TCP) {
			s->q.pad[0] = 0;
			if (bpf_skb_load_bytes(skb, l4off + 13, &s->q.pad[0], 1) < 0)
				return TC_ACT_SHOT;
			gate = (s->q.pad[0] & 0x02) && !(s->q.pad[0] & 0x10);
		}
		asm volatile("" ::: "memory");
		// Node-destined plumbing remains under HostFirewall, as before.
		if (gate && !bpf_map_lookup_elem(&np_nodes, &p->dst) && !np_egress_impl(s)) {
			s->cd.prefixlen = NP_DIR_EG;
			asm volatile("" ::: "memory");
			__u64 *d = bpf_map_lookup_elem(&np_drops, &s->cd.prefixlen);
			if (d)
				(*d)++;
			return TC_ACT_SHOT;
		}
		if (p->proto == IPPROTO_UDP) {
			s->ck.pod = p->src;
			s->ck.peer = p->dst;
			s->ck.pport = s->q.sport;
			s->ck.rport = s->q.dport;
			s->ck.proto = IPPROTO_UDP;
			s->ck.pad[0] = 0;
			s->ck.pad[1] = 0;
			s->ck.pad[2] = 0;
			__u8 one = 1;
			asm volatile("" ::: "memory");
			bpf_map_update_elem(&np_ct, &s->ck, &one, BPF_ANY);
		}
	}

	// The north-south bridge and floating IPs are v4-only today (v6 fabric IPs
	// and an NDP responder are later phases), so a v6 packet skips straight to
	// the family-agnostic overlay delivery below.
	if (!p->is_v6) {
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
			return svc_hairpin_reverse(skb, p, srcnet);
		// Off-net traffic from a floating pod egresses from its public IP (both
		// its replies and the connections it originates): SNAT VPC->public and
		// redirect out the uplink, dropping cluster-internal destinations.
		// Checked before isolation, which would otherwise send it to the gateway
		// or drop it. On a hit floating_egress_snat returns the action; on a miss
		// the packet is untouched, so p->src/p->dst (stack copies) stay valid.
		if (srcnet && !dstnet) {
			int fr = floating_egress_snat(skb, ip, srcnet);
			if (fr != FLOAT_MISS)
				return fr;
		}
	}
	// The v6 twin: a floating v6 pod's internet-bound traffic egresses from
	// its public address. Link-scoped v6 (NDP) was already bypassed above.
	if (p->is_v6 && srcnet && !dstnet) {
		int fr = floating_egress_snat6(skb, p, srcnet);
		if (fr != FLOAT_MISS)
			return fr;
	}

	// The per-VPC route table (issue #6, docs/vpn.md §3.1): a routed remote
	// prefix is delivered to its appliance leg, checked BEFORE the NAT gateway
	// below so the SNAT does not steal routed traffic toward the internet. It is
	// off-VPC egress, so it is gated by the source's egress SecurityGroups and
	// metered on the appliance door exactly as the gateway path is; then it is
	// delivered to the next-hop Port by identity (deliver_local / encap), the
	// same delivery as gateways[vni]. A miss falls through to NAT/gateway.
	if (srcnet && !dstnet && !is_gw) {
		struct route_entry *route = route_of(srcnet, p->dst);
		struct gw_entry *rt = route_next_hop(route, p);
		if (rt) {
			if (!ns_egress_ok(skb, srcnet, p->is_v6, p->proto, p->src, p->dst)) {
				return TC_ACT_SHOT;
			}
			count_ns(srcnet, skb->len, NS_APPLIANCE, 0);
			if (!rt->node_ip) {
				struct endpoint *rl = local_of(srcnet, rt->gw_ip);
				if (rl)
					return deliver_local(skb, rl);
				// next-hop leg not here yet: fall through to NAT/gateway.
			} else {
				return encap(skb, srcnet, rt->node_ip, 0);
			}
		}
	}

	// The VPC's own NAT gateway (docs/north-south.md): off-VPC egress for a pod
	// with no floating address of its own, SNATed to the VPC's identity and sent
	// straight out the uplink — no gateway pod, no hairpin. Checked after the EIP
	// path (a pod holding a public address egresses as that, 1:1) and before the
	// isolation block, which would otherwise steer it to the gateway pod.
	if (!p->is_v6 && srcnet && !dstnet && !is_gw) {
		int nr = vpc_nat_snat(skb, p, srcnet);
		if (nr != NAT_MISS)
			return nr;
	}
	// The v6 twin (docs/north-south.md §6a): a VPC with a v6 identity wears its own
	// v6 address on the way out, instead of laundering through the gateway pod.
	if (p->is_v6 && srcnet && !dstnet && !is_gw) {
		int nr = vpc_nat_snat6(skb, p, srcnet);
		if (nr != NAT_MISS)
			return nr;
	}

	// Isolation: same-network or explicitly peered traffic only (egress side) —
	// except a VPC pod's off-net traffic, which goes to the VPC's egress
	// gateway when one exists. Fabric->VPC and unpeered cross-VPC still drop->
	if (!nets_allowed(srcnet, dstnet)) {
		if (!srcnet || dstnet) {
			flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, dstnet), 0,
				       FE_META(FE_V_DENY, FR_ISOLATION, FE_FROM_POD, FE_NO_DOOR, 0, p->proto), 0);
			return TC_ACT_SHOT;
		}
		// North-south egress (v2): a grouped pod's off-VPC egress to the gateway
		// is default-deny, opened by a to:{cidr} rule. DNS already returned via
		// dns_steer; a grouped pod's replies pass (SYN-gated inside). No
		// sg_drops bump here — from_pod is too stack-heavy to host the
		// count_sg_drop BPF-to-BPF call (the reason metering lives in to_pod).
		if (!ns_egress_ok(skb, srcnet, p->is_v6, p->proto, p->src, p->dst)) {
			flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, 0), 0,
				       FE_META(FE_V_DENY, FR_SG_EGRESS, FE_FROM_POD, NS_GW, 0, p->proto), 0);
			return TC_ACT_SHOT;
		}
		struct gw_entry *g = bpf_map_lookup_elem(&gateways, &srcnet);
		if (!g) {
			// closed island: no gateway for this VPC
			flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, 0), 0,
				       FE_META(FE_V_DENY, FR_NO_GATEWAY, FE_FROM_POD, NS_GW, 0, p->proto), 0);
			return TC_ACT_SHOT;
		}
		// The gateway door, outbound: this is the VPC's traffic leaving through
		// its own gateway, and the one crossing that is *declared* rather than
		// incidental. Counted here, at the branch, rather than at the gateway pod
		// — where it would already wear the platform's identity, not the tenant's
		// (docs/north-south.md §1).
		count_ns(srcnet, skb->len, NS_GW, 0);
		// One allow event per flow leaving through the gateway door. Inline —
		// from_pod hosts no callee (the 544 lesson); stack-free via scratch.
		flow_allow_core(skb, &p->src, &p->dst, FE_NETS(srcnet, 0),
				FE_META(FE_V_ALLOW, FR_ALLOW, FE_FROM_POD, NS_GW, 0, p->proto) |
				FE_L4OFF(p->is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20)));
		if (!g->node_ip) {
			struct endpoint *gl = local_of(srcnet, g->gw_ip);
			if (!gl) {
				flow_emit_core(&p->src, &p->dst, FE_NETS(srcnet, 0), 0,
					       FE_META(FE_V_DENY, FR_NO_GATEWAY, FE_FROM_POD, NS_GW, 0, p->proto), 0);
				return TC_ACT_SHOT;
			}
			return deliver_local(skb, gl);
		}
		// Remote gateway: encapsulate toward its node under the VPC's VNI;
		// from_overlay there hands the packet to the gateway's veth.
		return encap(skb, srcnet, g->node_ip, 0);
	}

	// The gateway door, inbound: the gateway pod handing traffic back to a tenant
	// in its own VPC — the return half of everything counted above (and the DNS
	// the gateway proxies). It is east-west by address, but it is the boundary by
	// meaning: every byte here came from, or is going to, outside the VPC.
	if (is_gw && srcnet && dstnet == srcnet)
		count_ns(srcnet, skb->len, NS_GW, 1);

	// ServiceVIP DNAT. VPC ServiceVIPs (net != 0) for VPC pods; and — once
	// kube-proxy is gone (KPR increment 3) — default-network (net 0) ClusterIPs
	// too, fed by cozyplane-kpr. The rewrite updates p->dst, so delivery below
	// carries on toward the backend; a miss leaves the packet untouched. Only
	// clients whose connect() socket-LB never rewrote (a bridge-bound VM guest,
	// a raw socket) still carry a VIP destination here — a socket-LB'd pod
	// already carries dst = backend, so the svc_vips lookup misses. Gateways
	// never DNAT (is_gw); skipped at the uplink-egress attachment (ifindex ==
	// uplink) — host ClusterIP is socket-LB'd, and the outgoing Geneve/egress
	// path should not pay a per-packet lookup->
	if (!is_gw && ifindex != cfg(CFG_UPLINK_IFINDEX))
		svc_forward(skb, p, srcnet, dstnet);

	// Same-node destination: redirect through the pod's veth egress (-> to_pod)
	// — VPC nets only. Default-network (net 0) traffic is delivered by the
	// kernel, as the model requires: a direct redirect would bypass netfilter,
	// and with it kube-proxy's conntrack — a ClusterIP reply from a same-node
	// backend then reaches the client still carrying the backend's source,
	// never un-DNAT'd, and the client's socket discards it. (Latent since M0;
	// surfaced whenever the scheduler co-located a client with its coredns.)
	if (dstnet) {
		struct endpoint *l = local_of(dstnet, p->dst);
		if (l) {
			// A gateway forwarding into its VPC may carry an off-VPC source
			// (the internet's reply); mark it so the destination's anti-spoof
			// admits it.
			if (is_gw)
				skb->mark = GW_MARK;
			else if (foreign_src)
				// A tenant router's transit traffic. FWD_MARK, not GW_MARK:
				// it must clear the isolation check and still face the
				// destination's SecurityGroups.
				skb->mark |= FWD_MARK;
			// A gateway/forwarder returning an off-VPC SYN to a local VPC
			// pod crosses the same north-south/VPN boundary without Geneve.
			if (is_gw || foreign_src)
				tcp_mss_clamp_packet(skb);
			// Preserve the scoped destination through to_pod. An equal global
			// alias must not reinterpret this flow as exempt host plumbing.
			skb->mark |= VPC_MARK;
			return deliver_local(skb, l);
		}
	}

	// Remote destination in the same network (or a peer): encapsulate. Stamp
	// the source pod's authoritative group identity (stage B) so the receiver
	// trusts it across a peering. srcnet/p->src are the source node's own view
	// (from the veth's `ports` entry), not the (spoofable) claimed source.
	__u32 *node_ip = remote_of(dstnet, p->dst);
	if (node_ip) {
		__u64 srcmap = 0;
		if (srcnet && !is_gw) {
			struct local_key sk = { .net = srcnet, .ip = p->src };
			srcmap = sg_membership(&sk);
		}
		// Node-originated to a REMOTE POD (a hostNetwork pod resolving
		// cluster DNS via socket-LB is exactly this): the one node-origin
		// path that never reaches a host-stack fall-through, because this
		// encap consumes it. Hand it to the host firewall's egress program
		// (docs/host-firewall.md) — a tail call costs from_pod no stack (the
		// 544 lesson) and it performs the encap itself on admit. An
		// unpopulated slot falls through to the inline encap below.
		if (!srcnet && HF_ARMED() &&
		    (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) &&
		    bpf_map_lookup_elem(&hf_self, &p->src) &&
		    !bpf_map_lookup_elem(&np_nodes, &p->dst))
			bpf_tail_call(skb, &lb_prog, 3);
		__u32 tunflags = 0;
		if (is_gw)
			tunflags = TUN_F_GATEWAY;
		else if (foreign_src)
			tunflags = TUN_F_FORWARD;
		return encap_sg(skb, dstnet, *node_ip, tunflags, srcnet, srcmap);
	}

	// A default-network pod addressing a *node* (its reply to a hostNetwork
	// client, or a dial to a node service): encapsulate it to that node over the
	// overlay so the underlay only ever carries node source IPs. The kernel path
	// below would emit it with the pod's source, which a spoof-guarding fabric
	// (OCI) drops — black-holing every cross-node node<->pod flow. Gated to the
	// pod-veth attachment: at the uplink egress this hook also sees the Geneve
	// *outer* (node->node) frames, and encapsulating those would loop forever.
	// Default network only (srcnet==0): a VPC pod reaching the host is isolated.
	if (!srcnet && ifindex != cfg(CFG_UPLINK_IFINDEX)) {
		__u32 *nnode = node_remote_of(p->dst);
		if (nnode)
			return encap(skb, 0, *nnode, 0);
	}

	// Same-node north-south: a default-network packet to a local VPC pod's
	// fabric IP. Redirect into the pod's veth (to_pod does the DNAT), bypassing
	// the kernel FORWARD chain so no netfilter accept rule is needed. Fabric IPs
	// are v4-only, so a v6 packet always misses here and falls to the kernel.
	struct bridge_ep *be = bridge_of(p->dst);
	if (be) {
		struct endpoint *l = local_of(be->net, be->vpc_ip);
		if (l) {
			skb->mark |= NS_MARK; // pod-originated north-south -> subject to SG
			return deliver_local(skb, l);
		}
	}

	// Off-cluster / node: the kernel handles it — after the host firewall
	// (docs/host-firewall.md). Same-node pod→node ends here; at the uplink
	// egress the same tail call carries node-originated traffic, whose UDP
	// pins its reply inside hf_ingress. A tail call costs from_pod no stack.
	if (HF_ARMED())
		bpf_tail_call(skb, &lb_prog, 2);
	return TC_ACT_OK;
}

// At the uplink-egress attachment Cozyplane runs before Cilium's to-netdev,
// which owns the NodePort/LB reverse NAT of replies leaving the node. A plain
// "let it out" there must continue the tcx chain (TC_ACT_NEXT), not end it;
// on pod veths the verdict is unchanged (Cilium runs first on net 0, and
// Cozyplane's VPC verdicts stay terminal).
SEC("tc")
int cozyplane_from_pod_continue(struct __sk_buff *skb)
{
	int verdict = from_pod(skb);
	if (verdict == TC_ACT_OK && skb->ifindex == cfg(CFG_UPLINK_IFINDEX))
		return TC_ACT_NEXT;
	return verdict;
}

// cozyplane_to_pod: destination-side hook (pod ingress). Every delivery path
// leaves via the destination veth, so this runs for same-node, cross-node, and
// node->pod traffic alike — the placement-independent point for ingress policy.
SEC("tc")
int cozyplane_to_pod(struct __sk_buff *skb)
{
	pull_headers(skb);
	__u32 zero = 0, net = 0;
	__u32 ifindex = skb->ifindex;
	__u32 *port = bpf_map_lookup_elem(&ports, &ifindex);
	if (port && *port == PORT_QUARANTINE) return TC_ACT_SHOT;
	if (unsupported_ip_header(skb)) return TC_ACT_SHOT;
	if (port) net = PORT_NET(*port);
	struct boundary_scratch *s = bpf_map_lookup_elem(&boundary_scratch, &zero);
	if (!s) return TC_ACT_SHOT;
	__builtin_memset(s, 0, sizeof(*s));
	if (net && parse_ip(skb, &s->packet) == 0) {
		s->key.local = net; s->key.peer = net_of(&networks, net, s->packet.src);
		s->key.src = s->packet.src; s->key.dst = s->packet.dst; s->key.hook = 1;
		if (bpf_map_lookup_elem(&boundary_policy, &net) &&
		    (skb->mark & FWD_MARK)) return TC_ACT_SHOT;
		if (!boundary_gate(skb, s)) return TC_ACT_SHOT;
	}
	bpf_tail_call(skb, &lb_prog, 5);
	return TC_ACT_SHOT;
}

SEC("tc")
int cozyplane_to_pod_continue(struct __sk_buff *skb)
{
	__u32 ifindex = skb->ifindex;
	__u32 *dp = bpf_map_lookup_elem(&ports, &ifindex);
	if (dp && *dp == PORT_QUARANTINE)
		return TC_ACT_SHOT;
	if (unsupported_ip_header(skb))
		return TC_ACT_SHOT;
	__u32 dstnet = dp ? PORT_NET(*dp) : 0;
	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;

	// Check the receiving veth before any sanctioned early return. A stale
	// bridge/route must not lend the active endpoint's policy to a retired link.
	if (!receiving_owner(skb, dstnet, &p.dst))
		return TC_ACT_SHOT;
	__u32 native_vpc = skb->mark & VPC_MARK;
	// Consume the routing proof before any early return into the pod. The
	// existing GW/SG/FWD marks retain their separate policy meanings.
	skb->mark &= ~VPC_MARK;

	// The split-horizon resolver's DNS reply re-enters the pod here; un-NAT it
	// before the bridge below would masquerade it to the gateway address.
	if (!native_vpc) {
		int dr = dns_return(skb, &p);
		if (dr != DNS_MISS)
			return dr;
	}

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
		struct bridge_ep *be = native_vpc ? NULL : bridge_of(p.dst);
		if (be)
			return bridge_forward(skb, ip, be->net, be->vpc_ip);

		// A floating IP: DNAT public->VPC, preserving the external client's
		// source. Also sanctioned north-south (no isolation check follows).
		struct bridge_ep *fe = native_vpc ? NULL : float_of(p.dst);
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
	if (p.is_v6 && !native_vpc) {
		// A v6 floating IP: stateless DNAT public->VPC, client preserved.
		struct bridge_ep *fe6 = float_of(p.dst);
		if (fe6)
			return floating_forward6(skb, &p, fe6->net, fe6->vpc_ip);
		struct bridge_ep *be = bridge_of(p.dst);
		if (be)
			return bridge_forward6(skb, &p, be->net, be->vpc_ip);
	}

	// Link-local is not authenticated application identity. Only on-link
	// neighbour/router discovery and DHCPv6 replies bypass tenant isolation.
	// A multicast source is never valid, including for those protocols.
	if (p.is_v6 && v6_link_scoped(&p.src)) {
		if (p.src.b[0] == 0xff)
			return TC_ACT_SHOT;
		if (p.proto == IPPROTO_ICMPV6) {
			__u8 type = 0, code = 1, hops = 0;
			bpf_skb_load_bytes(skb, ETH_HLEN + 40, &type, 1);
			bpf_skb_load_bytes(skb, ETH_HLEN + 41, &code, 1);
			bpf_skb_load_bytes(skb, ETH_HLEN + 7, &hops, 1);
			if (hops == 255 && !code && (type == 134 || type == 135 || type == 136))
				return TC_ACT_OK;
		}
		if (p.proto == IPPROTO_UDP) {
			__u16 sport = 0, dport = 0;
			bpf_skb_load_bytes(skb, ETH_HLEN + 40, &sport, 2);
			bpf_skb_load_bytes(skb, ETH_HLEN + 42, &dport, 2);
			if (sport == bpf_htons(547) && dport == bpf_htons(546))
				return TC_ACT_OK;
		}
		return TC_ACT_SHOT;
	}

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
	// Read the mark ONCE, into a local. Every test below used skb->mark
	// directly until clang folded one of them into a variable ctx offset
	// (`r2 = ctx; r2 += r3; r2 = *(u32 *)(r2)`) and the verifier refused the
	// program outright: "dereference of modified ctx ptr R2 off=8 disallowed".
	// A ctx field must be loaded at a CONSTANT offset; one hoisted read leaves
	// clang no room to decide otherwise, and is cheaper besides. Policy paths
	// below only read it; the delivery tail consumes Cozyplane's private bits
	// before the packet enters the pod.
	__u32 mark = skb->mark;

	if (!nets_allowed(srcnet, dstnet)) {
		// A second exception: an LB/NodePort flow into a VPC-pod backend
		// (docs/lb-ingress.md) — external source, tenant destination, pinned
		// by from_uplink's lb_ingress in svc_rev (net-0-keyed; this node by
		// construction). SecurityGroups were enforced at the DNAT point, so a
		// hit is fully sanctioned, like the bridge/floating paths (return
		// delivered — the SG block below gates east-west, not this). Only
		// isolation-failing packets pay the lookup.
		if (srcnet == 0 && dstnet != 0 &&
		    (p.proto == IPPROTO_TCP || p.proto == IPPROTO_UDP)) {
			__u16 sp2, dp2;
			if ((p.is_v6 ? l4_ports6(skb, &sp2, &dp2)
				     : l4_ports(skb, &sp2, &dp2)) == 0) {
				struct svc_rev_key lrk = { .net = 0, .proto = p.proto,
							   .cport = sp2, .backend = p.dst,
							   .client = p.src, .tport = dp2 };
				struct svc_rev_val *lrv = bpf_map_lookup_elem(&svc_rev, &lrk);
				if (lrv && lrv->lb)
					return TC_ACT_OK;
			}
		}
		// A tenant router's transit traffic (docs/multi-attach.md): the source
		// belongs to another VPC, so srcnet is 0 here and isolation would drop
		// it. FWD_MARK, set only for a GRANTED forwarding leg carrying a source
		// it does not own, admits it past this check — and past nothing else.
		// The policy gate below still runs, which is the entire difference
		// between this bit and GW_MARK.
		if (!(mark & FWD_MARK) &&
		    !(srcnet == 0 && dstnet != 0 && mark == GW_MARK)) {
			flow_emit(&p.src, &p.dst, FE_NETS(srcnet, dstnet), 0,
				  FE_META(FE_V_DENY, FR_ISOLATION, FE_TO_POD, FE_NO_DOOR, 0, p.proto));
			return TC_ACT_SHOT;
		}
	}

	// SecurityGroups for a forwarded packet. This VPC holds no identity for an
	// address it does not own, so the east-west group test below cannot judge
	// it: srcnet is 0, the source bitmap is empty, and a grouped destination
	// would deny everything with no rule able to allow it. Judge it as what it
	// is from this VPC's point of view — a north-south source — through the
	// same helper the fabric bridge and floating IPs use. A tenant writes
	// `from: {cidr: 10.10.0.0/24}` and means exactly this.
	//
	// An UNGROUPED destination still passes (ns_sg_admit short-circuits on an
	// empty member bitmap), so forwarding works out of the box and tightens the
	// moment the destination joins a group.
	if (dstnet && (mark & FWD_MARK)) {
		__u16 fdport;
		__u32 fl4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
		if (sg_l4(skb, p.proto, fl4off, &fdport) &&
		    !ns_sg_admit(dstnet, &p.dst, &p.src, cidr_proto(p.proto, p.is_v6), fdport)) {
			count_sg_drop(dstnet);
			flow_emit(&p.src, &p.dst, FE_NETS(0, dstnet), FE_PORTS(0, fdport),
				  FE_META(FE_V_DENY, FR_SG_NS, FE_TO_POD, FE_NO_DOOR, FE_F_FWD, p.proto));
			return TC_ACT_SHOT;
		}
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
	//
	// A VPC pod acting as its net's gateway transits off-VPC egress: the packet
	// arrives on the gateway's veth (dstnet is the gateway's net) but its
	// destination is *not* a VPC address (the internet/cluster). That is
	// north-south egress, gated at the true source's from_pod by ns_egress_ok —
	// it must not be re-gated as east-west here, or sg_egress_admit would drop
	// every grouped source (the off-VPC dst is ungrouped) and break all TCP/UDP
	// north-south egress. A normal east-west delivery always has an in-VPC dst.
	int ns_transit = net_of(&networks, dstnet, p.dst) == 0;
	int managed_cross = srcnet && srcnet != dstnet &&
		bpf_map_lookup_elem(&boundary_policy,&srcnet) && bpf_map_lookup_elem(&boundary_policy,&dstnet);
	if (dstnet && !ns_transit && !managed_cross && !(mark & (GW_MARK | SG_OK | FWD_MARK))) {
		__u16 dport;
		__u32 l4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
		if (sg_l4(skb, p.proto, l4off, &dport)) {
			// The source's groups live under the source's OWN net (srcnet ==
			// dstnet intra-VPC; the peer's VNI across a peering), and peer-group
			// rules are keyed by that src_net — so a peered group matches.
			struct local_key sk = { .net = srcnet, .ip = p.src };
			__u64 srcmap = sg_membership(&sk);
			// Ingress: the destination's groups must admit the source.
			struct sg_query q = {
				.dst = { .net = dstnet, .ip = p.dst },
				.src_net = srcnet,
				.srcmap = srcmap,
				.dport = dport,
				.proto = p.proto,
			};
			// Reuse the query's destination key instead of another stack copy.
			__u64 dstmap = sg_membership(&q.dst);
			// Egress: the source's groups must admit the destination (v2). A flow
			// is delivered only if both directions allow.
			struct sg_egress_query eq = {
				.src_net = srcnet,
				.dst_net = dstnet,
				.srcmap = srcmap,
				.dstmap = dstmap,
				.dport = dport,
				.proto = p.proto,
			};
			if (!sg_admit(&q) || !sg_egress_admit(&eq)) {
				count_sg_drop(dstnet);
				flow_emit(&p.src, &p.dst, FE_NETS(srcnet, dstnet), FE_PORTS(0, dport),
					  FE_META(FE_V_DENY, FR_SG_INGRESS, FE_TO_POD, FE_NO_DOOR, 0, p.proto));
				return TC_ACT_SHOT;
			}
		}
	}

	// NetworkPolicy ingress at net 0 (docs/network-policy.md): the same
	// destination-side gate SecurityGroups use, on the default network's own
	// maps. Everything delivered into a net-0 pod passes here — same-node
	// redirects, decapsulated cross-node traffic (kernel-routed onto the
	// veth), LB/NodePort deliveries post-DNAT with the client source
	// preserved. Sanctioned replies returned earlier (svc_return). TCP is
	// SYN-gated; an admitted UDP flow's reply enters via the np_ct pin its
	// egress wrote; node-origin plumbing is exempt inside np_ingress.
	if (!dstnet) {
		__u16 dport;
		__u32 l4off = p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20);
		if (sg_l4(skb, p.proto, l4off, &dport)) {
			__u32 zero = 0;
			struct np_scratch_val *s = bpf_map_lookup_elem(&np_scratch, &zero);
			if (!s)
				return TC_ACT_SHOT; // unreachable (ARRAY); fail closed
			s->q.src = p.src;
			s->q.dst = p.dst;
			s->q.proto = p.proto;
			s->q.pad[1] = p.is_v6 ? 6 : 4;
			s->q.dport = dport;
			s->q.sport = 0;
			if (p.proto == IPPROTO_UDP)
				bpf_skb_load_bytes(skb, l4off, &s->q.sport, 2);
			asm volatile("" ::: "memory");
			if (!np_ingress(s)) {
				count_np_drop(NP_DIR_IN);
				flow_emit(&p.src, &p.dst, FE_NETS(srcnet, 0), FE_PORTS(0, dport),
					  FE_META(FE_V_DENY, FR_NP_INGRESS, FE_TO_POD, FE_NO_DOOR, 0, p.proto));
				return TC_ACT_SHOT;
			}
			if (!np_egress(s)) {
				count_np_drop(NP_DIR_EG);
				flow_emit(&p.src, &p.dst, FE_NETS(srcnet, 0), FE_PORTS(0, dport),
					  FE_META(FE_V_DENY, FR_NP_EGRESS, FE_TO_POD, FE_NO_DOOR, 0, p.proto));
				return TC_ACT_SHOT;
			}
			// Node-originated UDP into a local pod: its only datapath
			// crossing is this delivery, so the host firewall's reply-pin
			// is written here (self-sourced only, inside the callee).
			if (p.proto == IPPROTO_UDP && HF_ARMED())
				hf_pin_local(s);
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

	// One allow event per admitted tenant flow (docs/observability.md).
	// Net-0-to-net-0 is the platform's own traffic, not a tenant flow — the
	// same rule the meters apply.
	if (srcnet || dstnet)
		flow_allow(skb, &p.src, &p.dst, FE_NETS(srcnet, dstnet),
			   FE_META(FE_V_ALLOW, FR_ALLOW, FE_TO_POD, FE_NO_DOOR, 0, p.proto) |
			   FE_L4OFF(p.is_v6 ? (ETH_HLEN + 40) : (ETH_HLEN + 20)));

	// The mark is in-kernel proof used only while Cozyplane judges this packet.
	// Do not leak private bits into the pod; preserve unrelated platform marks.
	skb->mark = mark & ~(GW_MARK | SG_OK | NS_MARK | FWD_MARK);
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
	pull_headers(skb);
	// Decapsulation establishes a new trust boundary; only validated tunnel
	// metadata and scoped lookup below may assign private delivery proofs.
	skb->mark &= ~(GW_MARK | SG_OK | NS_MARK | FWD_MARK | VPC_MARK);
	if (unsupported_ip_header(skb))
		return TC_ACT_SHOT;
	struct bpf_tunnel_key tk;
	if (bpf_skb_get_tunnel_key(skb, &tk, sizeof(tk), 0) < 0)
		return TC_ACT_SHOT;
	if (!bpf_map_lookup_elem(&overlay_nodes, &tk.remote_ipv4))
		return TC_ACT_SHOT;

	struct pkt p;
	if (parse_ip(skb, &p) < 0)
		return TC_ACT_OK;

	__u32 gw = tk.tunnel_id & TUN_F_GATEWAY;
	__u32 fwd = tk.tunnel_id & TUN_F_FORWARD;
	__u32 vni = (__u32)tk.tunnel_id & ~(TUN_F_GATEWAY | TUN_F_FORWARD);
	if (vni == cfg(CFG_VNI)) {
		// etp: Cluster DSR (docs/lb-ingress.md): the ingress node DNAT'd an
		// LB/NodePort flow to a backend on THIS node and stamped the frontend
		// identity. Checked before the bridge below — a bridged fabric dst
		// with the option must take the DSR pin, not the masquerading bridge.
		// One get_tunnel_opt on net-0 decaps only; east-west VPC traffic
		// never pays it.
		struct lb_geneve_opt lopt;
		if (bpf_skb_get_tunnel_opt(skb, (void *)&lopt, sizeof(lopt)) >= (int)sizeof(lopt) &&
		    lopt.opt_class == bpf_htons(SG_OPT_CLASS) && lopt.type == LB_OPT_TYPE) {
			bpf_tail_call(skb, &lb_prog, 1);
			return TC_ACT_SHOT; // slot unpopulated: no correct delivery exists
		}
		// Default network. A cross-node north-south packet to a local VPC pod's
		// fabric IP (either family; the bridges map is 128-bit) is delivered to
		// its veth here (to_pod does the DNAT), bypassing the kernel FORWARD
		// chain; everything else — including the north-south *reply* toward a
		// default-network pod — is handed to the kernel, which is why
		// EnsureForwardRules must ACCEPT overlay traffic in both families.
		struct bridge_ep *be = bridge_of(p.dst);
		if (be) {
			struct endpoint *l = local_of(be->net, be->vpc_ip);
			if (l) {
				skb->mark |= NS_MARK; // pod-originated north-south -> subject to SG
				return deliver_local(skb, l);
			}
		}
		// Handed to the kernel. Cross-node pod→node (the node_remotes
		// encap) exits here — if it is addressed to this node itself, the
		// host firewall gets it first (docs/host-firewall.md).
		if (HF_ARMED())
			bpf_tail_call(skb, &lb_prog, 2);
		return TC_ACT_OK;
	}

	// A local pod in this VPC (intra-VPC, peered, or a gateway->tenant reply).
	// The lookup is 128-bit, so a v6 VPC pod is delivered exactly like a v4 one.
	struct endpoint *ep = local_of(vni, p.dst);
	if (ep) {
		if (gw) {
			skb->mark = GW_MARK;
		} else if (fwd) {
			// A tenant router's transit traffic, from another node. It carries
			// no identity option (its source is not a member here), so there is
			// nothing to enforce authoritatively; to_pod judges it below.
			skb->mark |= FWD_MARK;
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
				int managed = opt.src_net != vni && bpf_map_lookup_elem(&boundary_policy,&vni) &&
					bpf_map_lookup_elem(&boundary_policy,&opt.src_net);
				if (!managed && sg_l4(skb, p.proto, l4off, &dport)) {
					struct local_key dk = { .net = vni, .ip = p.dst };
					__u64 dstmap = sg_membership(&dk);
					// Ingress: dst's groups admit the (TLV-authoritative) source.
					struct sg_query q = {
						.dst = { .net = vni, .ip = p.dst },
						.src_net = opt.src_net,
						.srcmap = opt.srcmap,
						.dport = dport,
						.proto = p.proto,
					};
					// Egress: the source's groups admit the destination (v2).
					struct sg_egress_query eq = {
						.src_net = opt.src_net,
						.dst_net = vni,
						.srcmap = opt.srcmap,
						.dstmap = dstmap,
						.dport = dport,
						.proto = p.proto,
					};
					if (!sg_admit(&q) || !sg_egress_admit(&eq)) {
						count_sg_drop(vni);
						flow_emit(&p.src, &p.dst, FE_NETS(opt.src_net, vni),
							  FE_PORTS(0, dport),
							  FE_META(FE_V_DENY, FR_SG_INGRESS, FE_FROM_OVERLAY, FE_NO_DOOR, 0, p.proto));
						return TC_ACT_SHOT;
					}
				}
				skb->mark |= SG_OK;
			}
		}
		skb->mark |= VPC_MARK;
		return deliver_local(skb, ep);
	}

	// A VPC NAT reply, forwarded here by the node that attracted the address
	// because THIS node's ct_rev holds the flow (docs/north-south.md). Same
	// un-NAT, same delivery; the shard demux already decided it is ours.
	if (!p.is_v6) {
		int nr = vpc_nat_reverse(skb, &p);
		if (nr != NAT_MISS)
			return nr;
	} else {
		int nr = vpc_nat_reverse6(skb, &p);
		if (nr != NAT_MISS)
			return nr;
	}

	// Inbound to a floating IP, forwarded here by the node that announced it
	// (docs/floating-ha.md): the destination is still the PUBLIC address, so
	// local_of missed above — `locals` is keyed by VPC IP. Resolve it through
	// `floating` and hand it to the pod's veth, where to_pod's floating_forward
	// DNATs public->VPC and applies the north-south SG gate, exactly as it does
	// for a packet that arrived on this node's own uplink.
	//
	// This MUST come before the gateway lookup below: a public destination is
	// not a local pod, so it would otherwise fall into `gateways` and be
	// delivered into this VPC's gateway pod — a mis-delivery, not a drop. It
	// must equally come AFTER the SG-TLV block above: a floating packet carries
	// no identity option (its source is an external client, not a group member)
	// and must not be judged as east-west traffic.
	struct bridge_ep *fe = float_of(p.dst);
	if (fe && fe->net == vni) {
		struct endpoint *fep = local_of(fe->net, fe->vpc_ip);
		if (fep)
			return deliver_local(skb, fep);
	}

	// A per-VPC route table next-hop hosted here (issue #6): the source node
	// encap'd routed traffic (its destination a remote prefix, not a local pod)
	// toward this node under the VPC's VNI. Deliver it to the appliance leg the
	// route names. An explicit prefix must win over a default gateway here too.
	// Native VPC/peer destinations retain migration delivery below, even if
	// an explicit prefix covers them. The source hook only routes off-VPC.
	if (!net_of(&networks, vni, p.dst)) {
		if (!gw && routes_blocked(vni))
			return TC_ACT_SHOT;
		struct route_entry *route = route_of(vni, p.dst);
		struct gw_entry *rt = route_next_hop(route, &p);
		if (route) {
			if (!rt || rt->node_ip)
				return TC_ACT_SHOT;
			struct endpoint *rep = local_of(vni, rt->gw_ip);
			if (rep)
				return deliver_local(skb, rep);
			return TC_ACT_SHOT;
		}

		// Only an actual off-VPC route miss may use the default appliance.
		struct gw_entry *g = bpf_map_lookup_elem(&gateways, &vni);
		if (g && !g->node_ip) {
			struct endpoint *gep = local_of(vni, g->gw_ip);
			if (gep)
				return deliver_local(skb, gep);
		}
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

// cozyplane_from_uplink: attached at the node uplink's ingress. It is the only
// entry point for off-cluster ingress, and it DELIVERS — it does not attract.
//
// Cozyplane no longer announces anything (docs/north-south.md, tenet 3): making
// the fabric hand an external address to some node is the platform's job — a CCM
// assigning it to a VNIC, MetalLB, a static route, an address configured on a
// node. What used to be here (an ARP/NDP responder and a gratuitous-ARP emitter,
// elected per address) was MetalLB's L2 mode reimplemented inside a CNI.
//
// Because this hook sits at tc ingress — BEFORE the kernel's routing decision —
// delivery works however the address was attracted, and to whichever node. A
// packet for a floating IP is redirected into the target pod's veth when the pod
// is local and encapsulated to the pod's node when it is not; a reply to a VPC's
// NAT address is un-NAT'd here or forwarded to the node holding the flow. to_pod
// does the public->VPC DNAT (source-preserving) at the far end either way.
// Everything else — overlay traffic, node traffic — is left to the kernel
// untouched, at the cost of one hash lookup.
SEC("tc")
int cozyplane_from_uplink(struct __sk_buff *skb)
{
	pull_headers(skb);
	if (unsupported_ip_header(skb))
		return TC_ACT_SHOT;
	struct iphdr *ip;
	if (parse_ipv4(skb, &ip) < 0) {
		// v6 inbound to a floating address: deliver to the local pod like the
		// v4 path below (to_pod on its veth does the public->VPC DNAT).
		struct pkt p6;
		if (parse_ip(skb, &p6) == 0 && p6.is_v6) {
			int m6 = masq_reverse6(skb, &p6);
			if (m6 != MASQ_MISS)
				return m6;
			// A reply to a VPC's v6 NAT address: un-NAT if the flow is ours, or
			// forward to the node whose ct_rev holds it (docs/north-south.md §6a).
			int nr6 = vpc_nat_reverse6(skb, &p6);
			if (nr6 != NAT_MISS)
				return nr6;
			struct bridge_ep *fe6 = float_of(p6.dst);
			if (fe6) {
				struct endpoint *l6 = local_of(fe6->net, fe6->vpc_ip);
				if (l6)
					return deliver_local(skb, l6);
				// Host is elsewhere: forward over the overlay (v4 arm above).
				__u32 *n6 = remote_of(fe6->net, fe6->vpc_ip);
				if (n6)
					return encap(skb, fe6->net, *n6, 0);
			}
		}
		// v6 exits here without the v4 path's LB tail call below — but
		// host-destined v6 (external clients; pod→node v6 rides the
		// overlay now that node_remotes is dual-family) still owes the
		// host firewall a look (docs/host-firewall.md).
		if (HF_ARMED())
			bpf_tail_call(skb, &lb_prog, 2);
		return TC_ACT_NEXT;
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

	// A reply to a VPC's NAT address (docs/north-south.md): un-NAT it if the flow
	// is ours, or hand it to the node whose ct_rev holds it.
	{
		struct pkt np;
		if (parse_ip(skb, &np) == 0 && !np.is_v6) {
			int nr = vpc_nat_reverse(skb, &np);
			if (nr != NAT_MISS)
				return nr;
		}
	}

	struct bridge_ep *fe = float_of(d128);
	if (fe) {
		struct endpoint *l = local_of(fe->net, fe->vpc_ip);
		if (l)
			return deliver_local(skb, l);
		// The pod lives elsewhere: we attracted the address, another node
		// delivers it. `floating` gave us the pod's {net, VPC IP} — exactly
		// the key `remotes` is fed with per-pod — so the host is one lookup
		// away. Encapsulate verbatim (public dst and client src intact) and
		// let from_overlay hand it to the pod's veth, where to_pod DNATs it
		// like any other floating packet. The reply does NOT come back
		// through here: the host SNATs it to the public address and sends it
		// straight to the client (docs/floating-ha.md).
		__u32 *node_ip = remote_of(fe->net, fe->vpc_ip);
		if (node_ip)
			return encap(skb, fe->net, *node_ip, 0);
		return TC_ACT_OK; // no live target anywhere: leave it to the kernel
	}

	// LoadBalancer/NodePort ingress (docs/lb-ingress.md): dst may be a
	// Service LB IP or this node's address on a NodePort — a tail call into
	// its own program (fresh stack + budget; see lb_prog). Falls through to
	// TC_ACT_OK when the agent hasn't populated the slot. An LB miss chains
	// into the host firewall from inside lb_ingress; if the LB slot itself
	// is unpopulated, run the firewall from here.
	bpf_tail_call(skb, &lb_prog, 0);
	if (HF_ARMED())
		bpf_tail_call(skb, &lb_prog, 2);
	return TC_ACT_NEXT;
}
