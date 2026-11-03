# cozyplane internals

How cozyplane works **as built today** (the default network + basic VPCs), and
how the code is organized. For the broader architecture this is converging
toward, read [design.md](design.md); where this doc and the design disagree, this
doc describes reality.

## 1. The model in one paragraph

Every pod interface belongs to a **network**, identified by a small integer
*network id*. The default/system network is id `0`. Each `VPC` gets a unique id
(≥100, also used as the Geneve VNI). All inter-node traffic rides a single
per-node Geneve device; the datapath encapsulates a packet only when its
destination is on another node, and drops it when source and destination
networks differ (unless a `VPCPeering` explicitly connects the two). Services
are not cozyplane's job — kube-proxy or Cilium-KPR handles them, unchanged.

**VPC CIDRs may overlap freely** — two tenants can both use `10.0.0.0/24`, even
the cluster pod CIDR. Everything a tenant addresses is keyed by **(network id,
IP)**, never by IP alone: the `locals`, `remotes`, and `networks` maps carry a
network scope, and cross-node overlay traffic is decapsulated and delivered by
an eBPF program that demuxes on the Geneve VNI (the kernel cannot route two
identical VPC IPs). The default/system network keeps unique cluster-pod-CIDR
addresses and stays on the kernel-routed path, so only genuine VPC overlay
traffic takes the eBPF delivery path. The one rule overlap carries: two VPCs
with overlapping CIDRs cannot **peer** (peered traffic is routed natively, so a
shared address would be ambiguous).

## 2. Components

```
            ┌──────────────── control plane ────────────────┐
            │  sdn-controller        VPC/Port API (CRDs)     │
            │  (assigns VPC VNIs)    group sdn.cozystack.io   │
            └───────▲────────────────────▲───────────────────┘
                    │ watch VPCs          │ get VPC / claim Port
        ┌───────────┴──────────┐   ┌──────┴───────────┐
        │ cozyplane-agent (DS) │   │ cozyplane (CNI)  │
        │ per node, hostNet,   │   │ per pod ADD/DEL, │
        │ privileged           │   │ host-side binary │
        └───────────┬──────────┘   └──────┬───────────┘
                    │ load/pin eBPF,       │ veth + IPAM,
                    │ Geneve, maps,        │ writes ports map,
                    │ FORWARD rule         │ attaches program
                    └──────────┬───────────┘
                          eBPF datapath (bpf/overlay.c)
```

- **`cozyplane-agent`** (`cmd/agent`, DaemonSet, `hostNetwork`, privileged). Owns
  the node datapath: loads and pins the eBPF objects, creates the Geneve device,
  sets sysctls and the FORWARD rule, attaches the classifier to the uplink, and
  publishes node state + a kubeconfig for the plugin. It then *watches* the API
  and keeps the maps in sync: `Node` → remote pod CIDRs, `VPC` → the networks
  map, `Port` → remote VPC pod /32s, `VPCPeering` → the peers map. It depends
  only on the **core** API for the default network, so it can bootstrap before
  the VPC API exists.
- **`cozyplane` CNI plugin** (`cmd/cni`, invoked by kubelet per pod). Sets up the
  pod's veth, allocates the IP, programs the per-veth network id, and attaches
  the classifier. Two paths: default (host-local IPAM) and VPC (claim a `Port`).
- **`sdn-controller`** (`cmd/sdn-controller`, controller-runtime Deployment).
  Assigns each `VPC` a unique network id (VNI) and marks it `Ready`; reaps
  `Port`s on `VPCBinding` deletion; surfaces `VPCPeering` matched/ready status;
  realizes a `VPCGateway` — for one with a pool, entirely in eBPF (no pod); only a
  pool-less `nat.enabled` gateway still gets a per-VPC gateway Deployment.
- **`cozyplane-gateway`** (`cmd/gateway`, one privileged pod per egress-enabled
  VPC). A default-network pod with a gateway-attached second leg; forwards the
  VPC's off-net traffic (masqueraded) under a default-deny filter — internet
  passes, cluster-internal CIDRs drop — and proxies cluster DNS (:53) through
  its own sockets so ClusterIP translation applies.
- **API** (`api/sdn`, group `sdn.cozystack.io/v1alpha1`): `VPC`, `VPCBinding`,
  `VPCPeering`, `Port`. Served as **CRDs** (`config/crd/`) or by the aggregated
  API server (`pkg/apiserver`, `cmd/apiserver`) — a transparent swap because the
  group/version/kind and generated clients are identical.

## 3. The eBPF datapath

One C file, `bpf/overlay.c`, compiled with CO-RE via `bpf2go`. It defines four
maps and one program.

### Maps

| Map | Type | Key → Value | Written by |
|-----|------|-------------|-----------|
| `remotes` | LPM trie | {scope net, dst IP/CIDR} → remote node IP | agent (Nodes + Ports) |
| `networks` | LPM trie | {scope net, CIDR} → dst net id | agent (VPCs + VPCPeerings) |
| `ports` | hash | veth ifindex → network id (bit 31 = gateway leg) | plugin (per pod) |
| `locals` | hash | {net id, pod IP} → {veth ifindex, pod MAC, SHA-256 Port/sandbox witness} | plugin (per pod) |
| `peers` | hash | {src net id, dst net id} → 1 | agent (VPCPeerings) |
| `gateways` | hash | net id → {gateway .1 IP, node IP (0=local)} | agent (gateway Ports) |
| `bridges` | hash | fabric IP → {net id, VPC IP} | plugin (per VPC pod) |
| `ct_fwd` / `ct_rev` | LRU hash | the bridge's L4 NAT connection table | datapath (in-band) |
| `svc_vips` | hash | {net, VIP, proto, port} → backend set + flags | agent (ServiceVIPs) |
| `vpc_counters` | PERCPU hash | net id → {tx,rx bytes/packets} | datapath (in-band) |
| `sg_members` | hash | {net, VPC IP} → group bitmap + SHA-256 Port/sandbox witness; explicit zero for resolved unselected Ports | agent (Ports' UID-proven membership status) |
| `sg_rules` | hash | {dst net, src net, dst group, proto, port} → `u64` allowed-source bitmap | agent (SecurityGroups) |
| `sg_egress` | hash | {src net, dst net, src group, proto, port} → allowed-dst-group bitmap | agent (SecurityGroups) |
| `sg_cidr` | LPM trie | {net, proto, port, client CIDR} → allowed-group bitmap | agent (SecurityGroups) |
| `sg_drops` | PERCPU hash | net id → policy-drop count | datapath (in-band) |
| `params` | array | `[0]`=Geneve ifindex, `[1]`=default VNI | agent |
| `vpc_routes` | LPM trie | `{VNI, prefix}` → up to two appliance next hops; zero hops is a blackhole | agent |
| `route_guard` | one-cell array | blocks off-VPC workload egress during incomplete route compilation/publication | agent |
| `hf_modes` | array | ingress/egress isolation mode + initialization witness, preserved independently of `params` | agent |

Per-VPC metering (#2): `count_dir` bumps `vpc_counters` — **both directions
from `to_pod`** (rx for the destination net, tx for the source net), the one
placement-independent delivery hook, so east-west is metered once. It is a
`noinline` BPF-to-BPF subprogram that only looks up and increments (never
allocates): inlining it blew `from_pod` past the verifier's 1M-instruction
budget on a 6.12 kernel (6.8 accepted it — caught only on the dev cluster; the
same divergence took the whole hook down on 6.18, field note 12), and any callee
stack of its own overflowed the 512-byte combined-frame limit against
`from_pod`'s already-large frame. The **agent seeds** a zeroed PERCPU entry per
VPC net (`EnsureVPCCounter`, alongside `SetNetwork`); the datapath can't create
one. PERCPU so the hooks never contend; the agent sums across CPUs and serves
Prometheus text on `:9411/metrics`, labeled by VPC. Net 0 (default) is never
metered; north-south (gateway/floating) and ServiceVIP replies are a follow-up.

Security groups (#7, intra-VPC policy — see [security-groups.md](security-groups.md)):
`to_pod`, right after the isolation check, gates admitted east-west traffic
destination-side. `sg_admit` (another stack-lean `noinline` subprogram, single
`sg_query` pointer arg) looks up the destination's group bitmap in `sg_members`;
missing registered local VPC membership remains pending under bit zero, while
an explicit zero entry proves resolved unselected membership. Before Port status
proves the current Pod UID, the agent keeps the same pending bit.
if it is grouped, it unions the `sg_rules` allowed-source bitmaps for the
destination's groups and admits only if that intersects the source's bitmap,
else drops and bumps `sg_drops`. TCP is gated on new connections only (SYN,
no ACK) so replies pass without a conntrack; UDP always. **Egress** is the
mirror (`sg_egress_admit` over the *source's* groups against `sg_egress`): a
grouped pod's east-west egress is default-deny too, so a flow is delivered only
if the destination's ingress admits the source **and** the source's egress
admits the destination — both loops run on the same gated SYN, in `to_pod` and
in the `from_overlay` TLV path. Gateway-forwarded (`GW_MARK`) ingress is exempt.
The source's groups come from its *own* net
(`sg_members[{srcnet, src}]`) and rules are keyed by `src_net` too, so a
**peered** group can be admitted (`from: {group, vpc}`) while an unreferenced
peer still hits the default-deny. Cross-peer identity is made authoritative by a
**Geneve TLV**: `from_pod` stamps a grouped source's `{net, groups}` (from its
veth, not the packet) into a Geneve option on encap; `from_overlay` — the only
hook that sees tunnel metadata — reads it, runs `sg_admit` before delivery, and
sets an `SG_OK` mark so `to_pod` skips the (spoofable) inference. So a
mutually-peered tenant can't wear another peer's *net*. (docs/security-groups.md
has the trust model and its intra-VPC RPF caveat.)

**North-south** (`from.cidr`): grouping closes a pod's north-south too — the
`bridge_forward`/`floating_forward` DNAT points enforce SG before the `ct_fwd`
alloc, `from: {cidr: 0.0.0.0/0}` reopening it via the `SG_WORLD` pseudo-group.
Kubelet stays exempt by *path*: pod-originated north-south is eBPF-redirected
(from_pod/from_overlay stamp `NS_MARK`) and gated, while kubelet reaches
`bridge_forward` via the kernel `/32` route unmarked and untouched — a first cut
that keyed on "source == node IP" broke readiness probes and was replaced.
Floating IPs gate unconditionally (never node-originated).

The scoped maps use a `{prefixlen, scope_net, addr}` LPM key: the scope net
occupies the leading 32 bits (always fully specified), so a lookup never
crosses scopes. `networks` doubles as delivery *and* isolation resolution — a
VPC's own CIDR maps to itself at its own scope (`{Nx, Cx} → Nx`); a peering
adds each side's CIDR under the other's scope (`{Nx, Cy} → Ny`), so
`from_pod`/`to_pod` resolve the peer's net and the peers-map verdict admits it.
A peer entry is recognizable (value ≠ scope), which lets the agent prune stale
ones after a restart.

All are pinned under `/sys/fs/bpf/cozyplane/` (`LIBBPF_PIN_BY_NAME`) so the
short-lived plugin and the long-running agent share the same map instances.

### The programs

cozyplane enforces at **two universal hooks** — see the placement-independence
invariant in [design.md](design.md) §4. Both run for every packet regardless of
where source and destination are scheduled. They are attached with **tcx** (BPF
links, pinned), not classic clsact filters: tcx links coexist with other tcx
users (notably Cilium, which reconciles tc on every device and strips foreign
*classic* filters but leaves tcx links alone), and pinning lets them survive the
short-lived CNI plugin.

**`cozyplane_from_pod`** — the egress hook. Attached at the **ingress of every
pod's host-side veth** (a pod's egress) and at the **egress of the node uplink**
(host-originated traffic). For each IPv4 packet:

1. exempt traffic to the link-local gateway `169.254.1.1` (replies to bridged
   node→pod traffic; the host stack/conntrack handles them);
2. source net = `ports[skb->ifindex]` (absent ⇒ `0`; bit 31 flags a gateway
   leg); dest net = `networks[dst]` (absent ⇒ `0`); if they differ and
   `peers[{src,dst}]` misses: a VPC pod's off-net traffic (`srcnet≠0`,
   `dstnet=0`) is handed to `gateways[srcnet]` — local gateway by redirect
   into its VPC leg, remote by encap to its node — and everything else
   (fabric→VPC, unpeered cross-VPC, no gateway) is **dropped**;
3. if the destination is a **local pod in a VPC net** (`dstnet != 0` and
   `locals[dst]` hits): rewrite the dst MAC to the pod's MAC and `bpf_redirect`
   to its veth — same-node delivery *through* the destination's ingress hook,
   no kernel-routing shortcut. **Net 0 is deliberately excluded**: the default
   network is delivered by the kernel, because a direct redirect bypasses
   netfilter and with it kube-proxy's conntrack — a ClusterIP reply from a
   same-node backend would reach the client still carrying the backend's
   source, never un-DNAT'd (a latent M0 bug, found when the scheduler
   co-located the e2e client with its coredns);
4. else if **remote** (`remotes[dst]` hit): rewrite the inner dst MAC to the
   shared overlay MAC, set the Geneve tunnel key (`tunnel_id` = source net id,
   remote = node IP), `bpf_redirect` to the Geneve device;
5. else `TC_ACT_OK` (off-cluster / node / fabric-bridge — the kernel handles it,
   including the conntrack bridge DNAT for VPC fabric IPs).

**`cozyplane_to_pod`** — the ingress hook. Attached at the **egress of every
pod's host-side veth**. Every delivery path leaves via the destination veth
(same-node redirect from step 3, cross-node decap-then-route, node→pod bridge),
so this is the placement-independent point for ingress policy. For each packet:

1. exempt source `169.254.1.1` (bridge/masqueraded node→pod traffic);
2. dest net = `ports[skb->ifindex]` (flag bit masked); source net =
   `networks[src]`; **drop** if they differ and `peers[{src,dst}]` misses —
   unless the packet carries the **gateway mark**: traffic a VPC's egress
   gateway forwards inward has an off-VPC source (the internet, cluster DNS),
   so `srcnet` is 0, but it was blessed in-kernel (see below) and tenants
   cannot forge that. This keeps the anti-spoof property: an in-VPC pod
   spoofing an external source is still dropped.

**`cozyplane_from_overlay`** — attached at the **ingress of the Geneve
device**, where packets arrive decapsulated but with the tunnel key readable.
Gateway plumbing only; everything else passes through untouched:

1. a `TUN_F_GATEWAY` bit in the VNI marks gateway-forwarded traffic — re-apply
   the gateway mark (`skb->mark`) so the destination veth's `to_pod` admits it
   (the mark itself doesn't survive encapsulation; the VNI bit does);
2. an off-net destination arriving on a VPC's VNI is tenant→outside traffic
   for a gateway hosted on **this** node: the kernel has no route for it, so
   redirect it into the gateway's VPC leg (through the gateway's `to_pod`).

The gateway mark is set in exactly two places — `from_pod` at a gateway leg
(same-node delivery) and `from_overlay` (cross-node) — both in-kernel, so
"came through the gateway" is unforgeable from inside any pod.

Cross-node decapsulation itself is still done by the kernel Geneve device (see
the two tricks below); the decapped packet is then routed out the destination
veth and so still passes `to_pod`. Moving decap into an eBPF program (needed for
overlapping CIDRs) is future work and must preserve this invariant.

### Trick 1 — the shared Geneve MAC (decap delivery)

The Geneve device runs in `collect_metadata` (external) mode and carries L2
frames. A decapsulated frame still has the *sending* node's inner Ethernet
destination MAC, which is foreign on the receiver, so the kernel marks it
`PACKET_OTHERHOST` and refuses to route it. `skb->pkt_type` is read-only in tc,
so instead every node's Geneve device is given the **same fixed MAC**
(`02:cf:cf:cf:cf:cf`, `datapath.OverlayMAC` / `OVERLAY_DMAC`), and the encap path
rewrites the inner destination to it. The decapsulated frame is then addressed to
the receiver's own Geneve device → `PACKET_HOST` → the kernel forwards it to the
local pod via that pod's `/32` route. (This is the Flannel-style trick adapted to
eBPF encap.)

### Trick 2 — FORWARD ACCEPT (conntrack)

Pod egress is encapsulated by a tc `bpf_redirect`, which **bypasses conntrack**.
The decapsulated reply that returns on the Geneve device therefore has no
matching conntrack entry, so kube-proxy's `KUBE-FORWARD ... ctstate INVALID -j
DROP` discards it. The agent inserts `-i cozyplane0 -j ACCEPT` and `-o cozyplane0
-j ACCEPT` at the top of the `FORWARD` chain — **in both families** (`iptables`
*and* `ip6tables`, nft backend) — so overlay traffic is accepted before that
drop. kube-proxy programs the INVALID drop into ip6tables too; with only the v4
ACCEPT, the v6 north-south *reply* toward a default-network pod (the one leg
`from_overlay` hands to the kernel) was dropped exactly when client and server
sat on different nodes.

**The rule is conditional (#10):** the agent installs it per family only when
that family's `KUBE-FORWARD` chain exists — i.e. exactly when an iptables-mode
kube-proxy is present, which is also the only world where the drop exists. On a
kube-proxy-replacement node nothing is installed, and netfilter being
unreachable is a warning, not a startup failure. The rule cannot be *designed
away* while coexisting with an iptables kube-proxy: ClusterIP replies must
traverse the client node's conntrack to reverse the service DNAT, so
`from_overlay` deliberately hands default-network traffic to the kernel instead
of redirecting past netfilter. (Coexistence is today's deployment reality, not
an architectural commitment — cozyplane may eventually own Services.)

### Packet walks

**Default network, cross-node (pod A on N1 → pod B on N2):** A sends → host veth
ingress → `from_pod` (srcnet 0, dstnet 0, allowed) → `remotes` hit at scope 0
(B's node) → inner MAC rewritten, tunnel key {vni=1, N2}, redirect to Geneve →
out the uplink as Geneve/UDP 6081 → N2 receives, kernel decaps (frame addressed
to N2's Geneve MAC), `from_overlay` sees the default VNI and passes it to the
kernel → routes to B via B's `/32` → B. Reply retraces it.

**Node → remote pod:** host stack routes the packet out the uplink → uplink
egress `from_pod` (srcnet 0 because the uplink isn't in `ports`) → `remotes` hit
→ encapsulate. This is what makes Service return paths and apiserver→pod work.

**Isolation (VPC pod → default pod):** srcnet = the VPC's id; `net_of(networks,
srcnet, dst)` misses (the default network's addresses aren't in the VPC's scope)
→ dstnet 0 → off-net → drop (or the gateway, if one exists). Same for
VPC→other-VPC. A `VPCPeering` is the exception: it adds the peer's CIDR to each
side's scope, so `net_of` resolves the peer's net, `peers[{src,dst}]` admits it,
and the packet is delivered exactly like same-VPC traffic (native IPs, no NAT;
`locals[{dstnet,dst}]` redirect same-node, `remotes[{dstnet,dst}]` encap
cross-node). Overlapping CIDRs make this ambiguous, so they can't peer.

**VPC, cross-node under overlapping CIDRs (A in VPC-X → B in VPC-X, another VPC-Y
pod shares B's IP):** A → `from_pod` resolves dstnet = X (B is in X's scope) →
`remotes[{X, B-ip}]` hit → encap with **tunnel_id = X** → B's node. There
`from_overlay` reads VNI X, looks up `locals[{X, B-ip}]`, and redirects into B's
veth — *not* the kernel's `/32` route, which couldn't tell B from the VPC-Y pod
sharing the IP. The VPC-Y pod is reached only under tunnel_id Y. Same-node, A's
`from_pod` uses `locals[{X, B-ip}]` directly.

**Egress (VPC pod → 8.8.8.8, gateway on another node):** srcnet = VPC id,
dstnet 0, peers miss → `gateways[srcnet]` hit → encap to the gateway's node
(VNI = the VPC's) → `from_overlay` there sees an off-net dst on a VPC VNI →
redirect into the gateway's VPC leg (through its `to_pod`: src is in-VPC,
allowed) → the gateway pod's kernel forwards it: filter (internal CIDRs
dropped, internet allowed), MASQUERADE to the gateway's fabric IP, out its
default-network leg → node masquerade SNATs to the node → internet. DNS is the
exception: queries to the cluster DNS ClusterIP are REDIRECTed to a proxy in
the gateway, whose *own* sockets dial upstream — under socket-level
kube-proxy-replacement, ClusterIPs are translated at connect(), never for
packets merely forwarded through a pod. The reply
unwinds the two conntracks, and the gateway sends `8.8.8.8 → tenant-IP` out
its **VPC leg**: `from_pod` there is flagged (ports bit 31) so the packet gets
the gateway mark (same-node) or the `TUN_F_GATEWAY` VNI bit (cross-node), and
the tenant's `to_pod` admits the off-VPC source.

### The dual-address bridge (VPC pods)

A VPC pod has two addresses: its `status.podIP` is a unique **fabric** IP from
the node pod CIDR (allocated by host-local, reachable cluster-wide over the
default overlay), while its interface carries the **VPC** (tenant) IP. The fabric
IP is a node-side handle, never configured inside the pod.

The translation is **eBPF NAT** — no iptables, no fwmark, no policy routing.
The datapath keeps its own small connection table (`ct_fwd`/`ct_rev`, LRU
hashes) in place of kernel conntrack, and does the rewrites (checksum-correct)
in the two universal hooks:

- **node/Service/pod → VPC pod:** `to_pod` looks up the packet's destination in
  the pinned `bridges` map (`fabricIP → {net, vpcIP}`). On a hit it DNATs
  `fabricIP → vpcIP` and masquerades the source to `169.254.1.1:gw_port` — a
  masquerade port allocated by probing the reverse key with `BPF_NOEXIST`, so it
  is unique per `{net, vpcIP, pod_port}`. The pod sees only the gateway and never
  learns the node/fabric/client address.
- **VPC pod → reply:** the pod replies to `169.254.1.1`; `from_pod` looks the
  `gw_port` back up in `ct_rev`, restores `vpcIP → fabricIP` on the source and
  `169.254.1.1 → client` on the destination, and delivers the reply on the
  default network (`deliver_net0`).

TCP, UDP, and **ICMP echo** (ping). ICMP has no L4 ports, so the echo
**identifier** plays the part of the port: a request masquerades its id to a
unique `gw_id` (via the same `ct_rev` allocation as `gw_port`) and the reply
restores it. Two checksum wrinkles distinguish ICMP from TCP/UDP: an address
rewrite fixes only the **IP** checksum (ICMP's checksum, unlike TCP/UDP's, does
not cover the IP header), and the id rewrite fixes only the **ICMP** checksum.
ICMP *error* messages (fragmentation-needed / PMTU, unreachable, TTL-exceeded)
embed the original packet and are not NAT'd yet — still a follow-up, so
PMTU discovery through the bridge does not work.

This gives the design's directional trust for free: the system/default network
reaches a VPC pod via its fabric IP (north-south, allowed), but a VPC pod can't
initiate outward (dropped by the isolation rule). Because the fabric IP lives in
the node pod CIDR, the default overlay carries it cross-node, so
Services/Endpoints and remote-node access work unchanged.

**Delivery by identity, under overlapping CIDRs.** After the DNAT the
destination is the VPC IP, which two same-node pods in different VPCs may share
— so nothing routes by it. The **fabric IP is unique**, so it is what steers
delivery: a plain `/32` route (`fabricIP → the pod's veth`, netlink) carries
node-originated traffic (kubelet probes) to `to_pod`, and cross-node / same-node
north-south is redirected straight into the pod's veth from `from_overlay` /
`from_pod` (a `bridges` hit resolves the pod's MAC via `locals[{net, vpcIP}]`),
bypassing the kernel FORWARD chain entirely. The NAT itself is keyed by
`{net, vpcIP}`, so the two same-IP pods stay distinct. Like the overlay, the
bridge delivers by identity, never by a shared address.

**The fabric neighbour.** The `/32` route alone cannot carry node-*originated*
traffic: the kernel must resolve the fabric IP's L2 address on the veth, and
nothing answers — the pod's interface carries only the VPC IP (only
default-network pods, which *are* their fabric identity, answer that ARP). So
CNI ADD pins a **permanent neighbour** (`fabricIP lladdr <podMAC> dev <veth>`,
both families) next to the route, and the agent's rebuild heals it on veths
ADDed by older releases. Without it, kubelet-probe-style traffic and the DNS
resolver's replies die in FAILED ARP/NDP before ever reaching `to_pod`'s DNAT
(the eBPF-redirected paths never noticed — they carry the MAC from `locals`).
Like the route, the entry lives and dies with the veth.

### VPC DNS steering (split-horizon resolver)

VPC CIDRs may overlap the fabric pool. Native VPC delivery carries a private
VPC_MARK derived by trusted origin/overlay hooks and cleared at untrusted
boundaries. The receiving hook resolves the scoped local owner, consumes the
marker, and enforces SecurityGroups without reinterpreting an equal address as
a global fabric, DNS or floating alias. Unmarked host probes and legitimate
resolver replies retain their plumbing path. Real classifier tests cover local
and Geneve IPv4/IPv6 TCP/UDP delivery, default-deny, explicit group rules,
overlapping VNIs, recycled owners and repeated descriptor lifetime.

A VPC pod's `resolv.conf` points at the cluster DNS ClusterIP, which the
isolation rule makes unreachable — so `from_pod` **steers** those queries to a
node-local split-horizon resolver instead ([services-in-vpc.md](services-in-vpc.md)).
Both halves are **stateless** (no ct entry, no port allocation):

- **`dns_steer` (from_pod):** for a non-gateway VPC pod whose destination
  resolved off-VPC (`dstnet == 0` — so a tenant whose own CIDR covers the
  service range shadows it, and intra-VPC `:53` is never hijacked), a TCP/UDP
  packet to `dns_ips[family]:53` is rewritten: source → the pod's **fabric IP**
  (via `fabric_of`, the `bridges` inverse — programmed only for same-family
  pairs), destination → `nodeIP:15353` (`CFG_RESOLVER_PORT`; 0 disables), and
  passed to the host stack. The pod's ephemeral source port is preserved —
  fabric IPs are unique, so the 5-tuple stays unambiguous.
- **`dns_return` (to_pod):** the resolver's reply (`nodeIP:15353 →
  fabricIP:sport`, routed back by the fabric `/32`) is recognized by its
  reserved source port (below the masquerade/NodePort/ephemeral ranges, so a
  kubelet probe can never carry it), un-NAT'd via the `bridges` map, and
  delivered without the ingress isolation check (a sanctioned path, like the
  bridge).

**Socket-LB coexistence (`dns_ct`).** Under a socket-LB kube-proxy replacement
— and Cilium KPR *forces* socket LB on (`NewKPRConfig` overrides
`bpf-lb-sock: false`; validated live on the dev cluster) — the ClusterIP is translated to
a backend pod address at `connect()` time, so the wire packet `from_pod` sees
carries the backend, not `dns_ips`. The steer therefore also matches any
**cluster-internal** `:53` destination (`is_internal`; a tenant's DNS to an
off-cluster server via its gateway never matches, and in-VPC `:53` never gets
here — `dstnet != 0`), and records the original wire destination in `dns_ct`
(LRU, keyed `{proto, pod sport, fabric IP}`). `dns_return` restores it as the
reply's source: the pod's connected socket filters on that exact address, and
the socket-LB `recvmsg` hook translates it back to the ClusterIP for the
application. Under a plain kube-proxy the recorded address is simply the
ClusterIP, so the behaviour is unchanged (LRU eviction falls back to
`dns_ips`).

The rewritten **fabric source doubles as the per-Port identity handle**: the
responder (`cmd/responder`, an unprivileged second container in the agent
DaemonSet) maps it to the querying Port and answers that VPC's view —
annotation-attached headless Services resolve to backend **VPC IPs**
(A/AAAA/per-hostname/SRV), services attached to an *actively peered* VPC
(a Ready `VPCPeering` half; peered CIDRs are disjoint, so the answers are
unambiguous and natively reachable) resolve the same way, every other
cluster-domain name is authoritative NXDOMAIN (never forwarded: other tenants
stay unprovable, and cluster ClusterIPs would be dead ends anyway), and
non-cluster names forward to the node's own upstreams. The agent publishes
`dns_ips` from the `kube-system/kube-dns` Service (`--cluster-dns` overrides,
`--vpc-dns=false` disables); the responder autodetects the cluster domain
from its own kubelet-written search path — present despite hostNetwork
because the DaemonSet runs `ClusterFirstWithHostNet` — with `CLUSTER_DOMAIN`
as the override.

### ServiceVIPs (ClusterIP inside a VPC)

An attached non-headless Service gets a **ServiceVIP**: an address from the
VPC's own space (allocated top-down; Ports walk bottom-up), discovered only
through the split-horizon resolver, and load-balanced entirely in `from_pod`
([services-in-vpc.md](services-in-vpc.md)):

- **Forward:** after admission (same net or peered — so a peered client uses
  the peer's VIPs), a TCP/UDP packet to `svc_vips[{net, vip, proto, port}]`
  is DNAT'd to one of ≤16 backends `{VPC IP, target port}`. The backend is a
  5-tuple hash **pinned per flow** in `svc_fwd` (LRU) — a backend-set change
  never moves an established connection — and the reverse entry lands in
  `svc_rev`, both on the client's node, where both directions of the flow are
  guaranteed to pass. Two hash subtleties, both found live: the mix must
  **avalanche** (a plain XOR left `% n` constant because the kernel strides
  ephemeral ports), and the reduction must be **multiply-shift**
  (`hash * n >> 32`), not modulo — Talos hands out single-parity ports in a
  burst, starving the low bits `% n` reads, so a whole client collapsed onto
  one backend even with avalanching. Multiply-shift buckets on the
  fully-mixed high bits. Delivery then simply continues toward the rewritten
  destination (locals/remotes/overlay — placement-independent).
- **Reverse:** the client's `to_pod` looks up `svc_rev` and restores
  `backend:target → vip:port`; a hit is sanctioned (the forward direction was
  admitted).
- **Hairpin:** a backend dialling its own service and selecting itself has
  its client half SNAT'd to a reserved loopback (`169.254.42.1` /
  `fe80::2a01`) so the two directions stay distinguishable inside one pod;
  the whole flow lives on that pod's veth (out and straight back in), and
  `from_pod` reverses it on the reply.

The agents project ServiceVIPs into `svc_vips` (full-state diff); the
controller owns allocation (live union of Ports + ServiceVIPs — the CNI's
Port claim counts VIPs as used, too) and backend resolution (EndpointSlice →
Port → VPC IP; fabric addresses never appear). A Port always wins an IP
conflict: the VIP is the movable kind and reallocates.

### Floating IPs (external north-south)

**Cozyplane does not attract a floating address — it delivers one.** Something else
puts the address on the wire (a CCM assigning it to a node's VNIC, MetalLB, a static
route, or simply an address configured on a node); cozyplane's job starts when the
packet arrives. There is no ARP/NDP responder, no announcer election and no
gratuitous-ARP emitter: that layer existed and was **deleted**, because it was
MetalLB's L2 mode reimplemented inside a CNI (`docs/floating-ha.md` §5,
`docs/north-south.md` tenet 3).

What makes that work is that **`from_uplink` runs at tc ingress, ahead of the
kernel's routing decision**. So it does not matter *which* node the address was
attracted to: whichever node sees the packet resolves the pod and delivers it,
locally or over the overlay. A live migration therefore makes no L2 claim at all —
the address does not move.

Floating IPs are dual-family, and both families share the same maps and the same
stateless model — inbound public→VPC DNAT preserving the client
(`floating_forward`/`floating_forward6`), outbound VPC→public SNAT out the uplink
(`floating_egress_snat`/`floating_egress_snat6`) — including the ICMP/ICMPv6 error
embedded-header rewrites, so PMTU and traceroute work through a floating address in
either family.

The dual-address bridge above is *internal* north-south: a fabric IP reachable
from the cluster's default overlay. A **floating IP** is the same idea turned
outward — a routable public address, reachable from off-cluster, bound 1:1 to a
tenant IP — realized as an **extension of the eBPF bridge, not the gateway**. No
iptables, no gateway pod: it is the fabric bridge with an external address and
the client-masquerade removed, so the tenant sees the *real* caller. An address is
drawn from the pool of the VPC's `VPCGateway`, so a VPC with no boundary has no
external address (`docs/north-south.md`). The pieces:

- **`floating` map** (`publicIP → {net, vpcIP}`), programmed by the agent on
  **every** node — the external-facing sibling of `bridges`. It says where an
  address leads, not who owns it. Cluster-wide precisely *because* any node may be
  the one the address lands on.
- **An uplink-ingress hook** (`from_uplink`). A tc program at the node uplink's
  ingress catches `client → publicIP` and `bpf_redirect`s it into the target's
  veth by identity (`locals[{net, vpcIP}]`) when the pod is local — and
  Geneve-encapsulates it to the pod's node (`remotes[{net, vpcIP}]`) when it is
  not, since **the node the address was attracted to need not be the host**. Either
  way it does *not* rewrite the packet: the DNAT happens where the bridge's does, in
  `to_pod`. This mirrors the bridge exactly (`from_uplink` is to floating what
  `from_pod`/`from_overlay` are to the fabric bridge).
  A packet that arrives by the second path needs one more thing: `from_overlay`'s VPC
  branch probes `floating` **before** its `gateways` lookup, because a public inner
  destination misses `locals` (keyed by VPC IP) and would otherwise be delivered
  *into the VPC's gateway pod* — a mis-delivery, not a drop.
- **`to_pod` does the inbound DNAT** (`floating_forward`, beside `bridge_forward`).
  It DNATs `publicIP → vpcIP` on the destination, keeping the external client as
  the source — *not* masqueraded to `169.254.1.1`. It is **stateless**: a plain
  `floating`-map lookup, no conntrack. Like `bridge_forward` it returns delivered,
  so the isolation check below never runs.
- **Egress through `from_pod`** — the address is a *true public IP*, used for the
  pod's **outbound** traffic too, not just replies. `from_pod` looks the pod's
  `{net, vpcIP}` up in a reverse map (`floating_egress`); on a hit it SNATs the
  source `vpcIP → publicIP` and **`bpf_redirect_neigh`s it out the uplink** (kernel
  neighbour resolution for the destination). This one path covers both a reply to
  an inbound connection *and* a connection the pod originates — the mapping is a
  stateless 1:1 bijection either way (which is why `float_ct` is gone). The
  redirect matters: the reply would otherwise face `rp_filter` and the FORWARD
  chain; `redirect_neigh` bypasses them and fills the L2 header from the
  destination's neighbour entry — the datapath's usual "don't route, deliver by
  identity."
- **Internet only takes the public IP; internal still goes to the gateway.**
  Before the SNAT, `from_pod` checks the destination against an `internal` LPM map
  (pod/service/node CIDRs, programmed by the agent). Only *non*-internal (internet)
  destinations egress from the public IP; a cluster-internal destination falls
  through to the normal path — the VPC gateway, which proxies cluster DNS on `:53`
  and denies the rest, exactly as for a non-floating pod. So a floating pod keeps
  the **same internal reachability** as any tenant pod (its own VPC and peers via
  overlay delivery, cluster DNS via the gateway, other system services denied) and
  simply *also* egresses the internet from its public IP. A floating pod needs no
  gateway to work; if the VPC has none, its internal/DNS traffic is dropped like
  any gateway-less VPC's and it uses external DNS.

**Inbound walk (external client → floatingIP → tenant pod B in VPC-X), address
attracted onto B's own node:** `client → floatingIP` arrives → `from_uplink`
redirects it into B's veth (`locals[{X, B-ip}]`) → `to_pod`'s `floating_forward`
DNATs it to `client → B-ip`, keeping the client source → B replies `B-ip → client`
toward `169.254.1.1` → `from_pod` finds `floating_egress[{X, B-ip}]`, SNATs the
source `B-ip → floatingIP`, and `redirect_neigh`s it out the uplink, unmasqueraded.

**Inbound walk, address attracted onto some other node N:** `client → floatingIP`
arrives at **N** → `from_uplink` misses `locals`, hits `remotes[{X, B-ip}]`, and
Geneve-encapsulates the packet **verbatim** (public destination and client source
both intact) to B's node → `from_overlay`'s floating probe resolves it to B and
delivers into the veth → `to_pod` DNATs exactly as above, because it keys on the
destination and has **no notion of provenance**. B's reply leaves **B's own node**
directly (`floating_egress_snat`, sourced as the floating IP) and never touches N.
That is DSR: N carries only the request half.

**Outbound walk (B originates a connection to the internet):** identical from
`from_pod` on — `floating_egress[{X, B-ip}]` hits, the destination is not
cluster-internal, so `B-ip → dst` is SNATed to `floatingIP → dst` and redirected
out the uplink. The remote sees B's public IP as the source, matching the address
it is reached on. The reply retraces the inbound walk (`from_uplink` → DNAT). It
is one stateless bijection: inbound DNAT via `floating`, outbound SNAT via
`floating_egress`, no conntrack on either side.

**No gateway.** A floating pod uses neither the VPC's egress gateway nor any
conntrack; both directions are the 1:1 map. A floating IP is `Ready` once its
target IP is a **live Port** (a running pod to deliver to); with no live target the
address stays reserved but silent (see §4, the controller). Egress is distributed
(DVR) — the reply leaves from the pod's own node, sourced as the public address,
whichever node attracted the request.

### Addressing / byte order (for maintainers)

- `remotes` / `networks` LPM keys are `{prefixlen, scope_net, addr}` with
  `addr` in **network byte order** (LPM matches MSB-first) and `scope_net` an
  opaque net id matched for equality in the leading 32 bits. In Go `addr` is
  filled with `binary.LittleEndian.Uint32(ip4)` so its native-endian marshaling
  lands the bytes in network order; the C side uses `ip->daddr` directly. See
  `datapath.lpmKey`.
- `remotes` values are the remote node IP in **host byte order**, because
  `bpf_skb_set_tunnel_key`'s `remote_ipv4` is host-order (the kernel does
  `cpu_to_be32`). Filled with `binary.BigEndian.Uint32(ip4)`.
- `locals` keys are `{net id, pod IP}`, the IP in **network byte order** too
  (the C side keys on `ip->daddr`); see `datapath.localKey`.

This byte-order contract is locked by `datapath/keys_test.go`, which asserts the
keys marshal to the address in network order regardless of host endianness — so
an accidental endianness flip fails the build, not just a packet at runtime.

### IPv6 / dual-stack — unified 128-bit keys (in progress)

The API is already family-agnostic (`VPC.cidrs`, `Port.ip`, … are strings), so
IPv6 is a datapath change, not an API one. Every map address widens from a
`__u32` to a **128-bit** field. There is one map set, not a v4 set beside a v6
set — the maps stay keyed by `{net_id, address}`, only wider. `net_id` (the VNI)
is the scope, exactly as before; the address is now 16 bytes in network order (a
v6 LPM key is `{prefixlen, scope_net, addr[16]}`). The delivery hooks parse
either family, read src/dst as 128-bit, and drive the same lookups.

`addr128_eq` and `addr128_zero` compare the 16 bytes as two `__u64`s under a
single branch, never as a byte loop with an early return: sixteen branches leave
the verifier sixteen fall-through states, and each re-explores the rest of the
caller. Two of these guards sit near the top of `from_pod`, and the byte-loop
form alone accounted for 93% of that hook's verifier cost — 485k states against
a 1M ceiling (see field note 12). Keep new address predicates branch-flat.

**A v4 address is stored in its RFC 6052 (NAT64) form**, `64:ff9b::a.b.c.d` (the
v4 in the low 32 bits under a `/96` prefix), *not* the RFC 4291 IPv4-mapped
`::ffff:a.b.c.d`. The difference matters for the future: `::ffff:` is a
representation form the IPv6 stack will not route on the wire, so a v6 pod could
never use it to reach a v4 pod; `64:ff9b::` is an ordinary global v6 address
built for exactly that. Storing v4 in the NAT64 form means a later cross-family
translator — a v6 pod addressing a v4 pod as `64:ff9b::v4` — will *match the
stored map entry*, so cross-family peering becomes a translation problem to solve
rather than one the representation forecloses. The prefix is the well-known
`64:ff9b::/96` for now; RFC 6052 network-specific prefixes (appropriate for the
private v4 tenants actually use) are a later config knob, so it lives behind one
constant.

**Mixed-family multi-tenancy falls out for free**, which is the main reason for
unified keys over parallel maps. Tenant A can run a v4 VPC and tenant B a v6 VPC
in the *same* cluster and the *same* maps: A's pods are `64:ff9b::10.x` entries
under net X, B's are native `fd00::x` under net Y — distinct 128-bit values,
distinct nets, no possibility of collision (and no second map set to keep in
sync). A dual-stack VPC's pod simply has two entries, one per family, under its
one net. Peering *across* families (a v4 VPC ↔ a v6 VPC) still needs a NAT64-style
translator and is deferred — but, per the representation choice above, it is *not*
precluded: same-family peering works today, cross-family is future work the map
layout already accommodates.

The transport is unaffected: v6 VPC traffic rides the existing Geneve underlay as
a v6 inner packet under a v4 outer (the tunnel key stays the node's v4 IP), so v6
VPCs work on a v4 cluster. What v6 *north-south* needs (a v6 fabric IP for a pod)
is a dual-stack cluster (v6 node pod CIDRs); the overlay does not.

Built in two steps so neither is debugged against the other: **(1)** re-key every
map and the Go marshaling to 128-bit with v4 stored v4-mapped, still parsing only
v4 — the v4 e2e must stay green, proving the plumbing; **(2)** add v6 parse +
overlay delivery on top.

Step 2's parse is one `parse_ip` that reads either an IPv4 or IPv6 frame into a
`struct pkt {is_v6, proto, src, dst}` — both addresses already the 128-bit map
key (v4 in NAT64 form, v6 native). It *copies* the addresses onto the stack, so
they survive any later in-place NAT rewrite that would invalidate a header
pointer. Each of the three delivery hooks (`from_pod`, `to_pod`, `from_overlay`)
then drives the same `net_of` / `local_of` / `remote_of` / `encap` lookups
regardless of family — `from_overlay` never touches L4, so it is entirely
family-agnostic; `from_pod`/`to_pod` gate their **v4-only** branches behind
`!is_v6` and re-derive the `struct iphdr *` there. Those v4-only branches are the
`169.254.1.1` fabric bridge (`bridge_forward`/`bridge_reverse`) and the floating
NAT (`floating_forward`/`floating_egress_snat`) — all of which rewrite IPv4
checksums or advertise via ARP. A v6 packet skips straight to overlay delivery;
the fabric-IP lookups it would otherwise reach (`bridge_of`) can only ever hold
v4 keys, so they miss harmlessly. `from_uplink` stays v4-only (floating-IP
ingress + ARP): a v6 frame there is left to the kernel.

One wrinkle the overlay path forced: v6 neighbour discovery *is* an IPv6 packet,
whereas v4 ARP is not and so never reaches these hooks. A pod resolving its
on-link gateway sends an NS to that gateway's solicited-node **multicast**, which
—being off-net from the VPC's point of view—the isolation rule would drop.
`v6_link_scoped` short-circuits link-local (`fe80::/10`) and multicast
(`ff00::/8`) to `TC_ACT_OK` in both `from_pod` (on dst) and `to_pod` (on src):
that traffic never leaves the pod↔host-veth link, so the kernel and the host veth
handle it. The host veth **owns** `fe80::1` (assigned outright, not proxied):
Linux NDP *proxy* does not answer for link-local targets, so unlike v4's
`proxy_arp` for `169.254.1.1`, the gateway address is a real address on the veth.

The upshot is v6 gets **intra-VPC and cross-node overlay delivery, isolation, and
same-family peering** for free — everything that flows through the overlay path,
including ICMPv6 east-west (the delivery path never inspects L4). The v6 fabric
bridge (north-south), v6 floating IPs (NDP responder), and v6 gateway egress are
later phases.

### IPv6 north-south — the v6 fabric bridge (planned)

East-west v6 works on a v4 cluster; **north-south v6 needs a dual-stack cluster**,
because a pod's reachable fabric IP comes from the node pod CIDR, and only a
dual-stack cluster gives nodes a v6 pod CIDR. With that, the design is the exact
parallel of the v4 fabric bridge (`bridges` map, `ct_fwd`/`ct_rev` conntrack — all
already `addr128`-keyed and reusable across families), with three v6-specific
points:

- **Checksums differ.** IPv6 has *no* header checksum, so a v6 address rewrite
  never touches an L3 csum (there is none). But TCP, UDP, *and* ICMPv6 all carry
  the address in their pseudo-header checksum — including ICMPv6, unlike ICMPv4,
  whose checksum ignores the IP header. So `nat_addr6` fixes only the L4 csum, but
  must fix it over the full **16-byte** address change (eight 16-bit words via
  `bpf_l4_csum_replace`), for every L4 proto including ICMPv6. Header offsets use
  the fixed 40-byte IPv6 header (no options): L4 at `ETH_HLEN + 40`.

- **The masquerade gateway is `fe80::1`** (the address the host veth already owns),
  the direct analog of `169.254.1.1`. `to_pod` DNATs fabric→VPC and masquerades
  the client to `fe80::1:gw_port`; the pod replies to `fe80::1`, which `from_pod`
  reverses. This collides with the `v6_link_scoped` bypass above — a reply to
  `fe80::1` is link-local — so `from_pod` must test `dst == fe80::1` (unicast to
  the gateway → `bridge_reverse6`) **before** the link-scoped short-circuit. NDP
  never conflicts: it is to the solicited-node *multicast*, not unicast `fe80::1`.

- **ICMPv6 echo** is type 128/129 (not v4's 8/0); the echo identifier stands in
  for the L4 port in conntrack exactly as for v4, but its rewrite also touches the
  ICMPv6 (pseudo-header) checksum.

A v6 VPC pod then reports its v6 fabric IP as `status.podIP` (kubelet probes,
Services), the CNI programs the v6 `/128` fabric route + `bridges` entry it
currently skips, and a dual-stack e2e proves a default-network client reaching a
v6 pod's fabric IP (TCP + ICMPv6), including under overlapping v6 CIDRs.

## 4. Control flow

### Bootstrap order & invariant

**Invariant:** the default-network path depends only on the core API (Node
objects) and node-local config — never on the VPC API or Services. So bootstrap
is: kube-proxy/Cilium (hostNetwork, no CNI) → cozyplane-agent (brings up the flat
network, nodes go Ready) → CoreDNS / controller / workloads → VPC API usable.

### CNI ADD

The plugin (`cmd/cni`) is a thin host-side binary. It reads the pod's
namespace/name from `CNI_ARGS`, then:

- **default path** (`addDefault`): delegate IPAM to the upstream `host-local`
  plugin with the range injected from the node pod CIDR (published by the agent
  in `/run/cozyplane/agent.json`); create the veth; record net id `0`.
- **VPC path** (`addVPC`): parse the pod's `sdn.cozystack.io/vpc` annotation —
  `[<owner-ns>/]<vpc>`, owner namespace defaulting to the pod's (`parseVPCRef`) —
  then **enforce default-deny** (`requireVPCBinding`): a `VPCBinding` in the
  pod's namespace must reference that VPC, or ADD fails. Only then `Get` the VPC
  (must be `Ready`), `claimIP`, and create the veth with the VPC IP and net id.
- **gateway path** (`addGatewayLeg`, on top of the default path): the
  `sdn.cozystack.io/gateway-for` annotation gives the pod a *second* interface
  (`eth1`) carrying the VPC's reserved `.1`. Authorization is by placement:
  the pod must be in the agent's own namespace (published in the agent state —
  only the cozyplane controller creates pods there) and the VPC must have a
  pool-less `nat.enabled` `VPCGateway` (a gateway *with* a pool needs no pod at
  all — see below). The `.1` Port is claimed like any other, marked
  `spec.gateway`; the leg gets the VPC CIDR routed via the proxy-arp'd
  link-local hop (onlink), `ip_forward` is enabled in the netns, and the host
  side is a normal VPC port with the gateway flag (ports bit 31).

`claimIP` is the IPAM design point: it lists the VPC's `Port`s, picks the lowest
free address starting at network+2 (`.0` network and `.1` gateway reserved), and
**creates a cluster-scoped `Port` named `v<vni>.<ip-dashed>`**. The name is keyed
by the globally-unique VNI so it stays unique even though VPC names are only
unique per namespace; because the name encodes the IP, etcd name-uniqueness makes
the claim atomic — concurrent allocators on different nodes that pick the same IP
collide on `AlreadyExists` and retry the next one. No server-side allocator is
needed. (`cmd/cni/main_test.go` locks the address selection, naming, labels, the
retry, and the default-deny check.)

Both paths finish in `setupVeth` → `configurePodIface` (pod side: `/32` address,
link-local `169.254.1.1` default route) and `configureHostVeth` (host side:
`proxy_arp`, `/32` route to the pod, attach the classifier, write `ports`).

### CNI DEL

Clear `ports[ifindex]`; delete the pod's `Port`(s) (found by the pod-identifying
labels); release host-local IPAM (no-op for VPC pods); delete the veth (which
also removes the tc filter).

### Agent reconciliation

The agent runs four informers, all best-effort except Nodes (the sdn ones share
one informer factory):

- **Nodes** → `remotes[node.podCIDR] = node.InternalIP` (skip self). Default
  network reachability.
- **VPCs** → `networks[vpc.cidr] = vpc.vni` when the VNI is assigned.
- **Ports** → `remotes[port.ip/32] = port.nodeIP` for ports on other nodes. VPC
  pod reachability. (`Port.spec.nodeIP` is filled by the plugin from the agent
  state, so no node-name→IP lookup is needed.) A **local** port turning
  *terminating* (the CNI creates every Port with the
  `sdn.cozystack.io/sever` finalizer, so deletion pauses there) is the
  revocation path: if the owning pod is still alive — same name, same UID, not
  terminating — the agent severs the live datapath (`datapath.SeverLocal`): it
  reassigns the pod's `ports` entry to `QuarantineNet` so `from_pod`/`to_pod`
  drop both directions, drops the `locals` entry, and tears down the bridge.
  Then it releases the finalizer, letting the deletion complete. Because the
  Port stays terminating until acknowledged, a revocation that lands while the
  agent is down replays from the informer's initial sync on restart.
- **VPCPeerings** → the `peers` map. Every peering or VPC event triggers a full
  recompute (`desiredPeerPairs`): a VNI pair is programmed iff two halves
  mutually reference each other and both VPCs have VNIs. The desired set is
  diffed against the *pinned map itself* (not shadow state), so a restarted
  agent prunes pairs whose peerings vanished while it was down; one
  unconditional resync runs at cache sync for the same reason. Deliberately
  not keyed on the controller's status: severing must happen at watch latency
  even if status is stale, and the reciprocal grant's presence is the
  authorization.
- **Gateway Ports** (`spec.gateway`) → the `gateways` map, same resync/diff
  pattern: per VNI, the gateway's `.1` address plus its node (0 when local —
  each agent programs its own view). The VNI is parsed from the Port name
  (`v<vni>.…`, the documented naming contract).

With `--cluster-cidr` set the agent provides the cluster-egress masquerade:
pod CIDRs aren't routable outside the cluster, so without it no default-network
pod — including a gateway forwarding tenant traffic — has an internet return
path. `--masquerade` selects the implementation ([#10](../../issues/10)):

- **`bpf` (default)** — SNAT in the eBPF datapath, no netfilter. `from_pod` at
  the **uplink egress** (already attached there) rewrites a packet whose source
  is in the `masq_srcs` LPM (the pod CIDRs) and whose destination is not
  internal: source → the node IP (`params[CFG_NODE_IP]`), source port → a
  masquerade port from the same `ct_fwd`/`ct_rev` machinery as the north-south
  bridge, reused with `net=0` and inverted roles (`vpc_ip`:=remote address,
  `fabric_ip`/`client_ip`:=pod address) so the map ABI is unchanged. Masquerade
  ports come from **16384–32767** — disjoint from the host's ephemeral range
  (32768+), so a reverse lookup can never capture the node's own connections.
  `from_uplink` at the **uplink ingress** un-SNATs matching replies *before*
  netfilter ever sees them, then hands off to the kernel: its conntrack saw the
  original pod-sourced flow leave through FORWARD, so the un-SNAT'd reply
  matches ESTABLISHED and no INVALID drop can fire even under kube-proxy. ICMP
  echo masquerades by identifier, and inbound ICMP *errors* (frag-needed — the
  pod's PMTU signal for its own egress) are translated with the same
  embedded-header rewrite the bridge uses. **Both families**: the v6 pair
  (`masq_snat6`/`masq_reverse6`, node v6 address in the `node_ip6` map) gives
  pod ULAs — including a v6 VPC gateway's forwarded tenant traffic — an
  off-cluster return path, which the kernel rule never did. TCP/UDP/ICMP
  (other protocols don't egress — same practical envelope as before).
- **`iptables`** — the classic `-s <clusterCIDR> ! -d <clusterCIDR> -j
  MASQUERADE` kernel rule (with RETURNs for cozyplane-owned egress interfaces),
  for clusters that prefer netfilter to own NAT.
- **`off`** — the environment masquerades elsewhere.

Net effect of the pair: **cozyplane touches netfilter only if the cluster's
kube-proxy does.**

### Map-ABI upgrades — pinned-map reconcile & local-state rebuild

DNS discovery, node-address advertisement and missing-FabricIP repair each
use a five-second child operation deadline. The repair budget covers the Pod
list and all claim reads/creations together. A shorter parent remains effective;
every return cancels the child without cancelling the agent. Failed repair
preserves foreign claims and reports through the existing startup warning.
Informer synchronization remains a separate readiness condition. Real stalled
HTTP tests cover all five request stages, shared repair budget, shorter parents
and 125 cancellations with stable descriptors/goroutines. The repair skips Pod reads when no unambiguous rebuilt address is usable.
It requests only local Running Pods, in pages of 128 with a 65,536-object/512-page
budget under the same total operation deadline. The temporary selection retains
only matching addresses and Pod identities, not historical Pod specifications
or annotations. A failed, expired, cancelled or malformed page publishes no
repair authority, and conflicting live Pod identities for an address are omitted.
Claim operations start only after the complete bounded snapshot succeeds; repair
never deletes or adopts a foreign claim. Real HTTP tests exercise continuation,
filtering, ownership, incomplete snapshots and deadlines. A measured SDK fixture
with 1,024 completed Pods and one Running Pod reduces transient allocations from
about 34 MB to 30 KB per snapshot; this is not a permanent heap leak claim. The full Linux agent/IPAM suites pass with the race detector, including the
existing 125 cancellation/resource-lifetime checks; no deployment is implied.

A separate route-rebuild review remains open: a VPC address may equal its
fabric allocation. The CNI installs main-table VPC host routes only for the
default network; VPC bridge host routes therefore must not be rejected merely
because their address also appears in the VPC alias. Verify this with real
isolated IPv4/IPv6 host routes before changing reconstruction authority, and
refuse ambiguous or non-owned candidates.

Maps are pinned by name and reused across restarts, so a release that changes a
map's shape (the 128-bit rekey was the first) cannot reuse the old pins: the load
fails and, before this mechanism, the agent crash-looped until the node was
rebooted to clear bpffs ([#7](../../issues/7)). The agent now handles it:

- **Reconcile pins at load.** Before loading, the agent checks every
  pinned-by-name map spec against whatever is pinned under `PinRoot`
  (`MapSpec.Compatible` — the same test map reuse applies) and **removes
  incompatible or unopenable pins**, so the load creates fresh maps. Removing a
  pin is invisible to running pods: the tcx links on their veths keep the old
  program → old map objects alive until re-attach below.
- **The host veth alias is the rebuild record.** `configureHostVeth` stores
  `cozyplane:1;net=…;gw=…;mac=…;ips=…` — exactly the `ports`/`locals` payload —
  as the veth's link alias at ADD. It is host-local (no API dependency), survives
  agent restarts, and dies with the veth. Nothing else persists this state:
  `locals`/`bridges`/`ports` are CNI-written and are *not* derivable from the
  agent's watches (default-network pods have no `Port` object at all).
- **Rebuild + re-attach at every agent start.** The agent walks the `cph*`/`cpg*`
  links: parses the alias and re-`Put`s the `ports` and `locals` entries;
  re-derives a VPC pod's `bridges` entry from its unique owned, gatewayless main-table host route (/32 or /128);
  ambiguous routes do not authorize reconstruction; then points both
  tcx links at the freshly pinned programs. The link is **adopted and its program
  swapped in place** (`Link.Update`), never replaced by a second link, so there is
  never an unfiltered window *and* never a second generation — see "one link per
  hook" below. Running this unconditionally
  (not just after an ABI break) also closes a second gap: previously an existing
  pod kept executing the *previous release's* program until the pod was
  recreated.
- **One link per hook — the datapath must never run two generations.** tcx is a
  program *list*: attaching a second link at a hook does not replace the first,
  it queues behind it, and the **older link runs first**. The agent therefore
  never attaches on top of itself. `ensureTCX` queries what is already attached
  at `(ifindex, direction)`, adopts the cozyplane link it finds and `Update`s its
  program to the current one, detaches any further cozyplane links, and only
  attaches fresh when the hook carries none of ours. Foreign tcx links (Cilium's)
  are identified by program name and left strictly alone.

  This replaces an assumption that proved false in the field: that removing a
  tcx link's bpffs pin drops its last reference and detaches it. On Linux 6.8 it
  does; on 6.18 (Talos) it does **not**. An agent rollout there left the previous
  generation attached at `from_uplink`, `from_overlay` and every pre-existing
  pod veth, ahead of the new one and reading map objects nothing updated any
  more — a datapath split in half. `DetachVeth` (CNI DEL) asks the kernel to
  detach for the same reason, rather than only unlinking the pin.
  See [bringup-field-notes.md](bringup-field-notes.md) §9.

- **The program pins are swapped, not re-made.** `cozyplane_from_pod` /
  `cozyplane_to_pod` are pinned **pin-aside-then-rename**, so the path is never
  absent. The CNI plugin opens them on every ADD, and a remove-then-pin gap is
  not theoretical: it failed ~250 sandbox creations during one agent rollout.

- **Live TCX ordering fails closed.** Moving the same program in the TCX list
  requires detaching its old link; the kernel rejects a second attachment of
  that program. Before replacing an existing pin, install a separately pinned
  two-instruction DROP guard at the head. Keep it on attach/pin failure and
  remove it only after the replacement is pinned. Subsequent reconciliation
  retries recovery; a completed replacement also clears a guard left by an
  interrupted process. DEL removes both ordinary links and their guards.
  This trades a brief packet drop during a move for continuous isolation and
  bounds retained guard pins to one per interface and direction, plus a
  temporary swap pin during publication. Serialize hook queries, guard removal
  and swaps with the shared writer lock across agent/CNI processes; confirm
  each scanned veth alias before changing its hooks. Explicit link detachment
  avoids waiting for deferred kernel link destruction before a same-program
  retry.
- **Detached TCX pins are reaped.** Interface deletion detaches its TCX links
  but does not remove their bpffs pins; a missed DEL otherwise retains the link
  and program objects indefinitely. The periodic hook reconciliation streams
  the owned links directory in small batches and removes only links whose
  kernel TCX info reports ifindex zero. Inspect and unpin under the shared
  writer lock, retaining active pod, uplink and overlay hooks even without a
  rebuild alias. No historical interface-ID cache is retained.
- **The one-release gap.** A veth without the alias (created by a pre-alias CNI)
  cannot be rebuilt; after an ABI break such pods need a restart, and the agent
  logs each one. On a compatible restart they are unaffected — state lives in the
  maps, which are reused.
- **The walk also heals mis-masked veth addresses.** An early CNI wrote
  `fe80::1/0` (an 8-byte CIDRMask on the 16-byte address), whose on-link ::/0
  route — `default dev <veth>`, metric 256 — outranks a host's RA default and
  hijacks node v6 egress. The rebuild replaces it with the intended /64.
- **Stale entries are pruned, not just re-put.** A pod that dies uncleanly (its
  netns vanished, no CNI DEL) leaves `ports`/`locals`/`bridges` entries behind;
  a stale `locals` entry is not just a leak — once its VPC IP is reallocated to
  a pod on another node, the dead local entry shadows the remote route and
  blackholes same-node senders. The rebuild prunes any entry whose veth+alias
  witness is gone, checked per entry against the kernel at decision time — and
  because the CNI writes the alias *before* the map entries, a concurrently
  ADDed pod can never be falsely pruned.
- `ct_fwd`/`ct_rev` across an ABI break are recreated empty: established
  bridge/floating flows reset once, like a conntrack flush. Acceptable.

Net effect: **an upgrade across a map-ABI change is a rolling DaemonSet update** —
no node reboots ([#7](../../issues/7) acceptance).

### Controller

`VPCReconciler` assigns a monotonically increasing VNI ≥ 100 to any
VPC without one, and sets `status.phase = Ready`. Before publishing status it
reserves the identifier by resourceVersion CAS in the durable Lease
`kube-system/cozyplane-vni-allocator`, annotation `sdn.cozystack.io/last-vni`.
Reservations survive VPC deletion, controller restart and failed status writes;
identifiers are never recycled while delayed watches or pinned datapath state
could still refer to a previous tenant. Bootstrap seeds the counter above all
live VPC VNIs and Port/ServiceVIP claim names. The counter must be backed up and
must never be deleted or rolled back independently of the cluster's SDN state.
VNIs stay below `2^22` because the two high Geneve bits carry forwarding/gateway
flags; exhaustion or malformed counter state fails allocation closed.
The allocation list goes to the
**API server directly (`APIReader`), never the informer cache**: the cache lags
the reconciler's own status writes, so back-to-back reconciles of two fresh VPCs
could both see a VNI as free and assign it twice — a **cross-tenant isolation
break** (two VPCs sharing a network id are one delivery domain, and a peering
whose CIDRs collide then overwrites the victim's own `networks` entry). Caught
live in the e2e once the map-recreation phase re-tested a VPC late enough.
Reconciles are serial (default MaxConcurrentReconciles=1), and the counter CAS
also prevents concurrent reservations from colliding. The reconciler **repairs duplicates**
(pre-fix clusters): if another VPC holds the same VNI, the deterministic loser —
younger by creationTimestamp, then namespace/name — clears its VNI and
reallocates; the winner keeps it. A conflicting status update just requeues.

`VPCBindingReconciler` holds each `VPCBinding` with a reap finalizer. On deletion
it deletes the `Port`s for `(consumer-namespace, vpcRef)` — unless another live
binding in that namespace still authorizes the same VPC — then removes the
finalizer. Deleting the Ports is what drives the agents' sever above (and the
remote-route cleanup on other nodes). (`*_controller_test.go` lock the VNI
selection, the finalizer lifecycle, the reap, and the another-binding-keeps-alive
rule.)

`VPCPeeringReconciler` is status-only (the agents program the datapath from the
halves' specs): it marks a half `Ready` when a reciprocal half exists and both
VPCs are Ready, surfaces `PeerMatched`/`VPCReady`/`PeerVPCReady` conditions and
the peer's VNI, and reverts to `Pending` when either input goes away. It watches
VPCPeerings (each half re-enqueues its reciprocal) and VPCs (each VPC re-enqueues
the halves referencing it). No finalizer — deleting a half has nothing to reap.

`PortGCReconciler` handles the two abandoned-Port cases the normal lifecycle
misses:

- it releases the sever finalizer from *terminating* Ports whose node no longer
  exists — the agent that would acknowledge is never coming back, and the
  workload died with its node;
- it **deletes live Ports whose claimant pod is gone or terminal** (the pod recorded in the
  Port's pod labels no longer exists, or its UID differs — the name was reused
  by a new pod, or its phase is Succeeded/Failed). A pod that dies uncleanly (node reboot, forced eviction) never
  runs CNI DEL, so its Port leaks; for an ordinary pod that leaks an address,
  but for a **gateway pod it wedges the replacement forever** — the fixed `.1`
  claim fails `AlreadyExists` and the pod stays ContainerCreating. GC frees the
  name; the kubelet's next ADD retry claims it fresh. VM persistent Ports
  (`vm-name` label) are exempt — the PersistentPortReconciler owns their
  lifecycle, and a launcher pod's absence there must *not* release the pinned
  IP+MAC. Deletion still passes through the sever finalizer, so the owning node
  drains first (or PortGC's node-gone path releases it). Before deleting, the
  claimant's absence or terminal phase is confirmed against the API server directly — the
  informer cache could lag a *just-created* pod and GC would otherwise kill a
  newborn Port.

`GatewayReconciler` realizes a **pool-less** `VPCGateway` as a per-VPC gateway
Deployment (`cozyplane-gateway-<vni>`) in the system namespace. A gateway that
*has* a pool is realized in eBPF instead — `vpc_nat_snat` SNATs at each pod's own
veth to the VPC's own address, so the reconciler **deletes** the Deployment once
`status.natAddress` is set (docs/north-south.md). The pod path is: a privileged
pod running `cozyplane-gateway` with the `gateway-for` annotation, Recreate
strategy (the `.1` Port claim cannot roll). Deletion (egress disabled or VPC
gone) finds Deployments by VPC labels — the VNI-derived name is unknowable
after the VPC is deleted, and a cross-namespace ownerRef is not an option.
Deployment events map back to their VPC, so a manually deleted gateway
self-heals.

### Why the plugin needs a kubeconfig

The plugin runs in the host mount namespace and can't read the agent pod's
service-account files, so the agent materializes a self-contained kubeconfig
(embedding its SA token + CA) at `/run/cozyplane/kubeconfig`
(`datapath.WritePluginKubeconfig`). The plugin uses it for the VPC lookup and
Port claims. The kubeconfig references a **tokenFile** (`/run/cozyplane/token`)
rather than embedding the token: bound SA tokens expire (~1h) and kubelet
refreshes the projected file, so the agent re-syncs the host-visible copy every
minute and the short-lived plugin reads it fresh per invocation.

## 5. Code structure (package by package)

```
bpf/overlay.c              the eBPF datapath (one tc program + four maps)
bpf/vmlinux.h              CO-RE kernel types (generated by bpftool; gitignored)

datapath/                  Go wrapper around the eBPF datapath
  bpf.go                   //go:generate bpf2go directive
  overlay_bpfel.{go,o}     generated bindings + compiled object (committed)
  datapath.go              Manager: Load/pin, Geneve device, remotes/networks
                           maps, uplink attach, LPM key/byte-order helpers
  attach.go                tcx link attach/detach (ingress/egress), pinned
  ports.go                 plugin-side access to the pinned `ports` map
  locals.go                plugin-side access to the pinned `locals` map
  peers.go                 agent-side access to the pinned `peers` map
  gateways.go              agent-side `gateways` map + from_overlay attach
  bridge.go                fabric /32 route + the pinned `bridges` map
  firewall.go              FORWARD ACCEPT + node masquerade (go-iptables)
  bpffs.go                 mount bpffs if absent (kind nodes)
  state.go                 AgentState published for the plugin (agent.json)
  kubeconfig.go            write the plugin kubeconfig from the SA token
  paths.go                 pin paths, device name, OverlayMAC, constants

cmd/cni/main.go            CNI plugin (ADD/DEL/CHECK), default/VPC/gateway paths
cmd/agent/main.go          node agent: datapath bring-up + sdn API watches
cmd/gateway/main.go        per-VPC egress gateway (forward + filter + SNAT)
cmd/sdn-controller/main.go controller-runtime manager
cmd/apiserver/main.go      aggregated API server entrypoint (scaffolded)

internal/controller/sdn/   VPCReconciler (VNI assignment), VPCBindingReconciler
                           (revocation reap), VPCPeeringReconciler (status),
                           GatewayReconciler (egress gateway Deployments)
internal/cmd/server/       aggregated apiserver options/wiring (start.go)
internal/setup/            apiserver group registration + openapi merge

api/sdn/                    internal types + register + install
api/sdn/v1alpha1/           versioned VPC/Port types (kubebuilder markers)
pkg/apiserver/              apiserver framework (scheme, codecs, JSON codec)
pkg/registry/               REST storage (vpc, vpcbinding, vpcpeering, port)
pkg/generated/sdn/          generated clientset/informers/listers/openapi

config/crd/                 generated CRDs (how VPC/Port are served today)
deploy/                     agent DaemonSet, controller Deployment, RBAC
hack/                       codegen scripts; Makefile drives generate/build
```

### The two code lineages

- **Datapath / CNI** (`bpf/`, `datapath/`, `cmd/{cni,agent}`,
  `internal/controller`) is the working prototype.
- **Aggregated API server** (`pkg/apiserver`, `pkg/registry`, `internal/cmd`,
  `internal/setup`, `cmd/apiserver`) is the design-target serving path: the CNI
  chart ships the group as bootstrap CRDs, and the separate cozyplane-apiserver
  chart takes serving over via its APIService (control-plane.md).

## 6. Build & codegen

- **eBPF:** `go generate ./datapath` runs `bpf2go` (needs `clang`); `bpf/vmlinux.h`
  is produced by `bpftool`. The compiled `overlay_bpfel.o` is committed and
  embedded via `go:embed`, so plain `go build` needs no clang.
- **Kubernetes codegen:** `hack/update-codegen.sh` (deepcopy/conversion/defaults
  for the aggregated apiserver, plus clientset/informers/listers/openapi). The
  CRDs come from `controller-gen` over the kubebuilder markers.
- `make generate` runs the codegen; `make build` builds the binaries into `bin/`;
  the multi-stage `Dockerfile` builds all four binaries and bundles the upstream
  `host-local`/`loopback` plugins and `iptables`.

## 6a. The agent's memory is mostly eBPF maps, not heap

**Read this before you touch a map's `max_entries`, and before you believe a
memory graph.**

Since Linux 5.11 a BPF map's memory is charged to the **memory cgroup of the
process that created it** — so every pinned map cozyplane loads is charged to the
*agent's* container, for as long as the agent lives. And most of them are
**preallocated at load**: a `BPF_MAP_TYPE_HASH` or `LRU_HASH` without
`BPF_F_NO_PREALLOC` allocates all `max_entries` up front, whether or not a single
entry is ever written.

The footprint is dominated by a handful of maps:

| map | entries | preallocated? |
|-----|---------|---------------|
| `ct_fwd`, `ct_rev` | 262,144 each | yes (LRU) |
| `svc_fwd`, `svc_rev` | 262,144 each | yes (LRU) |
| `np_ct` | 131,072 | yes (LRU) |
| `np_allow`, `remotes` | 524,288 / 131,072 | no (LPM, on demand) |

That is ~100MB+ of kernel memory before a single packet is forwarded. **PERCPU**
maps are the sharp edge: a preallocated entry costs `value_size × nr_cpus`, so
growing a PERCPU value silently multiplies by the machine's core count.

### The failure mode, and why it is so hard to debug

The agent gets **OOM-killed while its RSS is ~10% of the limit**. Both numbers are
true at once:

- `container_memory_rss` counts **anonymous pages** — the Go heap. It looked fine
  (28MB against a 256Mi limit) right up to the kill.
- `container_memory_working_set_bytes` is what the **OOM killer** measures, and it
  **includes the kernel charge** — i.e. the maps. That was at the limit.

So the metric everyone habitually graphs is exactly the one that cannot see this.
The `dmesg` line says it plainly if you look — `anon-rss:28032kB` next to a
cgroup OOM — but nothing on a dashboard does.

**The signal:** `working_set_bytes` near the limit while `rss` (and
`container_memory_cache`) stay small. The difference is kernel/slab memory.

**The specific answer:** the agent publishes
`cozyplane_bpf_map_memlock_bytes{map=...}` (and `..._total`), read from the
kernel's own accounting in `/proc/self/fdinfo/<map fd>`. It names the map, so you
do not have to infer it. If the agent is being OOM-killed, look there first.

### Rules of thumb

- Do not preallocate a map that will hold tens of entries. Add
  `BPF_F_NO_PREALLOC` and size `max_entries` for the ceiling, not the budget.
  (Maps written only from userspace — `float_announce`, `vpc_counters` — cost
  nothing on demand.)
- Treat a PERCPU value-size increase as a per-core multiplication.
- The agent's memory **limit** must be sized for the map footprint, not for the
  Go heap. It is `512Mi`; `256Mi` was marginal for years-worth of maps and finally
  broke when ~8MB of new ones landed.

## 7. Known limitations / divergence from the design

TCP SYNs crossing a VPN route or a Geneve north-south path have an oversized
MSS option reduced by eBPF with an incremental TCP checksum update. This is a
bounded option parser and is a no-op for malformed packets, absent/smaller MSS,
SYN+ACK, UDP and ICMP; PMTU remains responsible for all other traffic.

Most of the design has since been built (all three policy layers, the north-south
boundary, Services, live migration, multi-tenancy). What remains divergent or
rough, as built:

- Overlapping VPC CIDRs are supported (net-scoped delivery, above); only
  *peering* overlapping VPCs is refused.
- The north-south bridge is eBPF NAT (its own `ct_fwd`/`ct_rev` table): TCP, UDP,
  ICMP echo (ping), and — for IPv4 — **ICMP errors** (dest-unreachable incl.
  frag-needed, time-exceeded, parameter-problem), for both fabric IPs and
  floating IPs. An error's *embedded* IP+L4 header is rewritten through the same
  NAT as the flow it describes (masq bridge: ct-keyed on the embedded `gw_port`;
  floating: stateless address swap), with every changed byte folded into the
  outer ICMP checksum — a receiver verifies that checksum, so a bad rewrite
  self-detects as a drop. Outward errors give clients port-unreachable and
  working UDP traceroute; inward errors deliver frag-needed to the pod, so
  IPv4 PMTU discovery through the bridge works (#3). Embedded *TCP* checksums
  beyond the 8 guaranteed L4 bytes are left untouched (Linux correlates errors
  by addresses+ports, not embedded checksums). **ICMPv6 errors** (dest-unreach,
  packet-too-big — the v6 PMTU signal, vital since v6 never fragments in
  flight, time-exceeded) traverse the v6 bridge the same way: outer address
  rewrites ride the ICMPv6 pseudo-header via `nat_addr6`, the embedded v6
  header has no checksum of its own, and the embedded (mandatory) UDP checksum
  is recomputed over its pseudo-header. Errors about echo flows and embedded
  packets behind extension headers are not translated.
- **Netfilter is now conditional** ([#10](../../issues/10), closed). The tenant
  datapath is netfilter-free; the cluster-egress masquerade moved to eBPF
  (`--masquerade=bpf`, the default), and the FORWARD-ACCEPT pair installs only where
  kube-proxy's `KUBE-FORWARD` chain exists — so cozyplane touches netfilter only if
  the cluster's kube-proxy does. It cannot be removed *entirely* under an iptables
  kube-proxy: ClusterIP replies must traverse the client node's conntrack. The
  pool-less gateway pod's internal filter still runs in its own netns.
- VPC egress is opt-in via a `VPCGateway` (`nat.enabled`), and coarse: it opens the
  internet, with no per-destination policy beyond SecurityGroups and no metadata
  endpoint yet. LoadBalancer ingress into a VPC is default-deny until the gateway
  admits it. A metadata endpoint is still missing (docs/vm-provisioning.md).
- The tenant API (`sdn.cozystack.io`) is served **only** by the aggregated
  apiserver — there is no CRD mode and no `apiserver.enabled` switch. Only
  `local.sdn.cozystack.io` (`FabricIP`) is a CRD (docs/api-groups.md).
- VNI allocation and Port IP selection are list-then-pick (atomic at the claim, but
  not high-concurrency optimized). (The plugin's kubeconfig token *is* refreshed
  now — it references a host-visible tokenFile the agent rewrites as kubelet
  rotates the projected SA token.)
- **A pool-less `VPCGateway` still launders.** `poolRef` is optional, so a
  `nat.enabled` gateway without one has no address to wear: it falls back to a
  gateway pod whose egress is SNATed to its fabric IP and then again to the
  *node's*, making the tenant indistinguishable from the platform on the wire —
  the one thing the eBPF VPC NAT exists to prevent. Requiring `poolRef` would
  delete `cmd/gateway` outright; open (docs/north-south.md).

### Security audit follow-up (2026-10-07)

Live, non-terminating VPCBindings are the authorization source for existing Ports, forwarding grants, DNS queries and annotated Services. An API/configuration error fails closed. Endpoint selection requires the actual Port VPC and matching Pod UID when the EndpointSlice provides one. VM Ports bind to a protected VMI controller reference and its UID; VM labels alone are insufficient. Legacy Ports without an authenticated VMI UID require explicit repair or recreation. Kubernetes OwnerReferencesPermissionEnforcement must be enabled.

Fallback gateway workloads live in the trusted system namespace. Cross-namespace ownership is recorded using the VPC UID; labels and generated names alone do not authorize adoption, modification or deletion. Legacy unmarked gateway Deployments require operator repair/recreation. The fallback container uses only NET_ADMIN and NET_BIND_SERVICE, disables privilege escalation and service-account-token mounting, and uses the runtime default seccomp profile. The CNI enables forwarding before container start; the gateway checks its value before attempting a write.

Port and ServiceVIP creation now checks both etcd keys in the same transaction as the write. They must use the same etcd backend; split resource overrides are rejected at startup. Ordinary codec/encryption, object versioning, watches and CRUD remain those of the registry. This replaces the non-atomic cross-kind lookup as the allocation authority. Existing conflicting claims still require reconciliation before rollout.

### FabricIP sandbox ownership (2026-10-07)

GC event lookup uses a cache index on the recorded Pod namespace/name, rather
than copying every FabricIP on each Pod status update. Both current and previous
Pod UIDs sharing that name are enqueued; the reconciler still checks the live
Pod UID and grace period before a conditional deletion. Port GC likewise indexes
the recorded Node and Pod namespace/name. These indexes change lookup work, not
the persistent-VM exemption or the sever acknowledgement contract.

The allocation owner is (containerID, ifName), with Pod UID retained for indexing and GC. ADD reuses an existing claim of that sandbox, including retries; rollback releases only claims created by that attempt. DEL removes bridges and claims only for its sandbox, with UID/resourceVersion preconditions. Legacy claims without sandbox identity are retained by DEL and left to GC.

Bridge next hops `169.254.1.1` / `fe80::1` and service hairpin identities
`169.254.42.1` / `fe80::2a:1` are reserved platform addresses. FabricIP, Port
and ServiceVIP allocators skip them; explicit CNI requests and new API claims
reject them. Their RFC6052 representations are reserved as well because they
share datapath keys with the IPv4 addresses. CIDRs containing these addresses
remain usable and may still overlap between VNIs. Existing pinned workload
identities are never silently replaced; an unusable reserved claim reports an
error. A gateway leg whose network+1 collides with a platform address fails ADD
before creating a Port.

GC also reaps claims not listed in a matching Running Pod status.podIPs after a five-minute grace period, and requeues younger claims. The agent repairs missing claims only for current local Pod status addresses actually present in successfully rebuilt local endpoint state. Existing conflicting claims are reported and preserved. New veth aliases retain sandbox metadata through forwarding updates; legacy rebuilt links can be repaired without inventing a container ID.
- Sandbox ownership also applies to ordinary tenant Ports and gateway Ports.
  Their annotations store the full container ID and CNI invocation interface;
  the interface label distinguishes attachments within that invocation. Retried
  ADD reuses owned Ports and an existing veth only after verifying its peer and
  host alias. Rollback releases only newly created objects with UID and resourceVersion preconditions. A same-UID Port rebound after ADD is observed survives rollback. The rollback record follows successful sandbox annotation patches made by that ADD, so an unchanged claim can still be released after a later failure.

DNS identifies a sandbox's primary attachment, never an arbitrary Port of its
Pod UID. Multiple legacy attachment candidates without this witness are refused.
Upstream DNS work is limited to 256 requests globally and 16 per querying VPC;
excess queries receive SERVFAIL. Gateway UDP/TCP relay work shares a 128-operation
limit and drops/closes excess work before spawning handlers. HTTP metrics bound
header/write/idle time; flow NDJSON bounds writes individually to preserve streams.

Release builds verify the downloaded CNI plugin archive against the published
v1.9.1 SHA256 pinned in the Dockerfile for amd64/arm64 before extraction. Other
version/architecture combinations fail until their trusted digest is added.

Local operator material (`.codex-*`, kubeconfigs and dotenv files) is excluded
from Git additions and Docker build contexts; it is never input to COPY . .
or a release artifact. Exclusion does not revoke credentials already disclosed.

Revocation resolves the fabric bridge from the veth actually found in locals,
so a migration target already recorded on the persistent Port cannot cause
cleanup to delete that target's bridge while draining the source.

Bridge writers and cleanup share a host file lock, and a new pinned
bridge_owners map records the veth ifindex and a SHA256 of sandbox identity.
Late cleanup after GC/address reuse removes a bridge only if this owner witness
still matches. Rebuild derives witnesses from veth aliases. A missing witness
fails closed for deletion; the original FabricIP label is never ownership proof.
During VM migration, target ADD preserves the active Port's pod and sandbox
identity while spec.node still points at the source. At cutover the controller
updates the pod identity and sandbox container ID together, deriving the latter
from the active launcher's status.podIP FabricIP claim. Missing claims cause a
short retry; an old sandbox identity is never silently reused for the new pod.
Persistent Port local delivery at cutover selects the host veth by its recorded
sandbox container ID and CNI interface, in addition to VNI and VPC address.
Legacy records with no sandbox metadata are usable only when exactly one local
veth matches. Multiple matches are an error, never an arbitrary first endpoint.
The shared bridge writer lock also serializes local endpoint map updates and
conditional deletion. CNI DEL and Port sever remove a local entry only while its
ifindex still belongs to their captured endpoint; a cutover/reallocation cannot
replace it between the ownership check and Delete.
Sever acknowledgement also checks the current Port's node against the event's
node, and its binding against the one actually drained. A lagging source agent
cannot acknowledge a terminating Port whose active sandbox moved elsewhere.
IPv6 link-local ingress is a control-protocol exception, not an identity:
only NDP with code zero and hop limit 255, and DHCPv6 server replies, may
bypass isolation. TCP/UDP application traffic from a link-local or multicast
source is rejected before policy; fabric bridge translation remains a separate
sanctioned path.

FabricIP repair refuses an address witnessed by multiple rebuilt sandboxes.
Pod status identifies the address but cannot identify the owning sandbox;
an old veth must not supply the container ID for the current pod's claim.

Default-network rebuild also checks the effective host route before restoring
an address to locals or offering it to FabricIP repair. A lingering sandbox's
alias cannot replace the current sandbox's source-authentication endpoint.
Pruning applies the same route witness, including to pre-alias net-0 entries.
An authorized default-network ADD replaces a stale host route to its claimed
fabric address; EEXIST must not silently retain another sandbox's route.

The bridge gateway (169.254.1.1) and ServiceVIP hairpin source (169.254.42.1)
are host-generated IPv4 identities. A workload cannot emit either source at
its origin veth, even with a forwarding grant or a misleading local endpoint
record. NAT may assign these sources only after the origin check.

### Policy compiler startup

NetworkPolicy, SecurityGroup and HostFirewall compilers wait until every input informer has completed its initial list before applying a snapshot. Early notifications leave pinned policy intact. Each compiler performs a full resync once its caches are ready, even if its last initial event arrived before the ready flag. If initial synchronization fails, no partial policy replaces the pinned state.

### Fabric route reconciliation

FabricIP notifications and Node-driven resyncs share a serialized reconciler. Events only identify a cache key: the reconciler rereads the current claim while holding its writer lock, so a stale DEL cannot remove a replacement claim and an old node snapshot cannot restore a deleted claim. A missing node endpoint removes its claims from remotes. After the initial FabricIP list, prune pinned net-0 remotes absent from the current claims; leave VPC-scoped remotes intact.

Grant reconciliation reads the full ports-map value, including gateway and quarantine flags. The network-only accessor is reserved for address-scoped cleanup. Platform gateway legs are never treated as tenant forwarding legs or severed for lacking a tenant VPCBinding.
# IPv6 responder lifecycle

Each RA/DHCPv6 responder belongs to the complete veth rebuild identity, not
only its ifindex. Changes to that identity cancel the previous listener before
starting a replacement. RA workers cancel and join their DHCPv6 and periodic
send goroutines before closing the raw socket. Fatal receive errors end the
worker rather than spinning. Closed netlink update channels are disabled, so a
failed subscription does not cause a busy rescan loop. Cancellation drains all
workers; only eligible real veths may start a responder.
Each responder reads at most ten solicitations per second. A guest flooding
RS or DHCPv6 cannot make the agent parse and answer every packet at line rate;
normal provisioning retries continue within the bounded socket queue.

Host veth configuration publishes alias, forwarding allowlist, port flags and
local endpoints under the same writer lock as grant reconciliation. Forwarding
stays disabled while its CIDRs are replaced; no partially populated grant may
inherit a reused ifindex's old prefixes. CNI arms quarantine before attaching
hooks. Bridge publication rechecks the active alias so a concurrent revocation
cannot recreate a revoked endpoint's bridge. ADD retries retain staging until
the agent performs a verified cutover.

Policy informer handlers queue one pending reconciliation instead of compiling
a full node snapshot per notification. A worker waits for complete caches,
applies their latest contents and coalesces bursts with a fixed 100ms interval
between passes. Continuous updates cannot postpone reconciliation indefinitely.
A notification during compilation schedules another pass; cancellation drops
pending work. This bounds handler backlog under object churn.
Binding reconciliation uses the same bounded notification worker and indexes a
single local-veth inventory by Port UID/address, so remote-only Ports do not
trigger per-Port kernel scans or pod API reads.
Gateway, route, FloatingIP and LoadBalancer-uplink reconciliation also use this
worker. Their informer callbacks perform no full-list scans, netlink discovery
or map writes. Each waits for all of its declared informer inputs before the
initial replay, retaining pinned forwarding state while an input list is
unavailable. This also prevents a startup view missing the oldest VPCGateway
from choosing a different boundary. Node-set callbacks queue the same VPC
boundary worker. One pending notification is retained during a running pass;
the next pass rereads the latest caches, rather than retaining every event.
Route rows are retained during startup, but their separate `route_guard` is
armed on every loader start and before compilation/publication. Off-VPC workload
traffic stops until a complete snapshot succeeds; incomplete or saturated
snapshots must not turn VPN traffic into an ordinary NAT miss. The route worker
also retries every 15 seconds through the same coalesced queue, without depending
on new events. Unresolved prefixes use zero next hops as explicit blackholes.
The guard is one kernel cell, with no per-event timer, goroutine or prefix state;
native VPC/peer delivery and fabric/node plumbing retain their own paths.
An explicit overlay delivery also requires the Geneve ifindex to be configured.
If transport configuration is absent, `encap_sg` drops instead of handing the
unencapsulated packet to ordinary kernel routing (hardening 192). This covers
VPN/default-appliance routes, native remote VPC delivery and migration forwarding;
ordinary host-stack plumbing that never selected overlay delivery is unchanged.
Forwarding reconciliation applies a UID-proven endpoint batch before legacy ownership API work, then a separate batch for individually verified legacy endpoints. Each batch snapshots the scoped CIDR map once for its local
legs, diffs each owned scope and leaves unchanged grants untouched. Changing
scopes still disable forwarding before mutation and retain that disabled state
on errors. RA discovery coalesces link-event bursts into one fixed-window
rescan, so grant changes cannot trigger a complete interface scan per event.

Fresh or recreated policy maps begin under the NetworkPolicy/SecurityGroup
deny guards before programs are published. Successful complete snapshots mark
each layer initialized in params slots 14/15; only then may its guard clear.
An interrupted initial startup cannot make empty, already-pinned maps appear
initialized on the next restart. Compatible initialized snapshots remain
available while caches load; missing inputs re-arm the relevant guard.
The four-slot LB/HostFirewall tail-call map is also pinned. Its targets must
survive closure of the agent's userspace descriptors while attached classifiers
continue to run. Loader initialization restores modes and all tail-call slots
before publishing the from_pod/to_pod pins used by CNI. Compatible loads replace
targets in that same bounded map.
### Peering reconciliation work

The agent indexes live peering halves by their directed pair of VPC references
to find reciprocal consent in linear time. Terminating halves never enter the
index, and an object cannot consent to itself. Reconciliation runs only after
both caches synchronize and coalesces notification bursts in a bounded queue.
### Auxiliary HTTP request lifetime

Agent, responder and VPN metrics/status/flow servers bound reading the whole
HTTP request to five seconds, including bodies attached to GET requests. Header
and idle deadlines alone do not bound the automatic body draining performed by
Go's HTTP server. Write deadlines remain ten seconds; flow streams refresh
their existing per-message deadlines and can outlive the request read budget.
Auxiliary request headers are limited to 32KiB before handler/authentication
work (Go allows an extra 4KiB parser slop). Oversized headers are rejected with
431 and connection closure; a client still writing may see a TCP reset. Request
body/write/idle and stream lifetime limits remain unchanged. This bounds header
work per connection without claiming an overall constant heap or request rate.

### Pool-reserved workload addresses

The network address and network+1 gateway address are reserved within each
allocation pool, independently of global bridge/hairpin reservations. Explicit
ordinary Port requests, sandbox retries and persistent VM binds obey the same
rule as automatic allocation; otherwise a tenant can preempt the platform
gateway claim. The authorized gateway attachment remains the sole network+1
claim path. Existing incompatible pinned identities are preserved and refused,
not silently reallocated. This per-pool check does not ban overlapping CIDRs.
ServiceVIP selection includes network+2 as its final usable candidate, so a
free /30 IPv4 pool can provide that address; only its network/gateway addresses
and the allocator existing broadcast exclusion remain reserved.

Terminal Pod claim cleanup also covers FabricIP: a matching UID in Succeeded
or Failed no longer holds a fabric address, even if the Pod object is retained
for Job history or finalizers. Pending, Running and Unknown are preserved by
this terminal check, as are claims without a recorded UID. FabricIP uses its
live Pod reader; Port GC confirms the terminal phase live before deletion and
retains the sever barrier. Persistent VM IP/MAC claims remain exempt.

Ordinary Ports from a primary CNI invocation can also outlive their sandbox
while the Pod UID stays unchanged. After a five-minute creation grace, Port GC
may reap a primary-invocation Port only when the Running Pod's current one or
two status addresses all have live, nonterminating FabricIP claims proving the
same different container ID and the primary CNI interface. Pod UID, namespace,
name, node and canonical address must match; the Pod and claims are confirmed
with the live reader before conditional deletion. Unknown/legacy witnesses,
mixed sandbox claims and delegate interface mismatches preserve the Port.
Persistent VM Ports remain exempt. FabricIP events revisit only this Pod's
indexed Ports, so late claim publication triggers cleanup without periodic
cluster scans or an additional worker. The normal sever finalizer still gates
address reuse until the node acknowledges withdrawal.

### Forwarding grant work budgets

A live unrestricted VPCBinding forwarding grant wins without constructing any scoped CIDR union, regardless of input order. Otherwise, the complete union may contain at most 4,096 input prefixes (duplicates count against work). Above that budget, attachment authorization remains present but forwarding resolves false with no partial CIDRs; CNI reports the budget error before endpoint publication and the agent revokes the forwarding flags on existing legs. API create/spec updates reject any single binding above 4,096 prefixes. Active scoped forwarding prefixes must be valid IP CIDRs of at most 64 bytes, enforced at admission and legacy resolution; errors report only the offending index, never the complete untrusted text. Unrestricted grants still bypass construction/validation of irrelevant legacy scoped unions. Legacy oversized or malformed scoped snapshots are handled fail-closed at resolution. Unchanged legacy specs remain eligible for authorized finalizer removal, and an authorized owner can disable forwarding while retaining the old prefixes; input validation must not prevent revoking a malformed legacy grant. This is a work bound, not a promise of available global fwd_cidrs map slots.

### IPv4-mapped CIDR input

An IPv4-mapped IPv6 CIDR with a mask of at least /96 represents the same IPv4 range as its unmapped form: `::ffff:192.0.2.0/120` equals `192.0.2.0/24`. Normalize the mask before adding the RFC 6052 /96 address prefix. All route, forwarding and policy LPM keys share this conversion; adding /96 twice exceeds the kernel key width and can leave policy update guards armed. SecurityGroup containment must normalize these inputs too, so a narrower mapped prefix inherits the same scoped group union as ordinary IPv4. Shorter IPv6 prefixes remain native IPv6 ranges after masking. Invalid internal IP/mask combinations are rejected before map mutation. No map layout or packet address encoding changes.

CNI attachment authorization reads VPCBindings in pages of 128, with the existing 65,536-object/512-page live scan budget and operation context. Its temporary accumulator stores at most 4,096 matching forwarding prefixes; it retains no unrelated binding specs or list backing arrays. An unrestricted matching grant on a later page overrides a rejected legacy scoped union, so union errors are resolved only after the complete scan. List failure, cancellation and non-progressing continuation return no authorization from partial state. The cached resolver keeps its inexpensive first unrestricted-grant pass; the streaming resolver may allocate a bounded scoped union before a later unrestricted grant arrives.

For each agent reconciliation, index bindings only for consumer namespace / full VPC reference keys that have local Port endpoints. Resolve each such key once and share its read-only scoped union among those endpoints; unrelated grants are never parsed or copied into a union. The index belongs to the current pass and retains no historical grants. Complete namespace and VPC identity remain part of the key, including the binding reference's default namespace. DNS checks only live attachment consent and do not construct a forwarding union. Forwarding still resolves fail-closed on invalid scoped input, without removing valid attachment consent.

Port retry/persistent-NIC lookup, sandbox Port teardown and gateway consent use the same bounded live CNI scan budget. Retry and persistent-NIC lookup retain at most one matching Port; multiple matches are an error, preserving every existing pinned identity rather than choosing an arbitrary NIC claim. Teardown retains only exact sandbox-owned Ports and starts cleanup after all pages succeed. Gateway consent retains only the oldest live boundary for the requested VPC, including its deterministic name tie-break, and consumes all pages before authorizing. Partial or failed scans cannot cause reuse, VM identity rebinding, endpoint cleanup or new gateway publication.

The pod's cozyplane networks annotation is decoded with a 16 KiB byte budget and a maximum of ten entries, enforced before decoding an eleventh entry. Both the annotation and Multus delegate paths use this same decoder. VPC references, IPs, MACs and interface names have bounded text lengths; oversized-field and JSON errors do not repeat the annotation payload. Duplicate explicit interface names are rejected before a delegate can choose a conflicting IP/MAC pin from the first match. This preserves the existing ten-entry annotation contract and does not change the separate supported delegate-name ordinal range or pinned VM identities. The single-VPC annotation also has the VPC-reference text bound.

### CIDR policy family identity

The shared RFC 6052 address encoding must not widen an IPv6 policy prefix into an IPv4 permission. For NetworkPolicy ipBlock and HostFirewall, an IPv6 CIDR authorizes IPv6 packets only, even when its range covers the internal `64:ff9b::/96` representation of IPv4. An IPv4 CIDR likewise must not authorize native IPv6 packets addressed in that range. Policy lookup needs the actual packet family as well as the encoded address; mapped IPv4 input normalizes to IPv4. Empty peer lists may still explicitly compile both families. Any key-encoding transition must leave legacy keys unable to authorize new family-scoped queries before complete reconciliation. This concerns policy authorization, not future SIIT translation or the shared routing address layout.

Specific SecurityGroup north-south CIDR rules follow the same packet-family constraint. Their 16-bit protocol field carries the L4 protocol in its low byte and family `4`/`6` in its high byte. Containment unions remain within one logical family and scope. The documented SG_WORLD shortcut for explicit all-addresses rules keeps its existing contract; specific IPv6 ranges such as `64:ff9b::/96` must not authorize IPv4 sources or destinations merely because IPv4 is encoded there. Legacy untagged CIDR rows cannot match either family's tagged query.

The north-south ingress query and CIDR lookup key use one unpinned per-CPU scratch entry (72 bytes per possible CPU). They are fully overwritten before use, with compiler barriers before lookups, and reused only within one non-sleepable TC execution. This keeps the combined eBPF call stack below the verifier limit without allocating per-flow state or retaining a packet history. Scratch lookup failure denies the packet.

Scoped forwarding grants bind the full host-veth ifindex, actual source packet family (4/6), and source prefix. A native IPv6 prefix cannot grant permission to emit foreign IPv4 sources through their RFC 6052 encoding; mapped IPv4 input grants only IPv4. `fwd_cidrs` uses a dedicated 28-byte key with 64 fixed scope/family bits followed by the 128-bit address, rather than the routing LPM key. Route addressing and overlapping VNI scopes remain unchanged. The existing incompatible-pin reconciliation recreates legacy 24-byte forwarding maps, leaving scoped foreign traffic denied until a complete owned grant replay. Old attached programs retain their old map until hook replacement, following the existing upgrade contract. Capacity stays 4,096 entries (16 KiB additional key payload at capacity), with no per-packet allocation or new worker.

Own VPC CIDRs are reconciled from a complete cache snapshot, covering every
declared family/prefix rather than just CIDRs[0]. The coalesced worker waits
for initial VPC cache synchronization and prunes obsolete own rows (scope equals
value), including rows retained across a restart or deletion. Peering rows
remain owned by their existing reconciler. Both writers serialize access to
the shared 1,024-entry networks map and preflight total retained plus desired
capacity before deletion. Desired input work and row memory are bounded to
65,536 input units and the map's actual distinct-key capacity. A malformed
legacy VPC contributes no partial own rows; other VPCs can still reconcile.
An over-budget snapshot or total capacity overflow retains the last complete
routing state. A successful peer replay queues a new own replay, so removal of
stale peer rows can free startup capacity without waiting for another VPC event.
Updating one VPC's CIDRs must not consume entries for every historical
prefix. This preserves RFC 6052 routing representation and overlapping VNIs.

Within this worker, successfully seeded counter IDs are remembered only while
their networks remain in the current successful own snapshot. Unchanged passes
therefore do not decode every CPU's counter values again. Failed seeds remain
eligible for retry and disappearing scopes are removed from the small userspace
set; restart begins with an empty set. This does not itself delete historical
kernel counters.

### VPC counter lifetime

The complete VPC informer snapshot also reconciles the scopes of vpc_counters and sg_drops. Counters for current VNIs, including terminating and CIDR-less VPCs, retain their values; scopes whose VPC object disappeared are removed. Counter seeding and pruning share a mutex, and a stale policy pass cannot recreate a scope excluded by the last complete snapshot. Before the first complete snapshot, counters remain untouched. Key enumeration is bounded by each map capacity and reads no per-CPU values. Unchanged scope sets skip kernel enumeration; failed pruning remains eligible for the next event. Failed or incomplete scans perform no pruning. These maps are bounded already; reclamation prevents historical VNIs exhausting their slots and increasing metrics work, rather than claiming an unbounded heap leak.

### VPC CIDR input admission

VPC creation and changes to spec.cidrs admit at most 1,024 input prefixes, matching the entire networks map capacity, with at most 64 bytes per prefix and valid IP CIDR syntax. Empty CIDR lists remain valid; overlapping tenant ranges, host-bit notation, IPv4-mapped notation and native IPv6 remain accepted. This is an input-work ceiling, not a reservation or a per-tenant quota: aggregate routing capacity still applies. Unchanged malformed legacy CIDRs do not prevent metadata/finalizer or unrelated field updates. CNI validates the full list before any claim or identity rebind, with index-only rejection diagnostics. The agent excludes an oversized legacy VPC before charging the complete snapshot work budget, so one stored oversized list cannot block all healthy VPC network updates. Bounded malformed lists still count toward the raw parsing work budget and contribute no partial routes.

Peering replay validates each referenced VPC CIDR list against the same bounds before overlap checks or peer-map publication. Invalid legacy VPCs contribute neither a peer grant nor delivery rows; healthy and revoked pairs can still reconcile. Validation is memoized by complete VPC reference for one snapshot, without historical retention. Peering controller readiness applies the same CIDR and VNI checks; invalid syntax must not be described as disjoint merely because an overlap parser ignored it.

### Metrics collection work budget

The agent metrics endpoint shares one immutable response snapshot across requests for one second. Rebuilds are serialized, including failures, so a burst cannot multiply full per-CPU map scans and formatting work by HTTP concurrency. The first request collects a snapshot; values and VPC labels refresh after expiration. HTTP writes take place outside the collection lock, retaining the existing connection/write-time budgets. There is no polling worker or snapshot history. A response larger than 128 MiB is refused, and failures use the same one-second retry budget. This changes metric freshness by at most one second after collection; it does not claim to eliminate all transient allocation or permanently authorize unbounded scrape rates.

### Persistent NIC creation transaction

Within a VNI, persistent Port creation checks the current namespace/VM/VPC/NIC identity in a paged etcd snapshot before writing. The transaction compares the modification revision of every Port key in that VNI with the snapshot revision, alongside the existing Port/ServiceVIP address guards. A concurrent creation or identity-affecting update invalidates the snapshot; eight retries and a 65,536-claim/128-per-page scan ceiling bound the work. The allocation client caps each gRPC response at 16 MiB, and each scan stops before decoding more than 64 MiB of stored data; exceeding either limit fails ADD without a partial allocation. This includes legacy claims without adding an index, lease or historical reservation. Empty-collection compares admit the first claim. A matching claim returns AlreadyExists with the actual holding Port name, so ADD can fetch it, verify the instance UID and pinned IP/MAC, and bind or stage it. NIC identity fields are immutable through normal and status updates; pinned VM MAC changes are refused. Unrelated status changes within a busy VNI may cause a bounded retry or an ADD failure for kubelet to retry; they cannot permit a second identity.

### Same-sandbox CNI operation concurrency

Address-name uniqueness does not by itself serialize concurrent ADD retries for one ordinary sandbox. Both calls can observe no owned Port and then choose different free addresses. The operation boundary covers rollback and DEL, since a failing ADD must not remove an allocation another same-sandbox ADD has already reused. Cross-node VM identity remains enforced by the allocation transaction.

CNI ADD and DEL hold a host flock around the complete operation, including failed-ADD rollback. All interfaces of one container ID share a SHA-256-selected shard in /run/cozyplane/cni-locks; the set has at most 256 files, independent of pod history. Nonblocking lock attempts sleep for 20 ms and stop at cancellation or five seconds. The root-owned parent directory must not be group/world writable; directory-relative opens refuse symlinks, nonregular or multiply linked files and unsafe ownership/modes before running the operation. The root-owned directory uses 0700 and lock files use 0600; descriptors close on all returns and kernel locks disappear on process exit. Hash collisions conservatively serialize unrelated sandboxes; kubelet can retry a busy shard. Missing identity fails ADD and makes DEL a harmless no-op. VM identity across hosts is still enforced by etcd.

### DEL namespace ownership

The namespace path supplied with DEL is not a sandbox identity: a removed namespace path may resolve to another sandbox by the time an old DEL runs. Pod-side primary, secondary and gateway interface deletion must verify the live veth peer in the host namespace against the full container ID and CNI interface ownership. A matching interface name or truncated host-name prefix alone is insufficient. Real isolated namespace/veth tests cover stale DEL, shared host-name prefixes, namespace-local index collisions, and current-sandbox teardown.

DEL validates both the host peer alias and the peer network-namespace ID against the opened pod namespace. Namespace-local interface indexes alone are not globally unique. Unknown ownership, non-veth interfaces, and missing namespace-ID proof are preserved for runtime teardown. Addresses are collected from the verified link object and that same object/index is deleted, without a second name lookup. This adds bounded local netlink calls, no retained state or background worker.

### Pod-label snapshot budget

Pod labels used for Port SecurityGroup fallback membership must be copied completely or rejected: truncation would change selector semantics. Kubernetes validates individual label keys and values but does not impose an aggregate label count limit. Writers check a 4096-label count and 128 KiB raw JSON-size estimate before serializing a snapshot, then enforce the same limit on the encoded result, leaving room within the 256 KiB Kubernetes annotation limit for other Port annotations. CNI must reject before allocation; migration writers must preserve the existing binding and pinned IP/MAC on rejection. This bounds additional serialization work and transient heap use; it does not remove the cost of obtaining the Pod itself. For valid Kubernetes label characters the estimate is exact; unexpected escaped input may expand during one bounded serialization and is checked afterwards. Default-network attachment needs no Port-label snapshot. Behavior tests reproduce repeated API rejection from a valid large Pod and require preflight rejection without any Port update.

### FabricIP lookup work during revocation

Severing a Port joins its Pod UID and sandbox/interface to the underlay claim. Bulk binding revocation must retrieve only claims of that sandbox (or that Pod UID for legacy Ports), rather than materializing the entire cluster FabricIP store once or twice per Port. Register both indexes before the FabricIP informer starts; updates and deletions remove old index memberships through client-go. Selection retains IPv4 preference and IPv6 fallback and does not use a claim of another sandbox. Index state contains only current cache objects, with no historical retention. A scoped lookup failure returns no invented fabric address. Behavior tests verify one retrieved sandbox row among 10003 claims, legacy Pod scope, 64-character container IDs, dual-stack preference, retarget/deletion and 1000-object churn without historical index keys. The measured lookup allocation falls from 327680 bytes to 40 bytes.

### Route capacity isolation (SEC188 availability)

The global route guard remains closed until all initial caches and a complete
publication succeed. Capacity overflow must then fail closed only for the
owner namespaces exceeding their fair route-candidate budgets. When total
demand fits, preserve every namespace unchanged; otherwise distribute capacity
with max-min shares, satisfying smaller demands first with deterministic ties.
An over-budget namespace publishes no partial route set: every VPC scope with
route intent from that namespace is explicitly blocked for off-VPC workloads.
Native VPC delivery and other namespaces keep their existing behavior.

A pinned scope bitmap covers all 22-bit tenant VNIs without a second scarce
per-VPC hash capacity: 1024 array cells, each 128 uint32 words (512 bytes), total
512 KiB of values. The source VNI chooses the array cell and bit; unknown/out-of-
range map lookups fail closed. The global guard covers bitmap and route-table
updates together. On restart initialize all 1024 cells before opening it; later
updates retain only current nonzero cells (at most 1024, no update history) and
record each successful mutation so retries recover partial writes correctly.
Kernel write/scan failures or incomplete cache proofs keep the global guard
closed. This addresses steady capacity overflow; atomic publication still has
a short global gate, and aggregate cache/work ceilings still require operator
resource quotas. No routing outside eBPF and no Port identity changes.

Once an owner is known to exceed the entire route capacity or has malformed
route input, stop parsing its remaining prefixes/rows, including later gateway
objects. Still visit each active VPC reference and record its blocked scope.
Only complete valid owner sets spend prefix-compilation work; global cache
lookup/object enumeration ceilings remain fail-closed. This avoids allowing
one already-rejected namespace to close the global gate via redundant parsing.
