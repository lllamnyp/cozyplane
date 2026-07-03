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
  spawns per-VPC egress gateway Deployments for `spec.egress.natGateway`.
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
| `locals` | hash | {net id, pod IP} → {veth ifindex, pod MAC} | plugin (per pod) |
| `peers` | hash | {src net id, dst net id} → 1 | agent (VPCPeerings) |
| `gateways` | hash | net id → {gateway .1 IP, node IP (0=local)} | agent (gateway Ports) |
| `bridges` | hash | fabric IP → {net id, VPC IP} | plugin (per VPC pod) |
| `ct_fwd` / `ct_rev` | LRU hash | the bridge's L4 NAT connection table | datapath (in-band) |
| `params` | array | `[0]`=Geneve ifindex, `[1]`=default VNI | agent |

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
3. if the destination is a **local pod** (`locals[dst]` hit): rewrite the dst MAC
   to the pod's MAC and `bpf_redirect` to its veth — same-node delivery *through*
   the destination's ingress hook, no kernel-routing shortcut;
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
-j ACCEPT` at the top of the `FORWARD` chain (via `iptables`, nft backend) so
overlay traffic is accepted before that drop.

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

TCP and UDP; ICMP to a fabric IP is dropped (a follow-up).

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

### Floating IPs (external north-south)

The dual-address bridge above is *internal* north-south: a fabric IP reachable
from the cluster's default overlay. A **floating IP** is the same idea turned
outward — a routable public address, reachable from off-cluster, bound 1:1 to a
tenant IP — realized as an **extension of the eBPF bridge, not the gateway**. No
iptables, no gateway pod: it is the fabric bridge with an external address and
the client-masquerade removed, so the tenant sees the *real* caller. The pieces:

- **`floating` map** (`publicIP → {net, vpcIP}`), programmed by the agent — the
  external-facing sibling of `bridges`.
- **Advertisement from the target pod's own node.** The agent on whatever node
  currently hosts the target's Port makes the node answer ARP for `publicIP` by
  assigning it as a `/32` on the uplink (L2 mode; BGP later). Proxy-ARP (a pneigh
  entry) does *not* work here: a floating IP is drawn from an L2 the node is
  already on, so the kernel treats the address as same-link and never proxies it —
  the classic MetalLB-L2 problem. Assigning the `/32` makes the kernel answer for
  it as a local address; `from_uplink` still intercepts inbound at tc ingress
  before any local delivery. So `client → publicIP` always arrives where the pod
  already is: floating ingress is always *local*, never cross-node, and the
  address follows the pod on reschedule.
- **An uplink-ingress hook** (`from_uplink`). A tc program at the node uplink's
  ingress catches `client → publicIP` and `bpf_redirect`s it into the target's
  veth by identity (`locals[{net, vpcIP}]` — the pod is local by construction).
  It does *not* rewrite the packet: the DNAT happens where the bridge's does, in
  `to_pod`. This mirrors the bridge exactly (`from_uplink` is to floating what
  `from_pod`/`from_overlay` are to the fabric bridge).
- **`to_pod` does the DNAT** (`floating_forward`, right beside `bridge_forward`).
  It DNATs `publicIP → vpcIP` on the destination, keeping the external client as
  the source — *not* masqueraded to `169.254.1.1` — and records a
  **source-preserving** conntrack entry (`float_ct`). Like `bridge_forward` it
  returns delivered, so the isolation check below never runs.
- **Reply through `from_pod`.** The pod replies `vpcIP → client` via its
  `169.254.1.1` default route — which every pod has unconditionally
  (`configurePodIface`), gateway or not. `from_pod` (already on every veth) finds
  the source-preserving ct, SNATs `vpcIP → publicIP`, and **`bpf_redirect_neigh`s
  it out the uplink** (kernel neighbour resolution for the external client). The
  redirect is not optional: because `publicIP` is advertised as a local `/32`, the
  normal RX path would drop the reply as a *martian source* (a local address
  arriving on the pod veth), and it would also face `rp_filter` and the FORWARD
  chain. `redirect_neigh` bypasses all three and fills the L2 header from the
  client's neighbour entry — the same "don't route, deliver by identity" move the
  rest of the datapath makes. (A pool must still be a routable range disjoint from
  the pod CIDR so the client and the switch fabric can reach it.)

**Inbound walk (external client → floatingIP → tenant pod B in VPC-X):**
`client → floatingIP` arrives at B's node (its agent answered ARP) → `from_uplink`
redirects it into B's veth (`locals[{X, B-ip}]`) → `to_pod`'s `floating_forward`
DNATs it to `client → B-ip`, keeping the client source, and stamps the ct → B
replies `B-ip → client` toward `169.254.1.1` → `from_pod` matches the ct, rewrites
the source `B-ip → floatingIP`, and `redirect_neigh`s it out the uplink to the
client, unmasqueraded.

**Why the conntrack, and how EIP egress drops in later.** The 1:1 map is a static
bijection, so reversing a reply needs no state in principle — but *unconditionally*
SNAT-ing every off-net packet from a floating-bound `vpcIP` to `publicIP` would
also rewrite the pod's **own-initiated** egress, which is the full Elastic-IP
semantic deferred to later. The ct is exactly what bounds this to *reply* traffic:
`from_pod` reverses only flows an inbound connection created. Removing that bound
(reverse the `floating` map for any egress from the bound `vpcIP`) is the whole of
the future EIP-egress upgrade — no API or map change, just a policy flip.

**No gateway.** Floating ingress does not use, and does not require, the VPC's
egress gateway. A floating IP is `Ready` once its target IP is a **live Port** (a
running pod to advertise from and deliver to); with no live target the address
stays reserved but silent (see §4, the controller). It is distributed (DVR) from
day one because it rides the pod's node.

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
  only the cozyplane controller creates pods there) and the VPC must have
  `spec.egress.natGateway`. The `.1` Port is claimed like any other, marked
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

With `--cluster-cidr` set the agent also installs the classic node masquerade
(`-s <clusterCIDR> ! -d <clusterCIDR> -j MASQUERADE`): pod CIDRs aren't
routable outside the cluster, so without it no pod — including a gateway
forwarding tenant traffic — has an internet return path.

### Controller

`VPCReconciler` lists VPCs cluster-wide, assigns the lowest free VNI ≥ 100 to any
VPC without one, and sets `status.phase = Ready`. (VNI selection is
list-then-pick; a conflicting status update just requeues. Fine for the
prototype.)

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

`PortGCReconciler` releases the sever finalizer from terminating Ports whose
node no longer exists — the agent that would acknowledge is never coming back,
and the workload died with its node.

`GatewayReconciler` realizes `VPC.spec.egress.natGateway` as a per-VPC gateway
Deployment (`cozyplane-gateway-<vni>`) in the system namespace: a privileged
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
Port claims. (Token rotation is a known TODO — it's written once at startup.)

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
  `internal/setup`, `cmd/apiserver`) is scaffolding adapted from
  `aenix-org/cozyportal`, currently unused at runtime (CRDs serve the API). It
  builds and runs; wiring `Port` storage and deploying it is a later step.

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

## 7. Known limitations / divergence from the design

The design (three planes, dual-address bridge, identity-based policy, etc.) is
mostly future work. As built:

- Overlapping VPC CIDRs are supported (net-scoped delivery, above); only
  *peering* overlapping VPCs is refused.
- The north-south bridge is eBPF NAT (its own `ct_fwd`/`ct_rev` table), TCP/UDP
  only — ICMP to a fabric IP is dropped. The datapath is netfilter-free except
  the agent's node masquerade and overlay FORWARD-ACCEPT (both non-NAT, both
  candidates to move to eBPF) and the gateway pod's internal filter (in its own
  netns).
- VPC egress is opt-in and coarse: `spec.egress.natGateway` opens internet +
  cluster DNS through a single per-VPC gateway pod; no per-destination policy,
  Service exposure, or metadata endpoint yet. **Floating IPs** (source-preserving
  public ingress) have an API and allocation; their gateway 1:1 NAT and address
  advertisement are landing (see "Floating IPs" in §3). No policy/security groups
  — a peering opens the two VPCs completely.
- IPv4 only; single CIDR per VPC; no VM live-migration plumbing.
- The API is served as CRDs by default; the aggregated apiserver
  (`apiserver.enabled=true`) serves the same group with server-side validation
  (e.g. VPCPeering spec immutability) in its strategies.
- The plugin's kubeconfig token isn't refreshed; VNI allocation and Port IP
  selection are list-then-pick (atomic at the claim, but not high-concurrency
  optimized).
