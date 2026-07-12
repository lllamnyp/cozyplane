# Host firewall

> One of three policy layers; flow ownership and the node-origin trust
> model are recorded in [policy-layers.md](policy-layers.md).

Status: **increments 1-2 complete** (2026-07-12). Increment 1 (ingress) is
dev-cluster-validated live — a control-plane node isolated behind the
apiserver LB, monitoring scrapes gated and counted, per-CIDR reopen.
Increment 2 (egress) is built and e2e-covered. The node-scoped sibling of
default-net NetworkPolicy ([network-policy.md](network-policy.md)): gates
traffic addressed to **the node itself** — the one delivery target the other
two policy layers deliberately leave alone (NetworkPolicy gates net-0 pods,
SecurityGroups gate VPC ports; both exempt node-destined traffic).

## Why

Removing Cilium (and with it any host-endpoint policy) left every node
service reachable by anything that can route to a node address:

- **Default-network workloads.** A net-0 pod — or a **VM guest** on the
  default network — can dial kubelet (10250), the Talos API (50000/50001),
  node-exporter, or any hostNetwork service on any node. Net 0 is
  *semi-privileged*, not tenant land (true tenants live in VPCs and cannot
  address nodes at all — [policy-layers.md](policy-layers.md) § trust
  zones), but semi-privileged is exactly the zone that needs a firewall:
  it can reach the hosts and is only somewhat trusted. NetworkPolicy
  cannot express this gating: its subjects are pods, and its node-destined
  egress is exempt by design (the deviation recorded in network-policy.md
  explicitly deferred to this document).
- **External clients.** Whatever the perimeter (cloud security lists, ToR
  ACLs) chooses not to block arrives at the uplink and goes straight to the
  host stack.

## The kind

`HostFirewall`, **cluster-scoped**, in `sdn.cozystack.io` — a *system* kind,
like SecurityGroup and unlike NetworkPolicy. The three-layer split is
deliberate (the two-kinds decision from network-policy.md, extended):
tenants read/write `NetworkPolicy` (namespaced, upstream), VPC owners
read/write `SecurityGroup` (namespaced), and only cluster operators touch
`HostFirewall` (cluster-scoped, no default grants — a tenant can neither
read the cluster's exposure map nor open a node port).

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata:
  name: workers
spec:
  nodeSelector:               # empty selector = every node
    matchLabels: {node-role.kubernetes.io/worker: ""}
  ingress:
  - from:                     # empty from = any source
    - cidr: 192.168.10.0/24
      except: [192.168.10.7/32]
    ports:                    # empty ports = all ports, TCP and UDP
    - {protocol: TCP, port: 22}
    - {protocol: TCP, port: 9100, endPort: 9110}
```

Semantics mirror NetworkPolicy's isolation model: a node selected by at
least one `HostFirewall` is **host-ingress isolated** — default-deny for
new TCP/UDP flows to its addresses — and the `ingress` rules of every
selecting object union open. A node selected by none is untouched. Rules
are allow-only; `except` carves holes exactly as NetworkPolicy `ipBlock`
does (longer deny prefix, allow-wins at equal prefix, unions across
policies stay monotonic).

### What is never gated (baseline, non-negotiable)

The firewall must not be able to kill the cluster it runs on:

- **Node-sourced traffic** (any address in `np_nodes`, self included):
  kubelet ↔ apiserver, apiserver → webhook/kubelet, node-to-node plumbing.
  This is invariant #7's spirit applied to the host: the Kubernetes contract
  keeps working no matter what the operator writes. (It also covers the
  Geneve outer flow between nodes.) Gating node→node is a non-goal.
- **The overlay transport**: UDP to the Geneve port is always admitted
  (belt-and-braces for the window where a just-joined node isn't in
  `np_nodes` yet — the datapath must never sever its own transport).
- **ICMP/ICMPv6, ARP/NDP** — same posture as NetworkPolicy and SG (PMTU,
  ping, neighbor resolution keep working).
- **Established TCP**: only SYN(-and-not-ACK) packets are gated, so flows
  that exist when a policy lands survive, and replies to node-*originated*
  connections always return.
- **Replies to node-originated UDP** via a reply-pin (below).

Not exempt — the point of the feature: **pod-sourced** and
**external** traffic to node addresses.

### What is out of scope (not host traffic)

- **NodePort / LoadBalancer ingress** is intercepted by `lb_ingress` and
  DNAT'd to pods *before* the host stack sees it — it is pod-destined
  traffic wearing a node address, gated by `loadBalancerSourceRanges`
  (`lb_src`) and the backend's NetworkPolicy, not by HostFirewall.
- **Masquerade/floating replies** are un-NAT'd back to pod-destined flows
  ahead of the check for the same reason.

### The lockout footgun (documented, deliberate)

Isolating a **control-plane** node without allowing your own client CIDR to
the apiserver port locks `kubectl` out (your workstation is not a node) —
at which point you cannot delete the HostFirewall that did it. The baseline
exemptions keep the *cluster* alive (nodes stay Ready, workloads run,
node-sourced kubectl still works), but the API becomes reachable only from
nodes. Recovery: `kubectl` from any node (node-sourced ⇒ exempt), delete or
fix the object. Rule of thumb: start with workers; when selecting
control-plane nodes, the first rule you write is your management CIDR to
the apiserver port.

## Datapath

### Where node-destined traffic actually flows

Every path that ends in this node's host stack exits the datapath through a
**fall-through** (a `TC_ACT_OK` that hands the packet to the kernel):

| Path | Hook, fall-through |
|------|-------------------|
| external / node → node (v4) | `from_uplink` → `lb_ingress` miss (the LB tail call never returns; its no-service-row exit is the fall-through) |
| external, **v6** | `from_uplink`'s early v6 exit (v6 skips the v4 LB tail call). Caught by the e2e: this branch initially returned without the firewall |
| cross-node pod → node | `from_overlay`, net-0 branch, non-bridge exit (the `node_remotes` encap arrives here — **both families**, see the masquerade trap below) |
| same-node pod → node | `from_pod` (veth), final `TC_ACT_OK` |

**The masquerade trap (found by the e2e, worth remembering).** `node_remotes`
was v4-only, so a pod's dial of a node's **v6** address took the kernel route
to the uplink — where the cluster-egress masquerade rewrote it to a *node*
source. It arrived at the target wearing a node address (port in the masq
range was the tell in the capture) and rode straight through the node
exemption: the firewall never leaked, the identity was laundered upstream.
Any exemption keyed on source addresses is only as good as the guarantee
that nothing on the path rewrites sources into the exempt set. Fix:
`nodeAddresses` (the `node_remotes` feed) now returns both families — the
same set as `npNodeAddresses` — so v6 pod→node rides the overlay exactly
like v4, the true pod source survives to the destination's gate, and the
masquerade never sees node-destined traffic. (This also closes the latent
v6 twin of the OCI anti-spoofing gap that `node_remotes` was built for.)

All of these fall-throughs now **tail-call one new program** —
`cozyplane_hf_ingress`, `lb_prog` slot 2 — when `CFG_HF_ENABLED` is set
(one array lookup when disabled; behaviour byte-identical to today). The
tail call is the whole trick: a fresh 512-byte stack and its own verifier
budget, so the host-firewall logic needs none of the percpu-scratch
gymnastics the 544-stack lesson forced on `from_pod` (and `from_pod` gets
to *invoke* policy it could never afford to inline).

`hf_ingress` in one screen:

```
parse; only TCP/UDP considered (everything else falls through open)
src ∈ hf_self && dst ∉ hf_self?          → node-originated egress passing
                                            from_pod's fall-through: if UDP,
                                            write the hf_ct reply-pin; OK
dst ∉ hf_self?                            → not host traffic; OK
src ∈ np_nodes?                           → node exemption; OK
UDP to the Geneve port?                   → overlay transport; OK
TCP and not a bare SYN?                   → established/reply; OK
UDP with a matching hf_ct pin?            → reply to node-originated flow; OK
hf_allow LPM: {proto, dport, src} then
              {proto, port 0, src}        → allow hit (value 1) admits;
                                            deny hit (value 0, an except) or
                                            miss ⇒ count in hf_drops, SHOT
```

`hf_self` (this node's own addresses — the same set the agent feeds
`np_nodes` for itself: InternalIPs/ExternalIPs + the node-addresses
annotation, both families, NAT64 form) decides "is this host traffic" —
so broadcast/multicast and forwarded flows fall through untouched, and the
same single program serves all three call sites *and* the uplink-egress
attachment (where `from_pod`'s fall-through carries node-originated
outbound: `src ∈ hf_self` routes it to the pin-write arm).

### Stateful UDP: the pin has three write points

The reply to a node-originated UDP flow (host DNS, NTP) must come back in
through an isolated node's gate. TCP needs nothing (SYN-gate); UDP gets an
`hf_ct` LRU pin (the `np_ct` shape: `{self, peer, sport, dport, proto}`),
written where the outbound query passes — which is three places, because
node-originated traffic takes three exits:

1. **node → off-cluster**: `from_pod` at the uplink egress falls through to
   the same `hf_ingress` tail call; the `src ∈ hf_self` arm writes the pin.
   Zero new code in `from_pod` itself.
2. **node → remote pod** (hostNetwork pods resolving cluster DNS via
   socket-LB are exactly this): the flow leaves via `from_pod`'s
   `remotes`-hit encap, never reaching the fall-through — a small inline
   write (percpu scratch, no new stack) just before the encap.
3. **node → local pod**: the flow's only datapath crossing is the
   destination's `to_pod` — a sibling-callee write there (siblings don't
   stack; the np_ingress/np_egress precedent).

The reply is then checked wherever it enters: `from_overlay` (remote pod),
`from_pod` veth (local pod), or `lb_ingress` miss (external) — all funnel
into the same `hf_ct` probe. Enabling a HostFirewall mid-flight can drop
the replies of UDP flows begun before the pins were being written; DNS
retries, and the next query re-pins.

### Maps

| Map | Type | Key → value |
|-----|------|-------------|
| `hf_self` | HASH | this node's addresses (`addr128`) → 1 |
| `hf_allow` | LPM_TRIE | `{prefixlen; u8 proto; u8 pad; u16 port(be); addr128 src}` → u8 allow(1)/deny(0). Fixed 32 bits ahead of the address; a v4 CIDR /n is `prefixlen 32+96+n` (NAT64 form), v6 /n is `32+n`. Port is exact in the fixed section (`0` = any-port row); `endPort` ranges expand to ≤64 per-port rows (warn + fail closed beyond — the NetworkPolicy `ipBlock×endPort` precedent, and node services don't span wide ranges) |
| `hf_eallow` | LPM_TRIE | the egress twin of `hf_allow`; the address is the **destination** |
| `hf_ct` | LRU_HASH | `{self, peer, sport(be), dport(be), proto}` → 1 (the `np_ct` shape). Written on BOTH admitted directions, so each direction's reply passes the other's gate |
| `hf_drops` | PERCPU_ARRAY(2) | drops by direction → `cozyplane_hf_drops_total{direction}` |

`CFG_HF_ENABLED` / `CFG_HF_EG_ENABLED` (params 9/10) arm each direction
independently — an Egress-only object leaves ingress open, and vice versa; the
tail calls fire when either is set. `CFG_HF_ENABLED` arms the tail calls and pin writes; the agent
sets it **after** the rule sync on enable and **before** clearing on
disable, so there is no fail-open window. `CFG_GENEVE_PORT` carries the
overlay port for the baseline exemption. Like `np_allow`, `hf_allow`
overflow is fail-closed by construction (isolation is the flag, the map
holds allows) — `cozyplane_hf_sync_errors_total` counts sync failures.

## Agent

`watchHostFirewalls` (the `watchSecurityGroups` shape: shared informer off
the sdn factory, mutex'd full recompute on any event): list all
HostFirewalls, match `spec.nodeSelector` against **this node's** labels
(each agent compiles only its own node's view — no cross-node identity, no
coordination), union the matching objects' rules into `hf_allow` entries,
diff-sync, then flip `CFG_HF_ENABLED`. Node label changes re-trigger the
same recompute (the agent watches its own Node object). `hf_self` is fed
alongside the existing self-`SetNPNode` call, same address set.

Compilation notes:
- empty `from` ⇒ `0.0.0.0/0` + `::/0` rows; empty `ports` ⇒ any-port rows
  for both TCP and UDP (NetworkPolicy's defaulting).
- `except` ⇒ longer-prefix deny rows per `{proto, port}` of the rule;
  equal-key allow-wins dedupe across policies (the `np_cidr` union rule).
- invalid CIDRs / endPort < port: warn once, fail closed (skip the rule,
  never widen).

## Interactions with NetworkPolicy

network-policy.md's documented deviation — "node-destined egress is exempt
(revisit with the host firewall)" — is now resolved as designed: a pod's
node-destined traffic is gated **at the destination node's HostFirewall**
(destination-side, placement-independent, the same side every other
cozyplane policy layer enforces on), not by the pod's own egress rules.
The two layers compose: pod→pod is NetworkPolicy's, pod→node is
HostFirewall's, and a flow crossing both (pod→node) sees only HostFirewall
(NP's exemption) — one owner per contract, no double jeopardy.

## Egress (increment 2)

`spec.policyTypes` mirrors upstream NetworkPolicy: default `[Ingress]`,
plus `Egress` when `spec.egress` is present; a node selected by an object
whose types include `Egress` is **host-egress isolated** — its own new
TCP/UDP flows to gated destinations are default-deny, opened by
`egress: [{to: [{cidr, except}], ports: [...]}]` rules (same shapes,
unions, and fail-closed compilation as ingress).

What egress isolation gates — and deliberately does not:

- **node → external** and **node → remote pod**: gated. The second is the
  apiserver→webhook shape — isolating egress on control-plane nodes is the
  operator explicitly signing up to allowlist their webhook/aggregated-API
  destinations (pod CIDRs, specific ports).
- **node → node: exempt, structurally.** This is what makes egress
  isolation safe to ship at all: kubelet↔apiserver, etcd peering, and the
  **agent's own apiserver access** are all node→node, so the self-lockout
  failure mode ("the firewall cuts the agent off from the API that could
  fix it") cannot occur. Gating node→node remains a non-goal.
- **node → local pod: exempt** in this increment. Kubelet probes are
  same-node node→pod and indistinguishable at L3/4 from any other local
  node→pod flow; gating them would put readiness one bad rule away from
  cluster-wide NotReady (the plumbing argument, policy-layers.md).
  Revisit under path-trust if kubelet-socket provenance ever becomes
  attributable.

Statefulness is symmetric with ingress via the same `hf_ct` map: an
ingress-**admitted** pod→node UDP flow now writes the pin (the key the
ingress check already computes), so the node's reply passes the egress
gate; a node-originated UDP flow is gated first and pins on admit, so its
reply passes the ingress gate. TCP is SYN-gated in both directions.

Datapath: `hf_eallow` (an LPM twin of `hf_allow`), `CFG_HF_EG_ENABLED`
(params 10, armed after sync like ingress). Two enforcement points:
node→external rides the existing `hf_ingress` node-originated arm (the
uplink-egress fall-through), which gains the gate ahead of its pin write;
node→remote-pod leaves through `from_pod`'s remotes-hit encap, which
tail-calls a new `cozyplane_hf_egress` program (lb_prog slot 3) for
TCP/UDP node-sourced flows — it re-resolves the remote and performs the
encap itself on admit (a tail call never returns), drops on deny, and an
unpopulated slot falls through open to the inline encap.

## Non-goals (increment 2)

- **Entity/selector peers** (`from: {pods: ...}` by label): sources are
  CIDRs in v1. Pod fabric CIDRs are cluster-assigned and non-overlapping,
  so "all pods" is expressible today; identity-based peers can reuse the
  `np_ident` machinery later if wanted.
- **SCTP**, matching the rest of the datapath.
- Gating **node→node** (see baseline) and **loopback/link-local** self
  addresses (`hf_self` is the Node-object address set).
- **Audit mode**. `hf_drops` + a `kubectl delete` is the v1 story.

## e2e

The `HF` phase of `test/e2e.sh` (kind, dual-stack): a hostNetwork listener
pod stands in for a node service; an external docker client and net-0 pods
(same- and cross-node) probe it through: no-policy baseline, empty-rules
isolation (refused for external + both pods; node stays Ready, kubectl
lives, overlay/cross-node pod traffic unharmed, ICMP passes), per-CIDR and
per-port admits, `except` carve-outs, v6 twins, node exemption (hostNetwork
client from another node admitted with no rule), and the UDP pins
(hostNetwork pod on the isolated node resolves cluster DNS — the
node→pod pin — and dials an external UDP echo — the off-cluster pin).
Deletion reopens. Real-cluster validation on the dev cluster follows the
NetworkPolicy playbook: workers first, allow-all → narrow, with the
monitoring scrape path (Prometheus pod → node:9411/10250) as the live
proof that pod→node gating works and is openable.
