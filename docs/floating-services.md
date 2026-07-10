# Floating Services — a public address for a VPC service (design draft)

**Status: DESIGN DRAFT (awaiting review).** Nothing here is built.

## The problem

A tenant can expose a single workload to the world (a `FloatingIP` targeting a
tenant IP — 1:1, source-preserving, eBPF-native) and can load-balance inside
the VPC (a `ServiceVIP` fronting an annotation-attached Service). What they
cannot do is combine them: **a public address fronting a multi-backend VPC
service** — `type: LoadBalancer` semantics for tenants, without leaking the
Kubernetes Service abstraction or the cluster's LB machinery into the VPC.

This was deferred explicitly: the floating-IP design (#5) resolved its
bind-granularity question as "a single tenant IP; a VIP variant can layer on
once Services exist." Services exist now ([services-in-vpc.md](services-in-vpc.md),
increments 1–3 built).

## What exists, and the one thing that doesn't compose

- **Floating IPs** (internals.md § "Floating IPs"): `floating` map
  (`publicIP → {net, vpcIP}`), advertisement *in* `from_uplink` (ARP/NDP
  answered only where the target pod is local), inbound DNAT in `to_pod`
  preserving the client source, GARP/unsolicited-NA on (re)programming.
  Anchoring is **decentralized**: each agent programs a floating IP iff the
  target Port's `spec.node` is itself (`desiredFloating`) — the Port's single
  location *is* the election.
- **ServiceVIPs** (internals.md § "ServiceVIPs"): `svc_vips[{net, vip, proto,
  port}] → ≤16 backends`, selection by avalanched multiply-shift hash, flow
  pinned in `svc_fwd`/`svc_rev` **on the client's node**, where both directions
  of the flow are guaranteed to pass.
- **The non-composing part**: a VIP has backends on many nodes, so the
  decentralized anchor rule ("program where the target is local") would have
  *several* nodes answering ARP for one public address — the MetalLB-L2
  problem, unstable per client cache. And "the client's node", where all
  service NAT state lives, doesn't exist for an external client.

Both gaps close with the same move.

## Design: anchor on a backend node, select local-only

**Elect one backend-hosting node as the anchor; it advertises the public IP
and DNATs only to backends on itself.** The Kubernetes analogue is
`externalTrafficPolicy: Local`, and it buys three properties at once:

- **The election is minimal.** The controller picks the anchor and records it;
  agents program the `floating` entry only where `status.node` names them.
  One ARP speaker, as today — just chosen by the controller instead of
  implied by a Port.
- **All NAT state is node-local.** The anchor is both "the client's node"
  (where `svc_fwd`/`svc_rev` pin the flow) and the backend's node (where the
  reply passes `from_pod`). No cross-node forward, no reply steering, no new
  conntrack shape.
- **The client source is preserved** — the floating path's signature property.
  No masquerade is needed because the reply exits the node the state lives on.

### API

Identity, not addresses (design tenet): the FloatingIP follows the *Service*,
not the VIP address — a VIP is the movable kind by construction (Port-always-wins
repair reallocates it), so binding to its address would silently break on
repair. `spec.target` and `spec.serviceRef` are mutually exclusive:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  serviceRef: {name: web}     # Service in this namespace; resolved via its ServiceVIP
  # poolRef / address as today
status:
  address: 203.0.113.7
  node: node2                 # the elected anchor
```

Resolution: `serviceRef` → the attached Service's `ServiceVIP` (by the
`service-namespace`/`service-name` labels, within `vpcRef`'s VPC). `TargetLive`
generalizes to "the ServiceVIP exists and ≥1 backend is ready"; a new
`Anchored` condition reports the election. All the VIP's declared ports are
exposed on the public address (no per-port subsetting in v1).

### Anchor election (controller)

- Candidates: nodes hosting ≥1 ready backend of the VIP (from
  `ServiceVIP.status.backends` joined with Ports' `spec.node`).
- **Sticky**: keep the current anchor while it remains a candidate; re-elect
  only when it stops hosting any ready backend (or the node goes away).
  Deterministic tie-break (lowest node name) so reconciles converge.
- On re-election the agent's existing announce path fires (GARP/unsolicited
  NA on programming) — external caches re-learn exactly as for a pod move.
  Established flows die with the old anchor; same class as any L2 failover.

### Datapath

No new maps. The composition is a lookup order in the existing hooks:

- **`from_uplink`** (inbound): `floating[public] → {net, X}` as today; then
  `svc_vips[{net, X, proto, dport}]` — a **hit** means X is a VIP, not a pod.
  Select among the backends that are **local** (`locals[{net, be.ip}]` hit),
  hash-pinned via `svc_fwd`/`svc_rev` exactly as `from_pod` does for in-VPC
  clients; DNAT `public:port → backend:target` **here** (unlike pod-mode,
  which defers the rewrite to `to_pod` — service mode must rewrite where it
  selects), keep the client source, redirect to the backend's veth. A miss
  falls through to today's pod-mode path unchanged.
- **`to_pod`** (delivery): sanctioned by the `svc_rev` entry the anchor just
  wrote (same-node by construction), the same way an in-VPC service flow is.
  SecurityGroups gate unconditionally, as on every floating DNAT point
  (north-south `from: {cidr}` rules apply against the backend's groups).
- **`from_pod`** (reply): a `svc_rev`-keyed hit for an external client SNATs
  `backend:target → public:port` and `bpf_redirect_neigh`s out the uplink —
  the same exit the floating egress path uses — checked before the
  internal/gateway fallthrough.
- **v6**: the same composition; `floating_ndp` advertisement and the v6
  DNAT/SNAT halves already exist.

### Semantics worth stating

- **Inbound-only.** Backends do *not* egress from the public address (a pod
  `FloatingIP`'s EIP behaviour). A service address shared by N pods cannot be
  a source address without a masquerade, and LB semantics don't promise it.
  Backends keep their normal egress (gateway or their own floating IP).
- **In-VPC clients keep using the VIP** — the resolver keeps answering the
  VIP for the service name; the public address is for the world. Reaching the
  public IP from inside the VPC traverses the tenant's egress gateway out and
  back through the physical L2 (works when egress is enabled; not a promised
  path otherwise).
- **Local-only selection skews load** toward the anchor's backends — by
  design in v1 (it is what buys source preservation and zero new state). A
  future `Cluster`-policy mode (cross-node fan-out behind a client masquerade
  at the anchor) shares its machinery — uplink masquerade ct + backend-set
  DNAT at `from_uplink` — with KPR increment 3 Half B (#13); build them
  together, later, if the skew matters in practice.

## Increments

1. **Control plane** — `spec.serviceRef` (+ validation: exactly one of
   target/serviceRef), VIP resolution, `TargetLive` generalization, anchor
   election + `status.node`, `Anchored` condition; the agent's
   `desiredFloating` gains the "status.node == self" mode. kind-testable
   (CRD mode: everything but the ARP answer).
2. **Datapath** — the `from_uplink` service branch (local-only select, pin,
   DNAT), `to_pod` sanction, `from_pod` reply SNAT, SG gating, v4+v6.
3. **e2e + docs** — external client → public IP → multi-backend service:
   flow stickiness across requests, backend churn re-anchors + GARP observed
   on the wire, client source preserved at the backend, two VPCs with
   overlapping CIDRs each fronting their own service. User-guide section.

## Open questions

- **Where the election lives**: `FloatingIP.status.node` (proposed — one
  fewer object) vs a Port-like anchor object (would make the agent's view
  uniform: everything it programs is a Port). Leaning status field; revisit
  if the agent-side special case grows.
- **Anchor placement quality**: v1 elects any backend node. Weighting by
  local-backend count (less skew) is a cheap follow-up inside the same
  election.
- **Port subsetting** (`spec.ports` on the FloatingIP): deferred until a
  tenant asks; all VIP ports exposed in v1.

## Non-goals

- Not `type: LoadBalancer` for the cluster's own Services — this is
  tenant-facing, VPC-scoped; the cluster keeps its LB layer (and #13 Half B
  covers NodePort/LB per-packet DNAT for the default net).
- No BGP/ECMP advertisement — same L2-only stance as pod floating IPs; the
  BGP tail is tracked in the roadmap and lifts both when it lands.
- No shared-address port multiplexing across FloatingIPs (two services on one
  public address): one FloatingIP, one address, one service.
