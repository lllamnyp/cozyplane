# LoadBalancer ingress — `type: LoadBalancer`, eBPF-native (design draft)

**Status: DESIGN DRAFT (awaiting review).** Nothing here is built. Tracks
[#13](../../issues/13).

## The problem, and the fixed requirements

cozyplane owns Services (socket-LB + the net-0 per-packet fallback), but a
`type: LoadBalancer` Service still has no way to receive traffic addressed to
its external IP: nothing allocates that IP, nothing announces it, and nothing
DNATs it on arrival. On a Cilium-free, kube-proxy-free cluster that is the
last missing piece of the Service contract — and it is also the public path
for VPC-backed services (their fabric IPs are ordinary endpoints; the bridge
does the rest — services-in-vpc.md § Composition).

Requirements fixed by review (2026-07-10):

1. **The API is the Kubernetes Service.** No new tenant-facing kinds — this
   implements the primitive, it does not wrap it.
2. **No NodePort in the path.** MetalLB delivers `loadBalancerIP` traffic
   without NodePort; so does this. (External NodePort is a separate,
   low-priority item.)
3. **`externalTrafficPolicy: Local` is the supported mode and it preserves
   the client source IP**: deliver only to node-local ready backends, no
   second hop, no masquerade.

## What already exists

Every mechanism this needs is already built; the design is mostly wiring:

- **`cozyplane-kpr`** runs as a per-node DaemonSet, watches Services +
  EndpointSlices with plain client-go, and already writes this node's pinned
  `svc_vips` map at net 0 (ownership partitioned by net; the agent owns
  net ≠ 0). It is the natural owner of "which LB entries does *this node*
  program".
- **`ExternalPool`** is already the admin-facing public-address range with an
  `advertisement` mode — nothing in its spec is FloatingIP-specific. The
  FloatingIP controller has the sticky lowest-free allocator.
- **`from_uplink`** already answers ARP/NDP for programmed public addresses
  and announces on (re)programming (GARP / unsolicited NA); the floating path
  already exits replies via `bpf_redirect_neigh` out the uplink.
- **`svc_fwd`/`svc_rev`** already pin service flows per node with the
  avalanched multiply-shift backend selection.

## Design

### Control plane: allocate and report

A small LB controller (in `cozyplane-kpr`'s hive or the cozyplane
controller — increment 1 decides; leaning kpr, which already owns Services):

- **Which Services**: `type: LoadBalancer` with `loadBalancerClass` unset or
  `sdn.cozystack.io/l2`. Anything else is another provider's.
- **Allocation**: from an `ExternalPool` (annotation
  `sdn.cozystack.io/pool: <name>` selects one; single pool is the default,
  as for FloatingIPs). The free-set is the **live union of FloatingIP
  addresses and Service LB IPs** across pools — one keyspace, two consumer
  kinds, same lesson as Ports/ServiceVIPs. Allocation is serialized
  in-process in one controller; `spec.loadBalancerIP` (or the
  `metallb.io`-style annotation — increment 1 decides which to honour) is
  honoured when free and in-range; assignment is sticky.
- **Report**: set `status.loadBalancer.ingress[0].ip`. That is the entire
  tenant-visible API.
- **Policy gate**: `externalTrafficPolicy: Cluster` is *deferred* in v1 —
  the controller emits a clear event and does not allocate/announce. To be
  precise about why (it does **not** need NodePort): Cluster mode is DNAT to
  any ready backend cluster-wide plus a **client SNAT at the point of
  ingress**, so the reply returns through the ingress node — the eBPF
  masquerade ct at the uplink is the natural home for that SNAT, and by
  definition the mode gives up source preservation. Deferred purely as a v1
  scope cut. (Known later alternative that avoids even the SNAT: DSR —
  carry `{client, lbIP}` in Geneve metadata so the backend's node replies
  directly from the LB IP.)

### Announcement: deterministic, no new election machinery

An LB IP must be answered by exactly one node (the MetalLB-L2 problem), and
under `etp: Local` only nodes with a local ready backend may attract traffic.

Every node's kpr computes the announcer **deterministically from shared
inputs**: candidates = nodes hosting ≥1 ready endpoint of the Service
(EndpointSlices carry `nodeName` + readiness); announcer = a stable choice
over that set (lowest node name, with stickiness: keep the incumbent while it
remains a candidate). All kpr instances see the same EndpointSlices, so they
converge on the same answer with **no election protocol, no new API field,
no leader lease** — a node announces iff it names itself. Programming the
address fires the existing GARP/unsolicited-NA announce; when the announcer
changes, external caches re-learn exactly as for a floating-IP move.

Honest failover bound: the trigger is endpoint readiness/EndpointSlice
propagation. Pod-level failures re-point in seconds; a *node* crash re-points
when its endpoints go unready (kubelet/node-lifecycle latency, not
memberlist-fast). Acceptable for v1; BGP/ECMP later lifts both this and the
floating-IP L2 story at once.

### Datapath: `from_uplink` in, `from_pod` out, all state node-local

Backends here are **pod fabric IPs at net 0** — the same table the net-0
ClusterIP fallback uses. Each node's kpr writes `svc_vips[{net 0, lbIP,
proto, port}]` with **only its own node's ready backends** (etp: Local is a
per-node filter, not a datapath mode). Programmed on every candidate node
(so delivery works wherever traffic lands), announced from one.

- **Inbound** (`from_uplink`): dst = `lbIP:port` hits the net-0 `svc_vips`
  probe (a miss falls through to today's floating/pod path unchanged).
  Select a backend (all local by construction), pin the flow in
  `svc_fwd`/`svc_rev`, DNAT `lbIP:port → podIP:targetPort`, **keep the
  client source**, deliver by identity to the local veth.
- **Reply** (`from_pod`): the backend answers the external client directly;
  the `svc_rev` hit un-NATs `podIP:targetPort → lbIP:port` and
  `bpf_redirect_neigh`s out the uplink — the floating egress exit. All NAT
  state lives on the one node both directions traverse.
- **VPC-pod backends**: the DNAT target is the pod's *fabric* IP, so the
  bridge translates fabric → VPC as for any north-south flow — but the
  bridge's client masquerade must be **suppressed for pinned LB flows**
  (source preservation is the point; the reply path above already returns
  through the same node, which is all the masquerade exists to guarantee).
  `to_pod` sanctions the flow by its `svc_rev` entry, same-node by
  construction; SecurityGroups gate unconditionally at the DNAT point, as on
  every north-south path.
- **v6**: same composition — pools are dual-family, the NDP responder and v6
  NAT halves exist. Both families in scope.

### What this replaces and how it relates

- **Replaces MetalLB (L2 mode) on cozyplane clusters** — allocation +
  announcement + delivery, one component fewer, and the delivery half is
  eBPF instead of kube-proxy round-trips.
- **`FloatingIP` vs LB IP**, both drawn from `ExternalPool`: a FloatingIP is
  a 1:1 *pod* address (bidirectional, EIP egress, source-preserving by
  bijection); an LB IP is *Service* ingress (inbound-only, load-balanced,
  source-preserving by locality). The union allocator keeps them from
  colliding.
- **NodePort**: explicitly not in the path and not built here (#13).

## Increments

1. **Control plane** — allocation from ExternalPool (class gate, union
   free-set, sticky, `spec.loadBalancerIP`), `status.loadBalancer` reporting,
   the etp: Cluster rejection event. kind-testable with no datapath.
2. **Datapath + announcement, default-net backends, v4** — net-0 `svc_vips`
   LB entries (local-only backends), deterministic announcer + GARP,
   `from_uplink` DNAT + pin, `from_pod` reply un-NAT. e2e: external client →
   LB IP → 2-replica deployment; stickiness; **client source asserted at the
   backend**; announcer re-points on endpoint move (GARP observed).
3. **VPC-pod backends + v6** — masquerade suppression for pinned LB flows,
   SG gating verified, NDP announcement; e2e for both, including an
   overlapping-CIDR two-tenant exposure.

## Open questions

### Q1 — where the controller lives

Two jobs with different natures: **allocation** (one writer, cluster-wide,
must serialize against the FloatingIP allocator over the same pools) and
**programming/announcement** (per-node by construction).

- **Option A (leaning): split by nature.** Allocation in
  `cozyplane-controller` — it *already is* the single allocator over
  `ExternalPool` (FloatingIPs), so the union free-set stays serialized
  in-process in one place; adding a second allocator over the same keyspace
  in kpr would recreate exactly the two-uncoordinated-authorities disease
  the Port/ServiceVIP layer-2 work just closed. The allocation result is
  written to `status.loadBalancer.ingress`, which *is* the hand-off: each
  node's kpr consumes Service status + EndpointSlices and programs/announces
  its own node. No new API, no lease, crash-safe (recompute-idempotent, no
  claim object needed — a half-written allocation is re-derived from status
  on the next reconcile).
- **Option B: everything in kpr**, with a leader-elected allocation sliver.
  One component owns Services end to end, but it costs a leader lease, and
  the allocator either duplicates the pool view (two writers over one
  keyspace) or kpr must also absorb FloatingIP allocation — a much bigger
  move.

Decision rides on one principle: **one keyspace, one allocator.** A follow-on
detail for either option: `ExternalPool.status.allocated/available` today
counts only FloatingIPs; it starts counting LB IPs too.

### Q2 — how a user requests a specific address

`spec.loadBalancerIP` is deprecated upstream (since 1.24) because it cannot
express dual-stack (one field, one address) — but it is still present,
universally understood, and what most charts set. MetalLB's answer is the
`metallb.io/loadBalancerIPs` annotation (comma-separated, one per family),
with the field still honoured.

- **Option A: field only.** Simplest; dead end for dual-stack requests.
- **Option B: our annotation only** (`sdn.cozystack.io/loadBalancerIPs`,
  comma-separated, one address per family). Clean and dual-stack-capable,
  but silently ignores the field users actually set today.
- **Option C (leaning): both, annotation wins.** The field is honoured as a
  single-family request; the annotation is the dual-stack-capable form; if
  both are set and disagree, event + annotation wins. This is MetalLB's
  shape, so migrating a manifest is a key rename.

Explicitly *not* proposed: parsing `metallb.io/*` keys for drop-in
compatibility — migration is a sed, and honouring another project's
annotations is a trap when semantics drift. Related v1 scoping: dual-stack
Services (`ipFamilyPolicy: PreferDualStack/RequireDualStack`) get one LB IP
per family only once increment 3 lands; until then single-family, family
picked by the Service's first `ipFamilies` entry.

### Q3 — shared LB IPs (many Services, one address)

MetalLB's `allow-shared-ip`: Services carrying the same sharing key may
co-hold one address when their port sets are disjoint. Real uses: scarce
public v4, and TCP+UDP on one address across two Services (the classic
DNS-53 split before mixed-protocol Services).

The datapath is already indifferent — `svc_vips` keys on
`{ip, proto, port}`, so two Services on one IP with disjoint ports are just
more rows. What sharing actually costs is **control-plane rules**: the
sharing key + disjointness validation, equal `externalTrafficPolicy` across
holders, and — the subtle one — a **common announcer**: under `etp: Local`
all holders must have a ready local backend on the *same* node (the
announcer must be a candidate for every holder), which constrains scheduling
the way MetalLB's same-node requirement does.

Leaning: out of v1 (an explicit `spec.loadBalancerIP` collision is an event,
not a share), added later as a pure control-plane increment — unless
Cozystack deployments are v4-starved enough to want it in increment 1.

## Non-goals

- `externalTrafficPolicy: Cluster` — a v1 scope cut, not a dependency: it
  needs only an ingress-point client SNAT (see the policy gate above), or
  DSR later to avoid even that.
- BGP/ECMP advertisement (tracked with the floating-IP L2→BGP tail).
- Anything tenant-facing beyond the standard Service object.
