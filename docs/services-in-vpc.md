# Services in a VPC — per-VPC VIPs & split-horizon DNS

**Status: IMPLEMENTED (increments 1–3).** Reviewed 2026-07-06 and built the
same week; the per-increment as-built notes are inline below. Prioritized
ahead of the kube-proxy replacement work
([kube-proxy-replacement.md](kube-proxy-replacement.md)); the per-packet
service NAT built here is the foundation that draft's increment 3 later
builds on.

## The problem

ClusterIP Services do not work from inside a VPC **today**, and no planned
work fixed them. A VPC pod's packet to a ClusterIP hits `from_pod` before any
other machinery; the destination is neither in the VPC nor peered, so
default-deny drops it (with an egress gateway it is masqueraded toward the
internet, where a service VIP is equally dead). kube-proxy never sees the
packet, and the imported socket LB wouldn't help: it rewrites `connect()` to
the backend's **fabric** IP, which `from_pod` rightly refuses — and VM guests
bypass socket hooks entirely.

Motivating case (raised in the initial design phase): an etcd cluster deployed
in a VPC. Its members find each other through headless-Service DNS and its
clients dial a ClusterIP Service by name. Neither works. The failure
decomposes into three separable gaps:

1. **DNS transport** — kube-dns is itself a ClusterIP with default-network
   backends; a VPC pod can't reach any resolver at all.
2. **Headless records** — DNS answers carry `status.podIP`, i.e. fabric IPs,
   which are not addressable from inside the VPC. The answers must instead
   carry VPC IPs (the Port objects know both sides of the mapping).
3. **ClusterIP** — a VIP that something must load-balance and DNAT. DNS
   rewriting alone cannot fix this; it needs a data plane.

## The model

**A Service attached to a VPC gets a VIP allocated from the VPC's own address
space**, the split-horizon resolver answers the service name with that VIP,
and a net-scoped map in `from_pod` DNATs the VIP to a backend's **VPC IP**.
The cluster ClusterIP never appears inside the tenant.

Why per-VPC VIPs rather than reusing the ClusterIP (the design fork that was
reviewed): the resolver rewrites VPC-bound answers regardless (headless
records force it), so "DNS unchanged" was never on the table. Allocating from
the VPC's space then wins on all counts:

- **No shadowing hazard.** A tenant whose CIDR overlaps the cluster's service
  CIDR needs no precedence rule — VIPs come from the tenant's own pool, so
  collision is impossible by construction.
- **Tenet alignment.** No cluster-global address leaks into tenant space;
  the VIP is a per-net implementation detail (design.md §1 tenet 3).
- **Family freedom.** A v6-only VPC gets a v6 VIP for a Service whose
  ClusterIP is v4 — backends are Port VPC IPs, so the upstream Service's
  family is irrelevant. No NAT64 in the service path.

Accepted costs, to document loudly: kubelet's legacy service **env vars**
(`FOO_SERVICE_HOST`) carry the cluster ClusterIP and are dead inside a VPC,
and any client that reads `Service.spec.clusterIP` via the API and dials it
literally breaks. **DNS is the discovery mechanism in a VPC.** (etcd and
essentially all modern charts qualify.)

### Attachment — which Services project into a net

Explicit — nothing auto-projects: another tenant's Services, kube-system
Services, and the API server simply do not exist inside a net. The mechanism
is the one remaining open question (Q1 below), two candidates:

- **(A) Annotation on the Service** (`sdn.cozystack.io/vpc: <name>`),
  authorized by the `VPCBinding` in the Service's namespace — the exact
  pod-attach idiom; the controller materializes the `ServiceVIP` the way the
  system materializes Ports for annotated pods.
- **(B) A user-created attachment object** (spec: `vpcRef` + `serviceRef`)
  whose **status** carries the VIP — one object instead of
  annotation-plus-materialized-object, with typed spec room and separable
  RBAC, at the cost of a second user-facing kind and a two-manifest UX.

Either way the controller validates that ready endpoints resolve to Ports of
that VPC (mixed/foreign backends are ignored and surfaced as a condition).

### VIP allocation — `ServiceVIP`, and cross-kind uniqueness

A VIP is an allocation with no pod, held by a new small object (working name
`ServiceVIP`; **decided against** modeling it as a special Port — Port
semantics stay clean), one per family present in the VPC. Deterministic
choice is unnecessary because DNS is the only advertised path to it.

Two kinds now draw from one per-net IP keyspace, and a Port and a
`ServiceVIP` must never hold the same VPC IP. Layered design:

1. **One allocator view.** Every allocator of net-scoped IPs (VIP allocation,
   the CNI's Port claim at ADD, the gateway `.1`) allocates against the
   live-read (APIReader, per the VNI-duplicate lesson) **union of claims
   across both kinds**, serialized per VPC where the allocation happens
   in-process.
2. **Fail closed at the API** *(deferred as-built)*: the registry strategies
   have no cross-kind reader today, so this layer is not implemented. In its
   place, **both allocators check the live union** (the controller's VIP walk
   lists Ports + ServiceVIPs; the CNI's Port claim now also counts
   ServiceVIPs as used) and they **walk from opposite ends** of the CIDR
   (Ports bottom-up from `.2`, VIPs top-down from the last address), so a
   collision requires a nearly-exhausted pool plus a lost race — which layer
   3 then repairs.
3. **Deterministic repair backstop.** If a duplicate ever materializes (cache
   lag, CRD mode), **the Port always wins**: Port IPs are workload- and
   VM-pinned identity and immovable, while a VIP is movable *by construction*
   — nothing addresses it except through a DNS answer, so the loser VIP
   re-allocates and the resolver's next answer carries the new address.

Rejected simplification: a tenant-declared `serviceCIDR` sub-range (disjoint
pools, no race by partitioning) — it adds required per-VPC configuration to
dodge a problem the layers above close; kept only as an escape hatch if the
shared pool proves fragile in practice.

### DNS — split-horizon resolver

A per-node responder, **the same process as the metadata responder** in
[vm-provisioning.md](vm-provisioning.md) (decided in review): one node-local,
less-privileged-than-the-agent service with two listeners (DNS + metadata
HTTP), sharing the datapath steering and the per-net source identification.

- `from_pod` intercepts `dst == cluster DNS IP, port 53` from VPC pods and
  redirects to the node-local resolver, identifying the querying net the same
  way the metadata design does (rewritten per-Port source). Zero guest/pod
  config: kubelet's `resolv.conf` and a VM's RA/DHCP-provided resolver both
  keep pointing at the address they already use.
- **Cluster-domain names are answered authoritatively, never forwarded**:
  attached ClusterIP services → the per-VPC VIP; headless services of the VPC
  → member **VPC IPs** (A/AAAA and SRV targets); every other cluster-domain
  name → NXDOMAIN. Not forwarding these to the real kube-dns both prevents
  probing other tenants' existence and avoids handing out dead-end cluster
  ClusterIPs.
- **Names follow reachability across peerings**: a service attached to a VPC
  the querier's VPC is *actively* peered with (a Ready `VPCPeering` half —
  mutually created, disjoint CIDRs) resolves too, answered with the peer's
  backend VPC IPs, which the peered datapath delivers natively. Disjointness
  makes the answers unambiguous; anything short of a Ready peering stays
  NXDOMAIN.
- **The cluster domain is autodetected** from the responder's own
  kubelet-written search path (the DaemonSet runs `ClusterFirstWithHostNet`,
  so the cluster search domains are present despite hostNetwork — distinct
  from the *node's* resolv.conf it forwards upstream to); the `clusterDomain`
  chart value overrides.
- **Everything else defers upstream, kube-dns-style** (decided in review):
  non-cluster names forward to the node's upstream resolvers — the same
  upstreams kube-dns itself uses — from day one. A deliberate, documented
  system service, like metadata; not an isolation hole: answers are data,
  reachability still requires an egress path.

### Datapath — net-scoped service NAT in `from_pod`

One new map plus the existing ct machinery (bridge/masquerade tables):

```
svc_vips[{net, VIP(addr128), proto, port}] → backend set (VPC IPs) + flags
```

- Forward: `from_pod` looks up `{net, dst}`; on hit, pick a backend (5-tuple
  hash, v1 — maglev can come later with the KPR import), DNAT dst to the
  backend's VPC IP, record in ct, and fall through to normal intra-VPC
  delivery (locals/remotes/overlay — placement-independent by construction).
- Reverse: replies arrive at the *client's* node and traverse its return hook,
  where the same node's ct entry rev-SNATs the backend IP back to the VIP —
  the established masquerade pattern (forward and reverse on the same node's
  tables).
- Hairpin (a backend dialing its own service and selecting itself) needs the
  standard loopback-SNAT trick — a per-net reserved loopback address, one
  line of IPAM. Known wrinkle, not a blocker.
- Backends are only ready endpoints; the agent syncs from the controller's
  resolved view (EndpointSlice → fabric IP → Port → VPC IP join happens in
  the controller, not the datapath).

VM guests are covered for free: bridge-binding traffic traverses the pod veth,
so `from_pod` sees it — containers and VMs get identical service semantics,
which socket-based approaches structurally cannot offer inside a VPC.

### Composition

- **Security groups** ([security-groups.md](security-groups.md)): DNAT happens
  at `from_pod` before delivery, so `to_pod` enforcement sees the real client
  VPC IP as source and the backend VPC IP as destination. Rules never need to
  know VIPs exist.
- **KPR** ([kube-proxy-replacement.md](kube-proxy-replacement.md)): this lands
  first and needs no Cilium import — the controller watches Services and
  EndpointSlices with plain client-go. When KPR arrives, its imported StateDB
  tables can feed the same `svc_vips` map for net 0 (default-network VMs,
  NodePort), unifying both worlds on one datapath primitive. This also settles
  that draft's review Q2: the feed is tables → our maps; Cilium's map ABI
  could never express net-scoped VPC-IP backends.

## The etcd walkthrough (acceptance case)

etcd pods (or VM-hosted members) in `vpc-a`, Services annotated into the VPC:

1. Peer discovery: `etcd-0.etcd-headless.ns.svc` — resolver answers the
   member's **VPC IP**; plain intra-VPC traffic, nothing new in the datapath.
2. Client path: `etcd-client.ns.svc:2379` — resolver answers the per-VPC VIP;
   `from_pod` DNATs to a member's VPC IP, ct pins the flow, replies rev-NAT.
3. Failover: EndpointSlice change → controller updates the backend set →
   agent syncs the map; established flows to the dead member die and re-dial
   through DNS/VIP as they would anywhere.

## Increments

1. **Resolver + headless + upstream forwarding** — per-node split-horizon
   resolver (shared with metadata), DNS interception in `from_pod`, headless
   answers as VPC IPs, non-cluster names forwarded upstream. Already unblocks
   etcd *peer* traffic and all name-based intra-VPC addressing. kind-testable.
   **Implemented and validated on dev4 (2026-07-06)** — `dns_steer`/`dns_return`
   in the datapath (the pod's fabric IP is the rewritten source and the
   per-Port identity handle), `cmd/responder` as an unprivileged second
   container in the agent DaemonSet, e2e-covered on kind (kube-proxy) and
   validated on dev4 (Talos + Cilium KPR): headless answers as VPC IPs with
   same-node and cross-node delivery, per-hostname records, UDP + TCP, upstream
   forwarding via the node resolvers, authoritative NXDOMAIN across tenants,
   and the running VM untouched by the upgrade. As-built details: internals.md
   § "VPC DNS steering" — including the `dns_ct` twist that makes steering
   work under a socket-LB kube-proxy replacement (Cilium KPR forces socket LB
   on, so the wire destination is a backend, not the ClusterIP).
   Known limitation: a VPC pod whose fabric IP is the *other* family (the
   fabric-family fallback) has no same-family handle and is not steered — the
   v6-VPC-on-v4-cluster case additionally needs the RA/RDNSS work (#8) before
   guests even have a usable v6 resolver address.
2. **VIP data plane** — `ServiceVIP` + cross-kind uniqueness, `svc_vips`
   map, DNAT/rev-NAT, attachment + controller. Closes the ClusterIP gap;
   etcd e2e as above.
   **Implemented** — the controller materializes a cluster-scoped
   `ServiceVIP` per attached non-headless Service (name `sv<vni>.<ip>` = the
   atomic claim, VPCBinding-gated like pods), resolves ready endpoints to
   backend VPC IPs with per-port targets in status, and the agents project
   them into `svc_vips`. `from_pod` DNATs `vip:port → backend:target` after
   admission (so peered clients get VIPs too), pins each flow in an LRU ct
   (a backend-set change never moves established TCP), and the client's
   `to_pod` rev-SNATs the reply. Self-dials hairpin via a reserved loopback
   (`169.254.42.1` / `fe80::2a01`) on the pod's own veth. v1 limits: TCP/UDP
   only (no ICMP-to-VIP, no SCTP), ≤16 backends per port (excess truncated,
   logged), backend choice is a 5-tuple hash (no maglev/affinity yet).
   The resolver answers attached ClusterIP services with the VIP (A/AAAA and
   `_port._proto` SRV); the cluster ClusterIP never appears in a tenant.
3. **VM resolver config** — ties into vm-provisioning's RA/DHCP so guests
   learn the resolver without manual config.
   **Implemented** — the agent's userspace RA responder
   (vm-provisioning.md Part 1, as-built note there): a v6 guest
   autoconfigures its pinned `/128` by SLAAC and receives RDNSS when a v6
   resolver path exists; v4 guests already get the cluster DNS from
   KubeVirt's DHCP, which the steering then serves. The v6-VPC-on-v4-cluster
   DNS *transport* remains gated on cross-family (#9 / cross-family.md).

## Review resolutions (2026-07-06)

- **VIP in the API**: a new `ServiceVIP`-shaped object, not a special Port.
  The uniqueness hurdle (a Port and a ServiceVIP must never hold the same VPC
  IP) is addressed by the three-layer design above: one live-read allocator
  view over both kinds, fail-closed cross-kind validation in the aggregated
  registry, and Port-always-wins repair (VIPs are the movable kind).
- **Resolver scope**: kube-dns-parity — authoritative for the cluster domain
  (answer or NXDOMAIN, never forward), everything else defers to the upstream
  forwarder, from day one.
- **Responder packaging**: one per-node process serves both split-horizon DNS
  and the metadata endpoint.
- **Ordering**: confirmed — this draft precedes all KPR work; increment 1 is
  the first shippable slice.

- **Attachment UX (resolved 2026-07-06): option A** — annotation on the
  Service (`sdn.cozystack.io/vpc: <name>`) + controller-materialized
  `ServiceVIP`, the pod→Port idiom; the `VPCBinding` is the authz gate, as
  for pods. One idiom for tenants: "annotate the thing into the VPC."
  Escape hatch by precedent if per-attachment knobs ever become real:
  persistent Ports are user-created while ordinary Ports are materialized —
  `ServiceVIP` can grow the same dual pattern.

**Projection is annotation-gated for headless Services too** — nothing
auto-projects, and the resolver's authz proof is structural: it only answers
with backends that are Ports of the *querying* net, so a stray annotation
without a real binding yields nothing (Ports of that net wouldn't exist).
