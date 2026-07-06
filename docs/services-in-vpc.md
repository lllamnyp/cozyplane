# Services in a VPC — per-VPC VIPs & split-horizon DNS (design draft)

**Status: DRAFT — not implemented.** Prioritized ahead of the kube-proxy
replacement work ([kube-proxy-replacement.md](kube-proxy-replacement.md)); the
per-packet service NAT designed here is the foundation that draft's increment 3
later builds on.

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

Explicit, mirroring how pods attach: the Service carries the same annotation
(`sdn.cozystack.io/vpc: <name>`), authorized by the same `VPCBinding` gate in
the Service's namespace. The controller validates that ready endpoints resolve
to Ports of that VPC (mixed/foreign backends are ignored and surfaced as a
condition). Nothing auto-projects: another tenant's Services, kube-system
Services, and the API server simply do not exist inside a net.

### VIP allocation

By the existing per-VPC IPAM — a VIP is an allocation with no pod, recorded on
a small `ServiceVIP`-shaped status (exact object TBD, review Q2), one per
family present in the VPC. The allocator already guarantees non-collision with
Port IPs and gateway `.1`s; deterministic choice is unnecessary because DNS is
the only advertised path to it.

### DNS — split-horizon resolver

A per-node responder (same placement pattern as the metadata responder in
[vm-provisioning.md](vm-provisioning.md), plausibly the same process):

- `from_pod` intercepts `dst == cluster DNS IP, port 53` from VPC pods and
  redirects to the node-local resolver, identifying the querying net the same
  way the metadata design does (rewritten per-Port source). Zero guest/pod
  config: kubelet's `resolv.conf` and a VM's RA/DHCP-provided resolver both
  keep pointing at the address they already use.
- Answers, per net: attached ClusterIP services → the per-VPC VIP; headless
  services of the VPC → member **VPC IPs** (A/AAAA and SRV targets); names the
  VPC has no claim on → NXDOMAIN; external names → forwarded upstream (a
  deliberate, documented system service — like metadata, not an isolation
  hole: answers are data, reachability still requires an egress path).

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

1. **Resolver + headless** — per-node split-horizon resolver, DNS interception
   in `from_pod`, headless answers as VPC IPs. Already unblocks etcd *peer*
   traffic and all name-based intra-VPC addressing. kind-testable.
2. **VIP data plane** — allocation, `svc_vips`, DNAT/rev-NAT, the Service
   annotation + controller. Closes the ClusterIP gap; etcd e2e as above.
3. **Upstream forwarding + VM resolver config** — external names via the
   resolver; ties into vm-provisioning's RA/DHCP so guests learn the resolver
   without manual config.

## Open questions (review)

1. **Attachment UX** — Service annotation gated by the existing `VPCBinding`
   (proposed), or a dedicated `ServiceAttachment` object (more explicit, more
   API surface)?
2. **Where the VIP lives in the API** — status on a new small object, or
   modeled as a special Port (reusing IPAM/GC machinery at the cost of Port
   semantics getting muddier)?
3. **Resolver scope** — is upstream forwarding for external names in from day
   one (VMs and pods both want `pypi.org`), or increment 3 as proposed?
4. **Same process as the metadata responder?** Both are per-node,
   datapath-steered, per-net-identified services. One binary/DaemonSet with
   two listeners is operationally simpler; two components are independently
   shippable.
5. **Ordering confirmation** — this draft before any KPR increment, and
   within it, increment 1 (resolver+headless) as the first shippable slice?
