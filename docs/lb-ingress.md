# LoadBalancer ingress — delivery for LB IPs, eBPF-native (design draft)

**Status: DESIGN DRAFT (awaiting review).** Nothing here is built. Tracks
[#13](../../issues/13).

## Scope: delivery, not provisioning

Allocating a public address, provisioning a load balancer, and attracting
traffic to a node are **wildly implementation-dependent** — a cloud CCM, a
MetalLB install, an appliance, or a human with a console can each own them,
and none of that is cluster networking. The CNI's responsibility begins when
a packet addressed to a Service's LB IP **arrives at a node** and ends when
the reply leaves it.

The acceptance thought-experiment (review, 2026-07-10): manually create a
cloud load balancer in destination-preserving mode (OCI's NLB has exactly
this), point it at the node hosting the backend pod, create a
`type: LoadBalancer` Service, and hand-fill `status.loadBalancer.ingress`
with the LB's address. **That must work.** Today it doesn't — the packet
arrives with `dst = lbIP:port` and dies: socket-LB never sees it (no local
socket syscall), the floating map misses, the kernel owns no such address.
The missing per-packet DNAT is the entire feature.

So cozyplane consumes `status.loadBalancer.ingress` — *whoever* wrote it —
and implements the dataplane half of the Service contract:

1. **The API is the Kubernetes Service, read-only.** cozyplane allocates
   nothing, announces nothing, and writes nothing to the Service. The
   upstream `ipMode` field models exactly this boundary:
   `ingress[].ipMode: VIP` (default) means "dataplane, intercept this IP";
   `ipMode: Proxy` means "the LB proxies — hands off". cozyplane honours it.
2. **No NodePort in the path** (MetalLB precedent; external NodePort stays a
   separate, low-priority item).
3. **`externalTrafficPolicy: Local` is the supported mode and preserves the
   client source**: deliver only to node-local ready backends, no second
   hop, no masquerade.

Who attracts the traffic composes freely underneath:

- **Cloud LB** in destination-preserving mode, pointed at backend-hosting
  nodes (manually or by a CCM).
- **MetalLB** on-prem — controller does IPAM + status, speaker does the L2
  answer; cozyplane replaces only the kube-proxy *delivery* MetalLB assumes.
  (Earlier drafts had cozyplane "replacing MetalLB"; wrong boundary — it
  composes with it.)
- **Static routing** of the LB prefix at the ToR to the right nodes.

## What already exists

- **`cozyplane-kpr`**: per-node DaemonSet, watches Services + EndpointSlices
  with plain client-go, already writes this node's pinned `svc_vips` map at
  net 0 (ownership partitioned by net) — the natural owner of "which LB rows
  does *this node* program".
- **`svc_fwd`/`svc_rev`**: per-node flow pinning with the avalanched
  multiply-shift backend selection.
- **`from_uplink` / the floating exit**: uplink ingress hook and the
  `bpf_redirect_neigh` reply path out the uplink.
- **The bridge**: fabric→VPC translation for VPC-pod backends
  (services-in-vpc.md § Composition).

## Design

### Control plane: read the Service, program local rows

Each node's kpr derives its rows from objects as written:

- For every Service with `status.loadBalancer.ingress[].ip` set and
  `ipMode` VIP (or unset): for each ingress IP × service port, a
  `svc_vips[{net 0, lbIP, proto, port}]` entry whose backend set is
  **this node's ready endpoints only** (from EndpointSlices'
  `nodeName` + readiness). `externalTrafficPolicy: Local` is thereby a
  per-node table filter, not a datapath mode — and a node with no local
  ready backend has **no row**, so traffic mis-attracted to it falls
  through and is not served, which is `Local`'s contract.
- No allocator, no announcer, no election, no leader: kpr's existing
  event-scoped reconciler gains one more input field. Multiple ingress IPs,
  IP changes, and Service deletion are ordinary row diffs.

### Datapath: `from_uplink` in, `from_pod` out, all state node-local

- **Inbound** (`from_uplink`): dst = `lbIP:port` probes net-0 `svc_vips`
  (a miss falls through to today's floating/pod path unchanged). Select a
  backend (all local by construction), pin the flow in `svc_fwd`/`svc_rev`,
  DNAT `lbIP:port → podIP:targetPort`, **keep the client source**, deliver
  by identity to the local veth.
- **Reply** (`from_pod`): the `svc_rev` hit un-NATs
  `podIP:targetPort → lbIP:port` and `bpf_redirect_neigh`s out the uplink —
  the floating egress exit. All NAT state lives on the one node both
  directions traverse.
- **VPC-pod backends**: the DNAT target is the pod's *fabric* IP; the bridge
  translates fabric → VPC as for any north-south flow, but its client
  masquerade is **suppressed for pinned LB flows** — source preservation is
  the point, and the masquerade's only guarantee (reply returns through the
  same node) already holds. `to_pod` sanctions the flow by its `svc_rev`
  entry; SecurityGroups gate unconditionally at the DNAT point.
- **v6**: same composition; both families in scope (increment 2).

### `externalTrafficPolicy: Cluster` — deferred, and what it actually needs

Not NodePort: `Cluster` mode is DNAT to any ready backend cluster-wide plus
a **client SNAT at the point of ingress** so the reply returns through the
ingress node — the eBPF masquerade ct at the uplink is the natural home, and
the mode gives up source preservation by definition. Deferred as a v1 scope
cut. (Later alternative avoiding even the SNAT: DSR — carry `{client, lbIP}`
in Geneve metadata so the backend's node replies directly from the LB IP.)

## Increments

1. **Delivery, default-net backends, v4** — kpr status-driven rows
   (ipMode-gated, local-only backends), `from_uplink` DNAT + pin, `from_pod`
   reply un-NAT. e2e is the thought-experiment verbatim: create a Service,
   patch `status.loadBalancer.ingress` by hand (simulating any provider),
   steer packets for the LB IP at a node, assert delivery, stickiness, and
   the **client source seen by the backend**; assert a backend-less node
   does NOT serve.
2. **VPC-pod backends + v6** — bridge masquerade suppression for pinned LB
   flows, SG gating verified; overlapping-CIDR two-tenant exposure in e2e.

## Open questions

- **`loadBalancerSourceRanges`**: part of the Service dataplane contract
  (kube-proxy enforces it). An LPM check at the DNAT point is cheap —
  increment 1 or a fast-follow?
- **In-cluster clients dialling the LB IP**: kube-proxy short-circuits LB
  IPs from inside the cluster; Cilium's LB tables can carry ingress IPs as
  socket-LB frontends. Verify whether the imported lbcell already feeds
  them (likely) — if so this works today and needs only an e2e assertion;
  if not, decide whether in-cluster LB-IP dials matter.
- **Health-check integration for cloud LBs**: the upstream mechanism for
  "does this node have local backends" is `healthCheckNodePort` — which is
  a NodePort. Out of scope here (the provider owns attraction), but worth a
  documented answer for CCM users: target backend-hosting nodes, or accept
  that mis-attracted traffic is dropped by `Local` semantics (as upstream).

## Non-goals

- **Address allocation / IPAM, LB provisioning, and traffic attraction**
  (ARP/NDP announcement, BGP, cloud LB config) — the LB implementation's
  job: CCM, MetalLB, appliance, or operator. cozyplane never writes Service
  status. (`ExternalPool` remains FloatingIP-only.)
- `externalTrafficPolicy: Cluster` — v1 scope cut (ingress-point client
  SNAT, or DSR later), not a NodePort dependency.
- External NodePort — separate, low priority (#13).
- Anything tenant-facing beyond the standard Service object.
