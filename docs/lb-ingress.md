# LoadBalancer ingress — delivery for LB IPs, eBPF-native

**Status: IMPLEMENTED** — increments 1 and 2 (both families, net-0 and
VPC-pod backends), `loadBalancerSourceRanges`, external NodePort, and
`externalTrafficPolicy: Cluster` via DSR, source preserved in every mode.
Tracks [#13](../../issues/13). As-built notes are inline below.

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
  same node) already holds. `to_pod` sanctions the flow by its `svc_rev` entry.
  **Two gates run at the DNAT point, in this order:** first `vpc_ingress[net]` —
  LoadBalancer ingress into a VPC is **default-deny**, opened only by that VPC's
  `VPCGateway` setting `ingress.loadBalancer` — and only past it does
  `ns_sg_admit` apply the SecurityGroups. A VPC with no admitting gateway is
  refused before SGs are consulted at all, and the refusal is counted in
  `ns_denied[loadbalancer]`. Naming a VPC pod as a Service backend is no longer
  enough to reach it: the tenant must have opened its own door
  ([north-south.md](north-south.md) tenet 7).
- **v6**: same composition; both families in scope (increment 2).

### `externalTrafficPolicy: Cluster` — DSR, still source-preserving

`Cluster` mode is DNAT to any ready backend cluster-wide. The textbook
implementation adds a client SNAT at the ingress node so the reply returns
through it — kube-proxy's shape, which forfeits the client source and needs
a flow conntrack plus a port range carved against the egress masquerade.
cozyplane does **DSR** instead (Cilium's Geneve-DSR shape), keeping source
preservation even in `Cluster` mode:

- **kpr** writes `Cluster` rows with the **cluster-wide** ready backend set
  (`Local` keeps the node-local set — that stays the only difference between
  the modes in the tables). NodePort's upstream *default* is `Cluster`, so
  default NodePort services are now served too.
- **`lb_ingress`** selects as usual (sourceRanges and the `svc_fwd` flow pin
  at the ingress node are unchanged, so stickiness holds). A backend that
  resolves locally takes the existing path. A remote one is DNAT'd (client
  source untouched) and encapsulated to its node — `remotes` at net 0
  already maps pod addresses to nodes — with a Geneve option carrying
  `{lbIP, port}`, the identity the reply must assume.
- **`from_overlay`** (net-0 branch), on seeing the LB option, tail calls
  `cozyplane_lb_dsr` (`lb_prog` slot 1): resolve the inner destination — a
  `bridges` hit is a VPC-pod backend (SG-gated here, where the pod is local;
  DNAT fabric → VPC IP) — pin `svc_rev` with the option's identity (`lb=1`,
  lookup-first so steady-state packets don't rewrite the LRU), and deliver
  locally.
- **The reply exits the backend's own node**: `lb_return` finds the pin and
  answers *as the LB IP* out the local uplink — unchanged code; pinning the
  identity where the backend lives is the whole trick.

**Strictly opt-in.** DSR's fleet-wide spoof requirement (caveat 1 below) is
an underlay property cozyplane cannot detect, and denial fails as a silent
black hole — so `Cluster` DSR ships default-off, gated by `CLUSTER_DSR=true`
on cozyplane-kpr. Ungated, `Cluster` rows carry the node-local backend set:
`Local` delivery semantics under `Cluster`'s API contract — a node serves
the backends it hosts (source preserved), a backend-less node refuses,
nothing black-holes. (On a cluster still running kube-proxy, un-intercepted
LB traffic simply falls through to its iptables — served cluster-wide,
masqueraded: kube-proxy's own `Cluster` semantics.) Enable it only where every node may source the LB
range on the wire (e.g. the dev cluster's floating VLAN).

**As built.** kpr's `pick` between the node-local and cluster-wide bucket is
the entire control-plane delta. `encap_lb` stamps the option (class shared
with the SG TLV, types discriminate); `from_overlay`'s net-0 branch pays one
`get_tunnel_opt` per decap and tail calls `cozyplane_lb_dsr` (slot 1) on a
match — VPC east-west never pays it. Two things found live: **(a)** spelling
the remote test `!be && !l` lets clang fuse two pointer null-tests into a
pointer OR (`r1 |= r0`), which the verifier prohibits — a scalar
`remote = (l == NULL)` inside one branch is the fix; **(b)** the frontend's
link was only configured where a local FloatingIP existed, so a
MetalLB-announced LB IP black-holed on backend-less nodes — the agent now
ensures the attach (and the DSR reply's exit config) on **every node for the
link carrying every `status.loadBalancer.ingress` address** (a Services watch;
[external-addresses.md](external-addresses.md) §9 — `ExternalPool` CIDRs
carried this before the kind was deleted). Consequence for operators: the LB
range must be on-link on some node interface (or routed via the default-route
link).
Validated on the dev cluster as a fully asymmetric triangle — client on one
node, MetalLB announcing from a second (backend-less) node, backend on a
third: raw SYNs (an in-cluster client's socket-LB bypass) came back as
SYN-ACKs sourced from the LB IP, emitted by the backend's own node across
the OCI VLAN. e2e: the backend-less-node `Cluster` delivery with the client
source asserted, and the default-policy (Cluster) NodePort served from a
backend-less node.

Three DSR caveats, best read as three grades of spoof permission the
underlay must grant:

1. **`Cluster` LB DSR needs *every* backend-hosting node allowed to source
   the LB IP on the wire.** This is strictly stronger than what MetalLB-L2
   itself proves: L2 announcement only requires the *announcer* to source
   the IP, and under `Local` the announcer is also the replying node — so
   `Local` works wherever MetalLB-L2 works, but `Cluster` does not follow.
   A per-VNIC anti-spoof underlay (default OCI VNICs, AWS/GCP source/dest
   checks) can grant the announcer and deny the fleet; the failure is a
   silent black hole (DNAT and encap succeed, the fabric eats the reply).
   The dev cluster works because the floating VLAN carries the exemption on
   every node. On a strict fabric the degradation is `etp: Local`; the
   deliberately-unbuilt escape hatch is kube-proxy's SNAT-at-ingress, which
   would trade the client source for fabric-independence — an opt-in knob
   if such a provider ever matters, never a default.
2. Strictly symmetric middleboxes between client and cluster won't like the
   asymmetric return.
3. Sharper still, and NodePort-specific: a cross-node `Cluster` NodePort
   reply assumes the *ingress node's own address* as its source, emitted
   from the backend's node. A node address is not a shareable address — no
   anti-spoof exemption class exists for it anywhere — and this is the
   reason kube-proxy SNATs this path. Cross-node NodePort under `Cluster`
   is the most provider-dependent piece; LB IPs at least have the
   floating-IP exemption class to lean on.

## Increments

1. **Delivery, default-net backends, v4** — kpr status-driven rows
   (ipMode-gated, local-only backends), `from_uplink` DNAT + pin, `from_pod`
   reply un-NAT. e2e is the thought-experiment verbatim: create a Service,
   patch `status.loadBalancer.ingress` by hand (simulating any provider),
   steer packets for the LB IP at a node, assert delivery, stickiness, and
   the **client source seen by the backend**; assert a backend-less node
   does NOT serve.

   **Implemented** — kpr's reconciler derives LB rows beside the ClusterIP
   rows (one pass over the EndpointSlices buckets cluster-wide and node-local
   sets in parallel; `NODE_NAME` downward API scopes the node); the datapath
   forward is `lb_ingress` at `from_uplink`'s tail and the reply is
   `lb_return` inlined in `from_pod`, exiting by the floating uplink.
   e2e-covered (kind, both assertions above), and validated on the real
   cluster **as the full composition**: MetalLB allocated + L2-advertised the
   address, cozyplane delivered. (A validation footnote: an *in-cluster*
   host-netns test client is socket-LB'd at connect() — the wire never
   carries the LB IP, so the backend sees the client node's own address.
   The genuinely-external wire path, source preservation included, is what
   the kind e2e asserts with an off-cluster client.) Verifier war stories, for the next
   datapath increment: inlining the svc machinery into `from_uplink` blew the
   1M-insn verification budget (fixed: noinline BPF-to-BPF subprogram);
   building the conntrack keys on the stack blew the 512-byte combined
   call-stack limit — `from_pod` is 496 bytes by itself and can host no
   callee (fixed: per-CPU scratch map for `lb_ingress`, `lb_return` stays
   inline); and clang folded a memset-then-overwrite sequence on the per-CPU
   scratch into dropping the overwrites, shipping conntrack keys with zeroed
   fields (fixed: explicit per-field stores, no memset, and compiler barriers
   before each map call that reads the scratch).
2. **VPC-pod backends + v6** — bridge masquerade suppression for pinned LB
   flows, SG gating verified; overlapping-CIDR two-tenant exposure in e2e.

   **Implemented** — `lb_ingress` went family-agnostic and became a **tail
   call** out of `from_uplink` (`lb_prog`, slot repopulated on every agent
   load): its own program, fresh 512-byte stack, own 1M-insn budget — the
   structural end of the combined-stack fights (`from_pod` is 496 bytes and
   `to_pod` 432; neither can host a BPF-to-BPF callee, and the SG gate alone
   overflowed the callee budget behind `from_uplink`). A VPC-pod backend is
   one `bridges` hop inside `lb_ingress`: the row carries the pod's fabric
   address, the DNAT goes straight to the VPC IP (never the bridge's client
   masquerade — the reply exits this same node), the `vpc_ingress` default-deny
   gate runs first and SecurityGroups (`ns_sg_admit`, the floating rule) second
   — see above; that gate was added later, with `VPCGateway`, and it is what
   makes LB ingress into a VPC a crossing the tenant *declared* rather than a
   free ride. Metered and refused-counted per VPC by the `loadbalancer` door
   (`ns_bytes`/`ns_packets`/`ns_denied`, in `lb_ingress` and `lb_return`). The
   `to_pod` isolation check admits the flow by its `svc_rev` pin (a lookup
   paid only by packets that would otherwise drop), and the pinned reply
   identity is the VPC IP so `lb_return` catches the tenant pod's answer
   before the floating/gateway paths could rewrite it. `lb_return` handles
   both families; the v6 exit resolves via the FIB like the floating v6 half.
   e2e: v6 LB IP end-to-end with the client's v6 source asserted, and an LB
   IP fronting a VPC pod with the real external caller seen inside the
   tenant. Dev-cluster validation rode NodePort (the only wire path an
   in-cluster client exercises — see the socket-LB note above): node-to-node
   traffic served with no kube-proxy on the cluster, source preserved,
   through the VPC bridge hop. `loadBalancerSourceRanges` (lb_src LPM, flag-gated, drop before
   any flow state) and NodePort (node addresses as frontends; the kube-proxy
   KUBE-NODEPORTS counter stays flat while cozyplane serves, proving who
   answered) landed in the same increment, per the sections above.

### `loadBalancerSourceRanges`

Part of the Service dataplane contract (kube-proxy enforces it as a firewall
on the LB IP). Enforced at the DNAT point: a `SVC_F_SRC_RANGES` flag on the
LB row sends the client through an `lb_src` LPM keyed `{prefixlen, lbIP,
client}` — the same composite-LPM shape as `sg_cidr` (the frontend address
fully specified ahead of the client prefix; a v4 range is its NAT64 form, so
a `/24` is prefixlen 128+96+24). Flag set with no match → drop, before any
flow state is created. LB rows only, matching upstream semantics (NodePort
traffic is not range-filtered by kube-proxy either).

### External NodePort — the same rows, node addresses as frontends

NodePort needs nothing the LB path doesn't already have: kpr writes the same
net-0 rows keyed by **this node's addresses** (InternalIP/ExternalIP, both
families) × `spec.ports[].nodePort`, for `type: NodePort` and `LoadBalancer`
Services under `externalTrafficPolicy: Local` — node-local ready backends,
client source preserved, same `lb_ingress`/`lb_return` datapath, zero new
maps or hooks. A node without local backends has no row (`Local`'s drop
contract). `Cluster` mode stays deferred with the LB case. The masquerade
port range (16384–29999, #10) is disjoint from the NodePort range by
construction, so `masq_reverse` (checked first) never shadows a NodePort row.
`healthCheckNodePort` is not served — it is kube-proxy's healthz; providers
that health-check (MetalLB, CCMs) derive readiness from the API as MetalLB
already does.

## Resolved questions

- **In-cluster clients dialling the LB IP** — confirmed live on the dev
  cluster: the imported lbcell feeds LB ingress IPs as socket-LB frontends,
  so an in-cluster client's connect() is rewritten straight to a backend
  (kube-proxy's short-circuit, at the socket layer). Consequence: in-cluster
  clients bypass the per-packet path — `loadBalancerSourceRanges` and the
  `Local`-only gate apply to *wire* traffic, exactly as with Cilium KPR.
- **Health-check integration for cloud LBs**: the upstream mechanism for
  "does this node have local backends" is `healthCheckNodePort` — which is
  a NodePort. Out of scope here (the provider owns attraction), but worth a
  documented answer for CCM users: target backend-hosting nodes, or accept
  that mis-attracted traffic is dropped by `Local` semantics (as upstream).

## Non-goals

- **Address allocation / IPAM, LB provisioning, and traffic attraction**
  (ARP/NDP announcement, BGP, cloud LB config) — the LB implementation's
  job: CCM, MetalLB, appliance, or operator. cozyplane never writes *foreign*
  Service status (it owns the Services it mints for FloatingIP/NAT identities —
  [external-addresses.md](external-addresses.md)).
- Anything tenant-facing beyond the standard Service object.
