# Security groups — intra-VPC policy

> One of three policy layers; which layer owns which flow (and why a
> SecurityGroup can never break kubelet probes) is recorded in
> [policy-layers.md](policy-layers.md).

**Status: v1 implemented and dev-cluster-validated (2026-07-06).** East-west
(intra-VPC, group-to-group) ingress enforcement is built and validated on a real
cluster. This is the first increment of `design.md` §7 ("Network identity &
security groups"). The remaining §7 surface (egress, peered-group references,
FQDN and specific-CIDR sources, the Geneve identity TLV) is v2 — the v1 shape is
chosen so those are additive, never a reshape. What v1 does **not** yet do is
called out inline as "v2".

## What §7 commits us to

- A **security identity** per port, derived from workload metadata, **scoped to
  its VPC** — identities never collide or leak across tenants.
- **`SecurityGroup`** selects ports by metadata; rules reference *other
  groups*, FQDNs, or external CIDRs — never internal IP ranges.
- Enforcement in eBPF at both universal hooks; placement-independent.
- Cilium compatibility is a non-goal; k8s `NetworkPolicy` stays honored on the
  default/system network only.

## The model (first increment)

A `SecurityGroup` is a **namespaced object in the VPC owner's namespace**, like
the VPC itself — groups are part of a VPC's own design, not something a
consumer namespace defines (contrast `VPCBinding`, which lives with the
consumer). One group belongs to exactly one VPC.

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}            # local VPC, like VPCPeering
  podSelector:                      # who is IN the group (see "membership")
    matchLabels: {role: web}
  ingress:
    - from: {group: lb}             # another group in the same VPC
      ports: [{protocol: TCP, port: 8080}]
    - from: {cidr: 0.0.0.0/0}       # north-south (bridge/floating) callers
      ports: [{protocol: TCP, port: 443}]
```

Semantics, deliberately AWS-shaped:

- **No groups touch a pod ⇒ today's behavior** (allow-all intra-VPC,
  default-deny at the VPC boundary). Nothing changes for existing users.
- **Any group selects a pod ⇒ that pod's ingress becomes default-deny**, opened
  only by matching ingress rules of the groups it belongs to. Membership in
  multiple groups unions their rules.
- Rules are **ingress-only in v1**. §7 wants egress too; ingress is where the
  tenant-facing value is, and egress doubles the datapath work. The `ingress`
  field name leaves room for an additive `egress` in v2.
- **Stateful-shaped without a conntrack.** Enforcement gates TCP only on a *new*
  connection (SYN set, ACK clear); the reply direction of an admitted flow
  carries ACK and passes untouched. So a rule that admits `client -> web:80`
  lets `web` answer `client` even though `web`'s own group has no rule for
  `client` — AWS-stateful semantics for TCP with no per-flow state. UDP is
  gated statelessly (both directions), so intra-VPC UDP between grouped pods
  needs symmetric rules; most UDP (cluster DNS) takes the resolver/gateway path
  and never reaches this check. Non-TCP/UDP (ICMP) is not gated in v1, so PMTU
  and ping keep working to a grouped pod (a deliberate v1 gap).
- `from.group` references a group in the **same VPC**. Peered-VPC references are
  v2 (identity has to cross a trust boundary — the Geneve TLV). A peered source
  is in a disjoint CIDR (peering requires it), so it matches no group in the
  destination's VPC and is **dropped once the destination is grouped** — the
  AWS-shaped default-deny (chosen 2026-07-06). Until a v2 peer-group rule admits
  it, grouping a pod closes it to peered VPCs.
- `from.cidr` (north-south sources) is **rejected in v1** — the datapath
  scaffolding (a reserved "world" pseudo-group, id 63) and the API field are in
  place, but floating-path enforcement is not wired, so v1 rejects a cidr rule
  rather than advertise one that wouldn't restrict. North-south cidr (starting
  with `0.0.0.0/0`/`::/0`, then LPM for specific ranges) and FQDN rules are v2.

## Membership: how a pod lands in a group

The CNI already stamps every VPC pod's identity onto its `Port` (pod
namespace/name/UID labels). Membership derives from **pod labels at ADD time**:
the plugin copies the pod's labels into a dedicated annotation on the Port
(`sdn.cozystack.io/pod-labels`), and the **controller** evaluates every
`SecurityGroup.podSelector` against them, writing the resolved membership into
`Port.status.groups` (small integers, allocated per VPC — the wire identity).

Two consequences to be explicit about:

- **Label changes after ADD do not move a running pod between groups** in v1.
  Membership is claim-time, like the IP. (A controller re-evaluation on pod
  label updates is a v2 refinement; it needs a pods watch keyed to Ports, which
  the persistent-port machinery already half-built.) (Review Q3.)
- The **numeric group id** is allocated by the controller per VPC. id 0 = "no
  groups, legacy allow"; ids **1..62** are real groups; id **63 is reserved**
  as the north-south "world" pseudo-group (v2). Membership is a `u64` bitmap in
  the datapath. Allocation lives in `SecurityGroup.status.id`, assigned like
  VNIs (live-read allocator with deterministic duplicate repair — the
  VNI-duplicate lesson applies). ids are per-VPC, since the datapath keys them
  by net, so distinct VPCs reuse the low ids freely.

## Datapath (as built)

Three maps:

| Map | Key | Value |
|-----|-----|-------|
| `sg_members` | {net, vpc IP} (like `locals`) | `u64` group bitmap of the *member* |
| `sg_rules` | {net, dst-group-id, proto, dst-port} | `u64` allowed-source bitmap (`port` 0 = any-port) |
| `sg_drops` | {net} (PERCPU) | `u64` policy-drop counter |

Enforcement is **destination-side, in `to_pod`** — the hook every east-west
delivery already traverses (same-node redirect, from_overlay hand-off), so
placement independence holds with no Geneve TLV yet. Only genuine intra-VPC /
peered pod-to-pod traffic is gated; gateway-forwarded ingress (`GW_MARK` —
internet/DNS replies) is left alone (north-south, stateful-reply territory). For
a gated packet, `sg_l4` decides whether to enforce (TCP new-connection only; UDP
always) and reads the destination port, then `sg_admit`:

1. `dstmap = sg_members[{net, dst}]`; zero ⇒ legacy allow (no groups) — done.
2. `srcmap = sg_members[{net, src}]` — the intra-VPC source's groups; a peered
   source misses (disjoint CIDR) and gets `srcmap = 0` ⇒ the AWS-shaped drop.
3. For each set bit in `dstmap` (unrolled 1..62): union `sg_rules[{group, proto,
   port}]` and `sg_rules[{group, proto, 0}]` (any-port) into `allowed`.
4. Admit iff `allowed & srcmap`; else `TC_ACT_SHOT` and bump `sg_drops[net]`.

`sg_admit` is a stack-lean `noinline` subprogram taking a single
fully-initialized `sg_query` pointer — the same shape as `count_dir`, for the
same combined-call-stack reason. Two verifier lessons from bringing it up on the
6.12 kernel (which CI's 6.8 didn't catch): passing multiple scalar args to a
BPF-to-BPF call tripped a register-liveness check (fixed by the single-struct
arg), and a `__u16` temp kept in a caller-saved register across a
`bpf_skb_load_bytes` call was clobbered (fixed by loading the port straight into
the out-pointer). Loop cost is fine (12.8k insns, well under the 1M budget).

The agent syncs the maps: `sg_members` from Ports (`status.groups`, folded into
a bitmap), `sg_rules` from SecurityGroups (resolving `from.group` names to
per-VPC ids), and seeds `sg_drops` per VPC — the same diff-against-pinned-map
pattern as ServiceVIPs. The drop counter is exposed as
`cozyplane_sg_drops_total` on the `:9411` metrics endpoint.

**Why not source-side too?** §7 wants egress rules eventually; the identity TLV
in the Geneve header (§7) is what makes *destination trust of source identity*
robust when source-side marking is added. In v1 the destination derives the
source's groups from its own `sg_members` map — consistent cluster-wide because
the same controller feeds every agent. The TLV becomes necessary only when
identities must cross a trust boundary (peered VPCs, v2).

**Why not source-side too?** §7 wants egress rules eventually; the identity TLV
in the Geneve header (§7) is what makes *destination trust of source identity*
robust when source-side marking is added. In v1 the destination derives the
source's groups from its own `sg_members` map — consistent cluster-wide because
the same controller feeds every agent. The TLV becomes necessary only when
identities must cross a trust boundary (peered VPCs, v2).

## Control plane (as built)

- `SecurityGroup` — namespaced (VPC owner's namespace), aggregated-apiserver
  storage + CRD (both modes). Port gains a `/status` subresource for
  `status.groups`.
- **`SecurityGroupReconciler`**: per-VPC id allocation (live-read, ids 1..62,
  deterministic duplicate repair) → `status.id`/`phase`.
- **`PortMembershipReconciler`**: evaluates every SecurityGroup's `podSelector`
  in the Port's VPC against the pod-labels the CNI stamped (annotation
  `sdn.cozystack.io/pod-labels`, a claim-time snapshot) → `Port.status.groups`.
  Re-runs when a Port is created or any SecurityGroup in its VPC changes; **not**
  on later pod-label edits (v2 — a Ports-keyed pods watch, which the
  persistent-port machinery already half-built).
- The **agent** compiles SecurityGroups directly into `sg_rules` (it does not
  read a controller-compiled form).
- **AuthZ**: the VPC owner manages groups — the object is namespaced in the VPC
  owner's namespace and its `vpcRef` is same-namespace (like VPCPeering), so
  owning the namespace *is* owning the VPC's policy. No new virtual verb.

## Validated on the dev cluster (2026-07-06)

Two groups in `vpc-a` (`client`, `web`; `web` admits `client` on TCP 80). With
labeled pods `sgcli` (role=client), `sgweb` (role=web), `sgnone` (unlabeled):
ids allocated 1/2, membership resolved from the stamped labels, and enforcement
matched intent on all four cases — `sgcli→sgweb:80` open, `sgcli→sgweb:81`
dropped, `sgnone→sgweb:80` dropped (ungrouped source, default-deny),
`sgweb→sgcli:*` dropped (`client` has no ingress). Baseline (no groups) was
allow-all. `cozyplane_sg_drops_total` incremented per drop.

## Decisions (were review questions)

1. **Ingress-only v1** — accepted; `egress` is additive.
2. **Peered-VPC** — v1 **drops** peered traffic once the destination is grouped
   (AWS-shaped default-deny). Peer-group *rules* are v2 (need the identity TLV).
3. **Claim-time membership** — accepted; label-change-follows is v2.
4. **AuthZ** — owner-namespace-implies-policy-authority; no `policy` verb.
5. **Naming** — `SecurityGroup` (AWS familiarity).

## v2: peered-group references + the Geneve identity TLV (built + dev-cluster-validated)

**Goal:** a group in one VPC can admit a group in a *peered* VPC —
`from: {group: web, vpc: {namespace: team-b, name: vpc-b}}` — enforced
correctly and safely across the tenant trust boundary. Both stages are built and
validated on the dev cluster (2026-07-06).

### Why v1 can't do this, and why the TLV

v1 keys everything by net: `sg_members[{net, ip}]` is the pod's bitmap in *that
net's* id space, and a destination infers the source's bitmap from
`sg_members[{dst net, src ip}]`. Two problems for a peered source (a different
net, disjoint CIDR):

1. **Id-space collision.** Group id 3 in vpc-a and id 3 in vpc-b are different
   groups; a single `u64` allowed-bitmap can't mix "vpc-a group 3" and "vpc-b
   group 3". A rule that admits a peer group must name *which VPC's* id space.
2. **Spoofable identity.** Among mutually-peered tenants (a peers b and c), a
   pod in c can put a source IP from b's CIDR on its packet. At a's destination,
   `net_of(src_ip)` resolves it to b, and the inference reads *b's* membership —
   c impersonates b's groups. The source net must be **authoritative**, not
   inferred from a tenant-controlled field.

The **Geneve identity TLV** solves (2): the source *node* (trusted
infrastructure) stamps the real `{source net, source group bitmap}` — taken from
the source pod's own veth, not the packet — into a Geneve option on encap. The
destination reads it instead of guessing. (1) is solved by keying rules on the
source net too.

### Rule model (both stages)

`sg_rules` key gains **`src_net`**: `{dst_net, dst_group, src_net, proto, port}`
→ allowed-source bitmap *in `src_net`'s id space*. A same-VPC rule has
`src_net == dst_net` (unchanged behavior); a peer rule has `src_net = the peer
VPC's VNI` and the bitmap holds the peer group's id. This is an ABI change to
`sg_rules`, handled by the agent's recreate-incompatible-pinned-map path (#7).
The agent compiles a peer rule by resolving the peer VPC's VNI (VPC lister) and
the peer group's id (it already lists SecurityGroups cluster-wide).

API: `SecurityGroupPeer` gains `VPC *VPCRef` (namespace+name). When set, `group`
names a group in that peer VPC. The apiserver validates the ref has both a
namespace and name and pairs with a group; verifying the VPC is actually a
declared peer is a later controller-condition check.

### Stage A — destination-side inference (functional, non-adversarial)

`to_pod` already computes `srcnet = net_of(src)` for both same-node and
overlay-delivered traffic. Change the membership lookup from
`sg_members[{dst_net, src}]` to `sg_members[{srcnet, src}]` (the source's *own*
net) and pass `srcnet` into `sg_admit`, which now looks up
`sg_rules[{dst_net, group, srcnet, proto, port}]`. This makes peer-group rules
match with **no TLV, no `from_overlay`/`from_pod` change** — correct whenever
source IPs aren't spoofed. It is the functional increment; it does not yet close
the cross-peer spoofing hole.

### Stage B — the TLV (authoritative, anti-spoof)

The tunnel metadata is only readable in `from_overlay` (the geneve device
ingress); once `deliver_local` redirects into the pod, `to_pod` sees a bare
inner packet. So enforcement splits by path:

- **Encap (`from_pod`)**: for a *grouped* source pod (bitmap ≠ 0 — the common
  ungrouped case stamps nothing, so no hot-path cost), stamp a Geneve option
  carrying `{srcnet (u32), srcmap (u64)}` — 12 bytes of option data — alongside
  the existing tunnel key. `srcnet`/`srcmap` come from the source node's own
  `ports`/`sg_members` (the pod's veth identity), so they're authoritative.
- **`from_overlay` (cross-node)**: read the option
  (`bpf_skb_get_tunnel_opt`). If present, use its `{srcnet, srcmap}`
  authoritatively; enforce with `sg_admit` *before* `deliver_local`; on admit
  set an `SG_OK` mark bit; on deny drop + count. If absent (ungrouped source or
  a pre-TLV peer), fall through to `to_pod`'s inference.
- **`to_pod`**: if the `SG_OK` bit is set, skip (already enforced authoritatively
  upstream — `skb->mark` survives the redirect, the same mechanism `GW_MARK`
  relies on). Otherwise enforce via inference (same-node traffic, and the
  no-TLV fall-through). Same-node has no over-the-wire spoofing surface, so
  inference is safe there.

This keeps `sg_admit` a single shared subprogram. The `from_pod` stamping (one
`sg_members` lookup + a `bpf_skb_set_tunnel_opt` with a 16-byte opt) **loaded
clean on the 6.12 kernel** — the stack budget held even though `from_pod` is the
tightest hook.

**Trust result and its limit.** The TLV's **`src_net` is authoritative**: it
comes from the source pod's veth (`ports` map) on the source node, not from the
packet. So a mutually-peered tenant c cannot wear b's *net* — a rule keyed
`src_net = b` never matches c's traffic (its TLV says c). That closes the
cross-tenant impersonation the peering trust boundary is about. The source
*group bitmap* is still looked up by the packet's source IP on the source node,
so a pod could impersonate a **co-VPC** peer's group by spoofing that peer's IP
— but that is within one tenant's own VPC (the tenant can already label any of
its pods into the group), so it crosses no trust boundary. Closing it needs
`from_pod` source-IP RPF (validate `src` against the veth's Port IP), which also
hardens v1 intra-VPC — a noted follow-up, not done here.

Same-node and no-TLV traffic keep inference (`to_pod`); same-node has no
over-the-wire spoofing surface.

**Not yet:** the apiserver validation only checks a peer ref names a group with
a namespace+name; it does **not** yet verify a `VPCPeering` exists (an
unpeered ref simply never matches — a footgun, a cheap controller-condition
follow-up). A `migrate_fwd` re-encap during VM migration does not re-stamp the
TLV, so a migrated grouped VM's cross-node traffic falls back to inference for
the brief migration window.

### Validated on the dev cluster (2026-07-06)

vpc-a peered vpc-b (disjoint CIDRs, VNIs 101/102). vpc-a's `web` admits vpc-b's
`bclient`. Stage A (inference, same-node) and stage B (TLV, cross-node) both
correct: a cross-node vpc-b `bclient` pod reaches `web:80` (its TLV admitted in
`from_overlay`); a cross-node vpc-b pod in a *different* group (`bother`, id 2 —
colliding with vpc-a `web`'s own id 2) is dropped (the `src_net` key keeps the
id spaces distinct); an ungrouped vpc-b pod is dropped; same-VPC rules keep
working alongside.

## v2: north-south `from.cidr` (built + dev-cluster-validated)

**Goal:** a security group can admit *north-south* callers by source CIDR —
`from: {cidr: 0.0.0.0/0, ports: [{protocol: TCP, port: 443}]}` — so a grouped
pod can be exposed to (or restricted from) external / cluster-external clients.

**Semantics (decided 2026-07-06): AWS-strict default-deny.** Grouping closes a
pod's north-south ingress just as it closes east-west — once *any* group selects
it, north-south is default-deny, opened only by matching `from: {cidr}` rules.
So a grouped pod that should stay world-reachable adds `from: {cidr: 0.0.0.0/0}`.
Ungrouped pods are unaffected (today's open behavior).

**The one thing that stays exempt: Kubernetes plumbing.** Invariant #7 —
"probes reach a pod on `status.podIP`" — is non-negotiable. Kubelet health
probes, the split-horizon DNS resolver's replies, and node-originated traffic
must never be subject to tenant SG policy.

The exemption is by **path, not source IP**. A first cut that exempted "source ==
the node IP" was tried on the dev cluster and **broke** — a grouped pod with a TCP readiness
probe went NotReady, because kubelet's probe to a pod's fabric IP does not carry
the node's own address as source (the `/32` route to the veth has no host IP to
borrow). What *is* reliable: kubelet reaches `bridge_forward` via the **kernel
`/32` route**, never passing a cozyplane source hook, whereas pod-originated
north-south is **eBPF-redirected** through `from_pod`/`from_overlay`. So those
redirect points stamp an `NS_MARK` bit, and `bridge_forward` gates only marked
traffic — host-originated kubelet probes arrive unmarked and are never checked.
`skb->mark` survives the redirect (the mechanism `GW_MARK` already relies on).
Floating IPs are gated unconditionally (external clients are never
node-originated — the fabric IP carries kubelet). The DNS-return path already
returns before any ingress check (reserved resolver port).

### What gets gated, and where

North-south to a VPC pod arrives at `to_pod` as traffic to a **fabric IP**
(`bridge_forward`, the `/32`/redirect path) or a **floating IP**
(`floating_forward`) — both currently return *before* the SG check, which is why
north-south is open today. Enforcement moves *into* those functions (v4 and v6),
right after the client address is known and **before** the `ct_fwd` gateway-port
allocation (so a denied packet leaks no connection state):

1. For the bridge path: gate only if `skb->mark & NS_MARK` (pod-originated);
   unmarked kubelet traffic is delivered untouched. Floating IPs gate always.
2. `sg_admit` with the destination pod, the packet's L4 port, and a **north-south
   source identity** — `srcmap = 1 << SG_WORLD` (the reserved pseudo-group, id
   63) for the world case, plus an LPM lookup for specific ranges (stage 2). A
   `from: {cidr: 0.0.0.0/0}` rule compiles to the `SG_WORLD` bit (the agent
   already does this), so `allowed & srcmap` admits it. An ungrouped pod
   short-circuits to allow. No rule ⇒ drop (+ `sg_drops`). Stateless in the
   client IP, so every packet of a flow decides the same way — no SYN-gate.

The east-west `to_pod` check is unchanged (it runs only for non-bridge,
non-floating traffic — those paths return earlier).

### Stages

- **Stage 1 — world + kubelet exemption (built, dev-cluster-validated).**
  `from: {cidr: 0.0.0.0/0}` / `::/0` via the reserved `SG_WORLD` pseudo-group
  (scaffolding from v1); enforcement in `bridge_forward`/`floating_forward`
  (+ v6) with the `NS_MARK` path exemption. The apiserver un-rejects the
  all-addresses CIDR (specific ranges still rejected until stage 2). Validated:
  a grouped pod with a TCP readiness probe stays Ready (kubelet exempt); a
  default-network pod is dropped reaching it (N-S default-deny); adding
  `from: {cidr: 0.0.0.0/0}` reopens it; an ungrouped pod is unaffected.
- **Stage 2 — specific ranges (built, dev-cluster-validated).** An `sg_cidr` LPM map
  keyed by `{net, proto, port, client prefix}` → the bitmap of destination
  groups that admit that CIDR; the datapath ANDs it with the pod's own groups.
  A v4 range is stored in the NAT64 form (`/N` → `/(96+N)` in the 128-bit client
  space, behind the 64 fixed bits — a fully-matched key is prefixlen `64+96+N`).
  The agent compiles specific `from: {cidr: 203.0.113.0/24}` rules; the apiserver
  validates the CIDR parses. Two LPM lookups per packet (exact port + any-port),
  after the world check. Validated: an exact `/32`, a covering `/24`, and
  non-matching ranges all resolve correctly.

  *Limitation ([#11](../../issues/11)):* LPM returns the **longest** matching
  prefix only, so overlapping CIDR rules from *different* groups on the same
  `{net, proto, port}` don't union — a client covered by both a `/16` (group A)
  and a `/24` (group B) resolves to the `/24`'s bitmap alone, so a pod in group A
  only is wrongly denied. Non-overlapping rules, identical CIDRs across groups
  (unioned in the value bitmap), and a pod in a single group (the common case)
  are exact; a true union would need a per-group LPM or a prefix-walk.

## v2: egress rules (built + dev-cluster-validated)

**Goal:** a group controls where its members may *send*, the mirror of ingress —
`egress: [{to: {group: db}, ports: [{protocol: TCP, port: 5432}]}]`.

**Semantics (decided 2026-07-06): symmetric default-deny.** Any group selecting a
pod closes its east-west egress just as it closes ingress: a grouped pod may
reach another VPC pod only if one of its groups' egress rules admits that pod's
group. A flow A→B is delivered only when **both** B's ingress admits A **and**
A's egress admits B (AWS ANDs the two directions). The peer form
`to: {group, vpc: {...}}` reaches a peered VPC's group, exactly like ingress.

Consequence to be explicit about: since v1 egress references *groups* only, a
grouped pod cannot egress to an **ungrouped** destination (there is no group to
name) — grouped and ungrouped pods become mutually isolated, which is the strict
reading of default-deny-both-ways. `to: {cidr}` egress (reaching ungrouped /
external destinations) is a later increment; it needs source-side / gateway
enforcement, unlike the group case.

### Datapath

`sg_egress` mirrors `sg_rules`, keyed from the **source** side:
`{src_net, dst_net, src_group, proto, port}` → the bitmap of destination groups
(in `dst_net`'s id space) that the source group may reach. Enforcement stays in
`to_pod` — it already has both identities — right beside the ingress check and
under the same TCP SYN-gate (only new connections are checked; replies pass):

- **Ingress** (existing): `sg_admit` iterates the *destination's* groups and
  admits if a rule's allowed-source bitmap intersects the source's groups.
- **Egress** (new): `sg_egress_admit` iterates the *source's* groups and admits
  if a rule's allowed-destination bitmap intersects the destination's groups.
- Both short-circuit to allow when their subject is ungrouped, and a flow is
  delivered only if both pass.

The source identity is the same one ingress already uses (the `sg_members`
inference, or the authoritative Geneve TLV for a cross-node peered source), so
egress inherits the peered-group anti-spoof for free. Two group-loops now run on
a gated SYN (ingress over the dst's groups, egress over the src's) — bounded and
verifier-checked like the ingress loop.

**Off-VPC transit is exempt from the egress check.** A grouped pod's off-VPC
egress transits its VPC gateway: the packet is delivered onto the *gateway pod's*
veth, so `to_pod` sees `dstnet` = the gateway's net (the gateway is a VPC pod)
but the packet's destination is *not* a VPC address (it is the internet/cluster
IP). A naive east-west egress check treats this as `grouped source → ungrouped
destination` and drops it — silently breaking **all** TCP/UDP north-south egress
(ICMP is never gated, so it kept working, which is what made this subtle). The
fix: `to_pod` skips the SG block when the packet's destination is off-VPC
(`net_of(dstnet, p.dst) == 0`) — that is north-south transit, gated at the true
source's `from_pod` by `ns_egress_ok` (below), never a genuine east-west
delivery (which always targets an in-VPC address). The cross-node gateway path is
delivered through `from_overlay`'s gateway branch (the destination is not a local
VPC pod, so `local_of` misses and the TLV egress check is never reached), so it
needs no equivalent guard.

### Control plane

`SecurityGroupSpec` gains `egress []{to: SecurityGroupPeer, ports}`. The apiserver
validates a `to.group` is set (and, for v1, rejects `to.cidr`). The agent
compiles each egress rule into `sg_egress` by resolving the destination group's
id and VNI (same lister walk as a peered ingress ref). Membership and id
allocation are unchanged.

**Validated on the dev cluster (2026-07-06).** A grouped `client` pod with no egress rule
can't reach `web` even though `web`'s ingress admits `client` (egress
default-deny); adding `client` `egress: {to: web, TCP 80}` opens `:80` (both
directions now allow) while `:81` stays closed; both same-node (inference) and
cross-node (the Geneve TLV carries the source's groups to `from_overlay`, which
now runs the egress check too) confirmed; removing the egress rule closes it
again. Loads clean on the 6.12 verifier with the second group-loop.

**Note on adopting egress:** because grouping now closes east-west egress,
existing ingress-only configs must add egress rules on the *source* groups for
their flows to keep working (a `client` group that reaches `web` needs
`egress: {to: web}`). This is the deliberate consequence of symmetric
default-deny.

## v2: north-south / external egress (`to: {cidr}`) (built + dev-cluster-validated)

**Goal:** a group controls where its members may reach *off-VPC* — the internet
and cluster, via the VPC's NAT gateway — by destination CIDR:
`egress: [{to: {cidr: 8.8.8.8/32}, ports: [{protocol: UDP, port: 53}]}]`.

**Semantics.** Consistent with east-west egress (symmetric default-deny): a
grouped pod's off-VPC egress is default-deny; a `to: {cidr}` rule opens specific
external destinations (`0.0.0.0/0` for "any"). Ungrouped pods are unaffected.

**Where it's enforced — and why source-side.** Unlike east-west egress, the
destination is not a cozyplane pod, so there is no `to_pod` to check at. The one
point every off-VPC flow passes is the source pod's `from_pod`, specifically the
**gateway path**: a VPC pod's off-net (`dstnet == 0`) traffic routes to the VPC's
NAT gateway, and the check sits right before that routing. Two things stay
exempt because they return *earlier* in `from_pod`:

- **Cluster DNS** — `dns_steer` redirects it to the node-local resolver before
  this point (plumbing, like kubelet ingress).
- **A grouped pod's replies** — the SYN-gate: only a new outbound TCP connection
  (SYN, no ACK) is gated; established/reply packets pass. UDP is gated per
  packet (stateless in the destination, so consistent).

`from_pod` is the tightest hook (it cannot host a BPF-to-BPF call), so the check
is **inlined and loop-free**: `ns_egress_ok` does one `sg_members` lookup for the
source's groups, then up to two `sg_egress_cidr` LPM lookups (exact port +
any-port) on the destination address, and admits if the returned source-group
bitmap intersects the pod's groups. `sg_egress_cidr` is keyed
`{src_net, proto, dst_port, destination CIDR}` → the bitmap of source groups that
may egress there (v4 in NAT64 form, like `sg_cidr`); `0.0.0.0/0` is just a `/0`
entry, so no pseudo-group is needed. No group-loop, so `from_pod`'s budget is
safe.

**v1 scope:** the check gates the **gateway** path. A *floating* pod's egress
(`floating_egress_snat`, which returns before the gateway path) is not yet gated
— a documented follow-up, since floating egress is a distinct deliberate surface.
The `from_pod` source is `p.src` (the pod's claimed address); a co-VPC pod could
spoof a same-VPC IP to borrow its egress groups — the same intra-VPC RPF gap
noted for ingress, closed by the same future `from_pod` RPF.

**Validated on the dev cluster (2026-07-07).** A grouped `client` pod's off-VPC egress to a
node IP (`10.4.100.13:6443`, reached through the vpc-a NAT gateway) is
default-denied with no egress rule; `egress: {to: {cidr: 0.0.0.0/0}, TCP 6443}`
opens it, as do a covering `10.4.100.0/24` and an exact `10.4.100.13/32`, while an
unrelated `10.99.0.0/16` stays closed; removing the rule re-closes it; an
ungrouped pod is unaffected throughout. **The off-VPC-transit fix was essential**
(see the egress-rules section): before it, the pod→gateway hop was dropped by the
east-west egress check — grouped TCP/UDP north-south egress was fully broken (only
ICMP, never gated, worked). East-west enforcement is unchanged by the fix (an
in-VPC destination is still gated: `client`→`web` needs both directions).

## v2 backlog (remaining)

Floating-pod egress gating; FQDN sources;
label-change-follows membership; ICMP rules; a real conntrack to replace the TCP
SYN-gate; `from_pod` source-IP RPF (authoritative source group + general
anti-spoof); peer-existence validation for peer refs;
[#11](../../issues/11) (overlapping north-south cidr union).
