# Security groups — intra-VPC policy

**Status: v1 implemented and dev4-validated (2026-07-06).** East-west
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

## Validated on dev4 (2026-07-06)

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

## v2: peered-group references + the Geneve identity TLV (design)

**Goal:** a group in one VPC can admit a group in a *peered* VPC —
`from: {group: web, vpc: {namespace: team-b, name: vpc-b}}` — enforced
correctly and safely across the tenant trust boundary.

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
names a group in that peer VPC. Validation requires the referenced VPC to be a
declared peer (a `VPCPeering` half exists) — else the rule can never match and
is a silent footgun.

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

This keeps `sg_admit` a single shared subprogram. The risk is the `from_pod`
stack/complexity budget (already tight — see `count_dir`): stamping adds one map
lookup and a `bpf_skb_set_tunnel_opt` with a ~16-byte opt buffer. Load-verified
on the 6.12 kernel; if it overflows, the fallback is to gate stamping behind the
grouped-source check (already planned) and, worst case, a dedicated encap
variant.

**Trust result:** a peer's group identity crossing into another VPC is what the
source node vouched for, not what the packet claimed — c can no longer wear b's
groups. Intra-VPC and same-node keep inference (same trust domain).

## v2 backlog (remaining)

Egress rules; north-south `from.cidr` (world pseudo-group is reserved; needs
floating-path enforcement, then an LPM map for specific ranges); FQDN sources;
label-change-follows membership; ICMP rules; a real conntrack to replace the TCP
SYN-gate.
