# Security groups — intra-VPC policy (design draft, for review)

**Status: DRAFT — not implemented.** This is the buildable first increment of
`design.md` §7 ("Network identity & security groups"). Where this doc and §7
differ, the difference is called out and is a review question, not an accident.

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
  tenant-facing value is, and egress doubles the datapath work. (Review Q1.)
- `from.group` references a group in the **same VPC**. Peered-VPC references
  are v2 (the peers map admits the traffic today; policy across a peering needs
  identity distribution across tenants — deferred, see Review Q2).
- `from.cidr` matches the *pre-masquerade* client address for bridged/floating
  north-south traffic (the datapath knows it — the rewrite happens at the same
  hook that will enforce). FQDN rules from §7 are out of scope for v1.

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
- The **numeric group id** is allocated by the controller per VPC (1..63; id 0
  = "no groups, legacy allow"). 63 groups per VPC in v1 — a `u64` bitmap in the
  datapath. Allocation lives in `SecurityGroup.status.id`, assigned like VNIs
  (live-read allocator; the VNI-duplicate lesson applies).

## Datapath

Two new maps, both keyed like `locals` (net-scoped, addr128):

| Map | Key | Value |
|-----|-----|-------|
| `sg_members` | {net, vpc IP} | `u64` group bitmap of the *member* |
| `sg_rules` | {net, dst-group-id, proto, port-hi} | `u64` allowed-src-group bitmap + flags |

Enforcement is **destination-side, in `to_pod`** — the hook every delivery
already traverses (same-node redirect, from_overlay hand-off, and the bridge all
end there), so placement independence holds with no Geneve TLV yet:

1. `dstmap = sg_members[{net, dst}]`; zero ⇒ legacy allow (no groups) — done.
2. `srcmap = sg_members[{net, src}]` (intra-VPC source), or the CIDR-rule
   pseudo-group for bridge/floating traffic (the hook knows the original
   client address pre-rewrite).
3. For each group bit in `dstmap`: look up `sg_rules` for (group, proto, port);
   admit if `rule.allowed & srcmap` (or the CIDR pseudo-group matches). Bounded
   loop over set bits (≤63, verifier-friendly with a fixed unroll of the
   bitmap scan — in practice a handful).
4. Miss ⇒ drop, with a per-net drop counter (the observability hook #2 wants).

The agent syncs both maps from Ports (`status.groups`) and SecurityGroups
(`status.id` + rules), same diff-against-pinned-map pattern as peers/gateways.

**Why not source-side too?** §7 wants egress rules eventually; the identity TLV
in the Geneve header (§7) is what makes *destination trust of source identity*
robust when source-side marking is added. In v1 the destination derives the
source's groups from its own `sg_members` map — consistent cluster-wide because
the same controller feeds every agent. The TLV becomes necessary only when
identities must cross a trust boundary (peered VPCs, v2).

## Control plane

- `SecurityGroup` CRD + aggregated-apiserver storage (both modes, like
  everything else).
- Controller: id allocation (live-read), selector evaluation → `Port.status.groups`,
  rule compilation → nothing (agents read SecurityGroups directly).
- RBAC: the VPC owner manages groups (`create securitygroups` in their
  namespace + the object's `vpcRef` is same-namespace like VPCPeering — no new
  virtual verb needed; owning the namespace *is* owning the VPC's policy).
  (Review Q4.)

## Test plan

kind e2e: group two pods, assert allowed port passes / other port drops / an
ungrouped pod in the same VPC still reaches everything (legacy) / a bridged
north-south client hits the CIDR rule / policy survives the map-recreation
phase (rebuild must restore `sg_members` — the Port carries the groups, so the
agent resync covers it; no new alias field needed).

## Open questions (review)

1. **Ingress-only v1** — acceptable, or is egress a hard requirement for the
   first cut?
2. **Peered-VPC group references** — v2 as proposed, or must v1 at least
   *close* peered traffic when the destination has groups (currently peered
   traffic would be subject to the same ingress rules via the CIDR/group-miss
   path — i.e., peered sources simply won't match any group and get dropped
   once the dst is grouped; is that the right default)?
3. **Claim-time membership** — is label-change-follows v2 acceptable?
4. **AuthZ shape** — owner-namespace-implies-policy-authority, or do you want a
   `policy` virtual verb on the VPC (mirroring `export`/`peer`)?
5. **Naming** — `SecurityGroup` (AWS familiarity) vs `VPCPolicy`?
