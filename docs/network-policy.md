# NetworkPolicy on the default network (net 0)

Status: **design draft — awaiting review**. Nothing here is built.

The production blocker Cilium's removal left open (roadmap §6): the default
network has no `NetworkPolicy` enforcement. The decision (2026-07-11) is to
build it natively, reusing the SecurityGroups enforcement *shape* at net 0 —
and to **skip the Cilium-policy-only spike** (it was only ever a cheap
disproof, and the native path is now the committed direction).

## Two kinds, on purpose

`NetworkPolicy` stays upstream `networking.k8s.io/v1 NetworkPolicy`, consumed
as-is. `SecurityGroup` stays the tenant VPC surface. They are **not** unified
into one kind, for three reasons:

1. **The pod populations aren't clean siblings.** Every pod is on net 0 in the
   form of its fabric IP, but some pods are net-0-only while VPC pods live
   primarily in their VNI. A VPC pod's east-west traffic is SG territory; its
   fabric IP sees only plumbing (node-origin probes, service delivery). One
   kind spanning both would have to explain which half of a pod it governs.
2. **Tenant/system visibility separation.** Tenants read and write
   `SecurityGroups` (their VPC's own design). System policy on the default
   net is the operator's; tenants must not even *read* it. Distinct kinds make
   that an ordinary RBAC statement instead of a filtering problem.
3. **The ecosystem already speaks NetworkPolicy.** Helm charts, operators, and
   conformance suites ship `networking.k8s.io/v1` objects. A cozyplane-native
   kind for the default net would orphan all of it.

They share internal Go packages (selector evaluation, the diff-against-
pinned-map sync discipline, the live-read id allocator) and the datapath
*placement* (destination-side in `to_pod`, TCP SYN-gate, the same L4 reader) —
but not the API, and not the maps.

## Why not literally `sg_members`/`sg_rules` at net 0

`sg_members` values are a **u64 bitmap, ids 1..62 per net** (63 = SG_WORLD).
Per-VPC that is generous; for the entire default network it is nowhere near
enough — a modest cluster has hundreds of distinct label-sets and policies.
And SG semantics differ where NetworkPolicy semantics are non-negotiable:
NP isolation is **per-direction** (`policyTypes`), membership **must follow
label changes** (upstream semantics; SG v1 deliberately chose claim-time),
and peers are *selectors*, not named groups. So net 0 gets **twin maps sized
and shaped for NP**, and the SG maps stay untouched.

## The model: identities, Cilium-shaped

Compiling selectors to per-pair IP rules explodes; compiling them to 62-bit
group bitmaps starves. The proven middle is **numeric identity per unique
{namespace, pod-label-set}** (Cilium's model): userspace evaluates all
selectors once per *identity*, not per pod, and the datapath compares two
u32s.

- **Identity allocation must be cluster-consistent** (the destination node
  derives the *source's* identity from its own map) — but it needs **no API
  and no coordination** (decided 2026-07-11): identity = the first **64 bits
  of SHA-256** over the canonical `{namespace, filtered sorted labels}`
  encoding. A pure function, so every agent computes identical ids from the
  same watched objects. Collision safety at 64 bits: inheriting a *specific*
  identity is a second preimage (2⁶⁴, infeasible); a birthday collision
  (~2³², feasible offline) only conflates two label-sets the attacker himself
  controls — both preimages carry his own namespace — and selectors match
  labels, not hashes, so he gains nothing over just wearing the labels.
  Accidental collision at ~10⁴ label-sets ≈ 10⁻¹². **Door left open**:
  identities never cross the wire, so if compact ids are ever needed (a
  Geneve TLV, map memory) a claims-allocated `PodIdentity` kind (name =
  label-hash, the cross-kind-claims discipline) replaces one compiler
  function — nothing else moves.
- **Churn labels are excluded from identity** (Cilium's proven answer to
  cardinality): `pod-template-hash`, `controller-revision-hash`,
  `statefulset.kubernetes.io/pod-name`, `batch.kubernetes.io/job-*`. Without
  the filter every rollout mints identities and a StatefulSet gets one per
  pod; with it, identity count tracks application shapes. Consequence, same
  as Cilium's: those labels are unusable in NP selectors — the compiler
  warns when a policy references one.
- Each **agent** watches Pods + Namespaces + NetworkPolicies and
  independently compiles the same map contents — deterministic because
  everything is a pure function of the watched objects. (Same trust model as
  SG v1: the map feed is consistent cluster-wide because every agent computes
  from the same inputs.)

### Maps (net-0 twins)

| Map | Key | Value |
|-----|-----|-------|
| `np_ident` | fabric IP (addr128) | `{u64 identity, u32 flags}` — flags: ING_ISOLATED, EG_ISOLATED |
| `np_allow` | `{u64 dst_id, u64 src_id, u8 dir, u8 proto, u16 port}` | presence = allow (`port` 0 = any) |
| `np_cidr` | LPM `{u64 id, u8 dir, prefix, addr128}` | allow / deny (ipBlock `except` = longer deny prefix) |
| `np_ct` | `{addr128 ×2, ports, proto}` LRU | UDP reply-pin (written at the admitted direction) |
| `np_drops` | direction | drop counter (metrics, like `sg_drops`) |

Reserved src ids keep the common policies flat instead of expanded: **0 =
anything** (an empty `from:` rule — allow all, external included) and **1 =
ANY_POD** (`namespaceSelector: {}` — any pod source, i.e. src resolves in
`np_ident`), so "allow all within reason" costs O(subjects), not
O(subjects × peers).

**`np_allow` sizing (decided 2026-07-11)**: overflow is *inherently
fail-closed* — isolation is a flag in `np_ident` and `np_allow` holds only
allows, so a full map can only over-drop, never over-admit. Hence: HASH with
`NO_PREALLOC` and a generous ceiling (~512k entries ≈ 12MB worst case), a
sync-error metric plus an agent log naming the policy whose entries didn't
fit (no silent caps), and cardinality controlled upstream by the identity
label filter above.

`dir` keeps ingress and egress unions independent (NP's directions are
separate policy unions, unlike SG's symmetric-pair admission).

### Enforcement points

- **Ingress: `to_pod`, net-0 branch** — the hook every delivery already
  traverses (same-node redirect, `from_overlay` at net 0, LB/NodePort
  deliveries post-DNAT with the client source preserved, so `ipBlock`
  evaluates the *real* external client). Lookup `np_ident[dst]`; absent or
  not ING_ISOLATED ⇒ allow (upstream default-open). Else resolve
  `np_ident[src]` and probe `np_allow` (exact port, then any-port, then
  ANY_POD), then `np_cidr` — miss ⇒ drop + count.
- **Egress, pod-to-pod: also `to_pod`** — enforced at the destination's
  delivery hook exactly as `sg_egress_admit` is (a flow is delivered only if
  both directions allow; placement-independent, and it spares `from_pod`'s
  496-byte stack).
- **Egress, cluster-external: `from_pod`'s masquerade/uplink path**, the
  `ns_egress_ok` precedent — an `np_cidr` egress probe keyed by the source's
  identity, same loop-free shape.
- **Statefulness**: TCP gated on new connections only (SYN-gate — SG's
  conntrack-free trick, upstream-compatible in practice). **UDP is the open
  problem**: upstream semantics are stateful (an egress-allowed DNS query's
  reply must come back through an ingress-isolated client), and stateless
  symmetric gating would break every UDP request/response for isolated pods.
  Proposed: a small LRU reply-pin written at the admitted-egress direction and
  checked on the reply — the `svc_rev`/`dns_ct` shape the datapath already
  uses for NAT. ICMP not gated (SG v1 precedent: PMTU/ping keep working).

### Exemptions (upstream conventions)

- **Node-origin traffic bypasses ingress policy** — kubelet probes must reach
  pods regardless (every implementation exempts the host; the SG world has the
  NS_MARK/kubelet-exempt precedent). Cross-node node-origin arrives via
  `node_remotes` and is identifiable the same way.
- **hostNetwork pods** are node addresses and inherit the node exemption
  (Cilium's default behavior; documented, not configurable initially).
- **VPC pods**: NP never gates overlay (VNI ≠ 0) traffic — that is SG
  territory. A VPC pod's fabric IP can appear in `np_ident` like any pod's
  (upstream says policies select pods in the namespace), but the only
  gated paths it sees are net-0 deliveries.

## Increments

1. **Ingress, pod selectors** — PodIdentity claims + allocator, agent
   compiler (Pods/Namespaces/NetworkPolicies watches, label-follows from day
   one), `np_ident`/`np_allow`, `to_pod` net-0 ingress gate, TCP SYN-gate +
   the UDP reply-pin, node exemption. e2e: isolation on/off, cross-node,
   label churn, probes still pass, DNS still works for an isolated pod.
2. **ipBlock + egress** — `np_cidr` (with `except`), EG_ISOLATED, the
   `to_pod` egress pair and the `from_pod` external-egress LPM.
3. **Conformance + scale** — run the upstream netpol conformance/cyclonus
   suite against kind; map sizing under identity churn; `endPort` ranges.

Non-goals initially: SCTP, named ports (need pod-spec resolution), policy on
hostNetwork subjects, and the **host firewall** — that is the node-scoped
sibling of this work and gets its own design once this lands.

## Decisions (were review questions, resolved 2026-07-11)

1. **UDP is gated statefully via the LRU reply-pin** — a stateless-UDP gap
   would be too big (every isolated pod's DNS breaks). The pin is written at
   the admitted direction and checked on the reply: the `svc_rev`/`dns_ct`
   shape, the policy path's first per-flow state.
2. **No PodIdentity API for now** — identity is the coordination-free 64-bit
   label-set hash (see "The model"); the claims-allocated kind remains the
   documented evolution path if compact ids are ever needed.
3. **`np_allow`**: NO_PREALLOC HASH, ~512k ceiling, loud overflow (metric +
   log), fail-closed by construction; cardinality controlled by the identity
   label filter. (See the sizing note under "Maps".)
