# NetworkPolicy on the default network (net 0)

> One of three policy layers; flow ownership across
> NetworkPolicy/SecurityGroup/HostFirewall is recorded in
> [policy-layers.md](policy-layers.md).

Status: **complete** (increments 1–3): ingress + egress, selector and
ipBlock peers with `except`, `endPort` ranges, label-follows, the UDP
reply-pin, node exemption. Repo e2e 140/140; **cyclonus conformance 89/90
on the dev cluster — the one miss is a named-port case in disguise**
(a documented non-goal; see "Conformance" below).

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
| `np_allow` | LPM `{prefixlen, u8 dir, u8 proto, u64 dst_id, u64 src_id} + u16 port suffix` | presence = allow. The port is a big-endian LPM *suffix* (increment 3): an exact port is a /16, any-port is /0, and an `endPort` range decomposes into ≤ 31 maximal aligned prefixes — ranges cost O(log) entries and the datapath one probe per peer id instead of exact+any-port pairs |
| `np_cidr` | LPM `{prefixlen, u8 dir, u8 proto, u16 port, u64 id, addr128}` | allow / deny (ipBlock `except` = longer deny prefix; port 0 = any, probed second) |
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
  496-byte stack). This placement is also what makes stateful UDP work for
  the egress direction *with per-node maps*: a reply is policy-checked —
  both the reply's ingress into the initiator AND the responder's egress —
  on the **initiator's node**, which is exactly where the initiator's
  outbound query pinned `np_ct`. One pin sanctions both directions; no
  cross-node state. The pin-write condition is therefore "initiator
  ingress-isolated **or** responder egress-isolated" (the initiator's node
  knows both: `np_ident` is cluster-wide on every node).
- **Egress, cluster-external: `from_pod`, inline** (the destination has no
  `to_pod` anywhere) — reserved-ANY `np_allow` probes plus the `np_cidr`
  LPM, keys through the same per-CPU scratch (from_pod hosts no callee).
  Two documented deviations/gaps here: **node-destined egress is exempt**
  (apiserver/kubelet plumbing keeps working — invariant #7's spirit; resolved
  as designed by the **host firewall** ([host-firewall.md](host-firewall.md)):
  pod→node is gated at the destination *node's* HostFirewall, one owner per
  contract), and a net-0
  **VM guest's per-packet-DNAT'd ClusterIP egress is checked against the
  VIP, not the backend** (socket-LB'd pods — the normal case — present the
  post-translation backend address, matching upstream implementations).
- **Statefulness**: TCP gated on new connections only (SYN-gate — SG's
  conntrack-free trick, upstream-compatible in practice). **UDP is the open
  problem**: upstream semantics are stateful (an egress-allowed DNS query's
  reply must come back through an ingress-isolated client), and stateless
  symmetric gating would break every UDP request/response for isolated pods.
  Proposed: a small LRU reply-pin written at the admitted-egress direction and
  checked on the reply — the `svc_rev`/`dns_ct` shape the datapath already
  uses for NAT. ICMP not gated (SG v1 precedent: PMTU/ping keep working).

### Exemptions (upstream conventions)

- **LOCAL-node-origin traffic bypasses ingress policy** — kubelet probes
  must reach pods regardless (every implementation exempts the host; the SG
  world has the NS_MARK/kubelet-exempt precedent). `np_nodes` carries a
  locality flag; only the pod's own node is unconditionally exempt.
  **Remote-node sources are gated** once a pod is ingress-isolated
  (Cilium's host-vs-remote-node split): a pod that receives cross-node
  node-origin traffic — an admission webhook called by a hostNetwork
  apiserver, an aggregated API — declares it with the `nodes` entity
  (below). This is the first narrowing of the address-trust surface
  (policy-layers.md § trust model).
- **hostNetwork pods** are node addresses and inherit the node exemption
  (Cilium's default behavior; documented, not configurable initially).
- **Entities** (`policy-layers.md` § entities): peers upstream cannot
  express, encoded as a reserved namespaceSelector label
  (`policy.cozyplane.io/entity: local-node|nodes|local-pods` as the sole
  matchLabels entry, no podSelector beside it — anything else evaluates as
  a literal selector). Compiled to reserved source ids: `nodes` admits any
  cluster node address (probed on an `np_nodes` hit), `local-pods` admits
  net-0 pods co-scheduled on the subject's node (probed on a net-0 `locals`
  hit — author-declared placement dependence, allowed by tenet 6 because
  the AUTHOR names it, enforcement doesn't infer it), `local-node` is the
  explicit form of the structural local-node exemption (compiled,
  effectively redundant today, the forward path to a strict mode).
  `local-pods` also works as an egress `to` peer; `nodes`/`local-node` in
  egress are refused with a warning — node-destined egress is
  HostFirewall's (one owner per contract). Reserved ids 2/3/4; real
  identity hashes are remapped off 0–7.
- **VPC pods**: NP never gates overlay (VNI ≠ 0) traffic — that is SG
  territory. A VPC pod's fabric IP can appear in `np_ident` like any pod's
  (upstream says policies select pods in the namespace), but the only
  gated paths it sees are net-0 deliveries.

## Increments

1. **Ingress, pod selectors** — **BUILT.** Agent compiler
   (Pods/Namespaces/NetworkPolicies watches, label-follows from day one),
   `np_ident`/`np_allow`, `to_pod` net-0 ingress gate, TCP SYN-gate + the
   UDP reply-pin, node exemption. e2e (128/128): isolation on/off, same- and
   cross-node, v6, label churn both directions, probes still pass, DNS still
   works for an isolated pod, empty-`from` union.

   *As built.* The `to_pod` gate is a noinline `np_ingress(scratch)` — one
   map-value pointer arg, every key built in a per-CPU `np_scratch` (to_pod
   sits at 432 bytes of frame; the SG scratch/barrier lessons apply
   verbatim). The `from_pod` pin write is inline through the same scratch
   (from_pod = 496 bytes, hosts no callee); it costs non-isolated UDP one
   hash lookup and nothing else. Probe order: exact pair → its any-port row
   → ANY_POD rows (src must resolve as a pod) → ANY rows → the UDP pin.
   `np_nodes` is fed from **all** nodes *including self* (kubelet probes
   source from the local node) — all InternalIP/ExternalIP status addresses
   plus the agent-advertised default-route source (`nodeAddrsAnnotation`,
   the multi-NIC case). Unserved constructs (ipBlock, named ports, endPort,
   SCTP) compile to nothing — fail closed — and warn once per distinct
   message. `NP_EG_ISOLATED` is fed truthfully but not yet enforced.
   Resync is a full recompute + diff-sync on any watched event (the SG
   shape); map writes happen only for actual deltas.
2. **ipBlock + egress** — **BUILT.** `np_cidr` (allow/deny values; `except`
   = a longer deny prefix, allow-wins at an identical prefix so policies
   union), egress enforced at the destination's `to_pod` for pod-to-pod and
   inline at `from_pod` for identity-less destinations, the widened pin
   condition. e2e (138/138): ipBlock admit + except through the LB path
   with the source preserved, egress pair/DNS/external-cidr/empty-`to`,
   plus everything from increment 1.

   *As built — a verifier war story with a moral.* The first cut put both
   directions in one `np_check` callee and counted `from_pod`'s gate drops
   via the `count_np_drop` subprogram. the dev cluster's 6.12 kernel loaded it; kind's 6.8
   verifier refused: *"combined stack size of 2 calls is 544"* —
   `from_pod`(496) plus even a trivial callee frame busts 512, and the
   two-direction callee's spills did the same on `to_pod`(432). The moral:
   **frames near the cliff get sibling callees, never nested ones, and hot
   paths at 496 bytes get zero bpf-to-bpf calls** — `np_ingress` and
   `np_egress` are two lean siblings (sibling frames don't stack), and
   `from_pod` counts its drop inline with the map key routed through
   scratch. Different kernels explore different verifier states: a load
   that succeeds on one kernel proves nothing about the floor the project
   supports — kind's 6.8 is the gate.
3. **Conformance + scale** — **BUILT.** `endPort` ranges via the `np_allow`
   port-suffix LPM (above): general for identity-pair rules; for
   **ipBlock × endPort** the two variable dimensions (address prefix, port
   prefix) cannot share one LPM, so ranges on ipBlock rules expand per-port
   up to 64 ports and compile closed (with a warning) beyond — a documented
   cap, not a silent one. The pinned `np_allow` type change is absorbed by
   `reconcilePins` (incompatible pin removed on agent restart, re-seeded by
   the first resync; running pods keep the old program+maps until
   re-attach, so there is no fail-open window — observed live on the dev
   cluster: "recreated incompatible pinned maps: [np_allow]").

   **Conformance (cyclonus, dev cluster, 2026-07-12).** `test/cyclonus.sh`;
   90 generated cases (defaults minus multi-peer/upstream-e2e/example/
   namespaces-by-default-label/named-port/sctp, **end-port re-enabled**),
   TCP/UDP servers, pod-IP destinations. **89/90 passed** — every tag
   family 100% (direction 78/78, peer-pods 20/20, ipBlock ±except 4/4,
   ports 34/34 incl. end-port 8/8, protocols 24/24, conflicts 16/16,
   pathological 2/2, delete/set-label perturbations all green). The single
   failure, `update-policy`, is a **named port in disguise**: the case's
   step 2 updates the ingress port to `serve-81-udp`, which we fail-close
   by design; cyclonus tags the case only `update-policy`, so the
   named-port exclusion can't catch it. Reproduced in isolation and
   root-caused to exactly the 4 cells the named-port rule would open.
   The generic update path is separately proven (a live create-then-update
   flip enforces in seconds), as is the responder-egress-isolated UDP
   reply (the widened-pin shape no e2e had covered).

   Harness notes for reruns: cyclonus hardcodes `.svc.cluster.local`
   (dev cluster domain is `cozy.local`) → `--destination-type pod-ip`;
   SCTP servers flag every isolated pod's whole row+column (we gate only
   TCP/UDP) → `--server-protocol TCP,UDP`; its state verifier fatals on
   stale half-terminated x/y/z namespaces from a previous run.

   **Scale**: `BenchmarkCompileNetworkPolicies` — 5000 pods / 120 shapes /
   200 policies ≈ **5.9ms per full recompute** (i7-1280P); every watched
   event costs one recompute, so pod churn is a non-issue.

Non-goals initially: SCTP, named ports (need pod-spec resolution), policy on
hostNetwork subjects, and the **host firewall** — the node-scoped sibling of
this work, since built: [host-firewall.md](host-firewall.md).

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
