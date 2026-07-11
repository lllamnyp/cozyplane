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
  derives the *source's* identity from its own map). A pure label-hash risks
  collisions (unacceptable for policy); central allocation is the answer, and
  cozyplane already owns the pattern: a system-internal aggregated kind
  **`PodIdentity`** whose **name is the claim** (deterministic hash of the
  canonical label-set; first creator wins, the apiserver's name uniqueness is
  the lock — exactly the cross-kind claims discipline), with `status.id`
  assigned by the controller's live-read allocator (the VNI/SG-id lesson).
  Tenant RBAC never sees it (reason 2 above).
- Each **agent** watches Pods + Namespaces + NetworkPolicies + PodIdentities
  and independently compiles the same map contents — deterministic because
  identity ids come from the shared claims and everything else is a pure
  function of the watched objects. (Same trust model as SG v1: the map feed is
  consistent cluster-wide because every agent computes from the same inputs.)

### Maps (net-0 twins)

| Map | Key | Value |
|-----|-----|-------|
| `np_ident` | fabric IP (addr128) | `{u32 identity, u8 flags}` — flags: ING_ISOLATED, EG_ISOLATED |
| `np_allow` | `{u32 dst_id, u32 src_id, u8 dir, u8 proto, u16 port}` | presence = allow (`port` 0 = any; reserved src_id ANY_POD for empty-selector peers) |
| `np_cidr` | LPM `{u32 id, u8 dir, prefix, addr128}` | allow / deny (ipBlock `except` = longer deny prefix) |
| `np_drops` | direction | drop counter (metrics, like `sg_drops`) |

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

## Open questions (review)

1. **UDP reply-pin vs. deferring UDP gating** — the pin is per-flow LRU state
   on the policy path (the datapath's first, outside NAT). Acceptable, or
   should increment 1 gate TCP only and document the UDP gap (SG-v1-style)?
2. **PodIdentity as an aggregated kind** — agreed as system-internal API
   surface? (Alternative — per-agent pure label-hash — rejected above for
   collision risk; alternative — controller-annotated pods — rejected for
   write churn on objects cozyplane doesn't own.)
3. **`np_allow` sizing**: HASH (non-evicting) with generous headroom and a
   drop-to-log on cap, or is there appetite for a hard bound + degraded-mode
   (fail-closed for affected identities)?
