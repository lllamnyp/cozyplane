> Validation scope: lab results and earlier source hashes below describe their
> original branches. They do not certify this combined integration. Its current
> build, race, kernel and deployment checks are recorded separately.

# cozyplane — roadmap

A living checklist of what is built and what is outstanding. It complements the
design docs (`design.md`, `control-plane.md`, `internals.md`, `live-migration.md`)
— those explain *how*; this tracks *what's done*.

**How to read it.** A ticked box is merged on `main` and exercised by the e2e
suite or validated on a real cluster; where a real-cluster validation happened
it's noted. An unticked box is planned work; where a GitHub issue tracks it, the
number is linked (e.g. [#7](../../issues/7)). Security-audit checkboxes added during the local audit record verified working-tree behavior; they do not imply a commit, merge, or deployment. Keep this file honest — tick a box
only when the thing actually works end to end, and add outstanding items here as
they're discovered rather than leaving them only in issues.

---

- [x] Local extended IPsec tunnel validation: dedicated Debian KVM guest under
  Docker Desktop with XFRM interfaces, real IKEv2 peers, IPv4/IPv6, multi-VPC
  authorization, 1/8/16-peer load, ten-minute soak, impairment/recovery, rekey,
  certificate/EAP pools, credential revocation and appliance failover. Review
  fixes and ordinary cleanup passed on the final image/kernel; see
  `test/ipsec-validation.md` for phase-specific provenance, losses and kernel/
  availability limits. This tick records working-tree validation only.
- [ ] Qualify IPsec on a real external cluster/provider and native Windows
  IKEv2 clients; merge remains outstanding.
- [x] Local VPN monitoring contract: WireGuard/IPsec exposition, VictoriaMetrics
  HTTP ingestion, HA aggregation, missing-target/family/dependency alerts and
  Grafana queries tested; see `test/vpn-monitoring-validation.md`. Working-tree
  validation only; real VMAgent/VMAlert/Grafana selection remains to verify.

- [ ] WireGuard workstation backend: stable client pools, per-connection VPC grants,
  public client configuration and confirmed revocation implemented locally.
  Docker Desktop integration, native Windows application traffic, 1/8/16-client
  load, ten-minute soak, packet impairment and adversarial review passed; see
  `test/wireguard-client-validation.md` for losses and availability limits.
  Real-cluster validation and merge remain outstanding.

- [x] Security audit SEC223: bound FloatingIP admission, legacy index keys and status diagnostics; verify ownership-preserving withdrawal, valid recovery and agent projection. Main module Linux race/vet passed locally.
- [x] Security audit SEC224: prevent predecessor Pod and sandbox Ports from masking or replacing current ServiceVIP backends; reuse bounded sandbox proofs and verify list-order independence. Main module Linux race/vet passed locally.

- [x] Security audit SEC217: reproduce generic-store metadata diagnostic amplification; reject the first malformed entry before aggregation, preserve existing hooks and valid metadata, and verify all resources and `/status` stores behaviorally.
- [ ] Security audit SEC218: reproduce request-option diagnostic amplification through the actual Kubernetes HTTP handlers; reject malformed field managers before body reads/SDK validation while preserving standard authentication, authorization, APIStatus and valid options.

- [x] Security audit SEC188: reproduce route saturation with real packets and prevent incomplete routing snapshots from falling back to cleartext NAT; verify unresolved next hops, receive-side route precedence and recovery.
- [x] Security audit SEC189: preserve explicit VPN route precedence at the Geneve receive hook when a default gateway is co-located; verify actual destination MAC and unavailable-next-hop drops in both families.
- [x] Security audit SEC190: verify accepted VPN prefixes remain blackhole routes while the appliance has no Ready Port, rather than disappearing from controller status and allowing ordinary egress.
- [x] Security audit SEC191: verify quota/input rejection retains previously accepted VPN prefixes as blackholes after draining appliance authorization; reproduce the status transition before qualifying the fix.
- [x] Security hardening 192: verify an explicit remote route fails closed when Geneve transport configuration is absent, with a positive encapsulation control in both families.
- [x] Security audit SEC193: bound actual-cache VPN peer copies to configured quota plus one overflow witness, excluding terminating peers before the limit; verify complete fitting-set recovery and cache independence.

- [x] Security audit: guard whole NetworkPolicy and SecurityGroup updates so failed identity/membership insertion cannot revert an endpoint to allow; test real map exhaustion, replacement and recovery in the kernel.

- [x] Security audit: verify same-sandbox ordinary CNI ADD concurrency and rollback; bound any host serialization resources and wait.

- [x] Security audit: measure guest listener Port candidate work and scope current lister reads to local VNI/IP claims.
- [x] Security audit: verify and bound stalled live SDN requests during sever acknowledgement, preserving the address barrier and parent context.
- [x] Security audit: reproduce retained Port notifications during sever acknowledgement stalls; coalesce API work while preserving immediate proven-owner quarantine and unrelated routes.
- [x] Security audit: verify revocation recovery without new events when SDK resync is disabled; retry sever acknowledgements and forwarding grants through their coalesced workers.
- [x] Security audit: reproduce cumulative legacy ownership delays during binding withdrawal; bound a complete legacy phase and preserve current consent at publication.
- [x] Security audit: confirm current consent after a protected legacy ownership read; preserve replacement endpoints and verify attachment withdrawal and scoped recovery in the kernel.
- [x] Security audit: verify best-effort startup request lifetime for DNS discovery, node-address advertisement and missing-FabricIP repair with real stalled HTTP requests.
- [x] Security audit: verify native VPC delivery when an address equals a fabric/global alias; retain SecurityGroups, owner scopes and sanctioned host/resolver paths. Local real-kernel and global race tests passed; no existing-cluster deployment.
- [x] Security audit: verify VPC fabric-route reconstruction when fabric and VPC addresses coincide; real IPv4/IPv6 route, pinned-map rebuild/revocation controls and full global race/vet validation passed locally.
- [x] Security audit: bound startup FabricIP repair Pod snapshots and skip reads without rebuilt candidates; actual SDK HTTP behavior/allocations and full Linux agent/IPAM race suites plus vet verified locally.
- [x] Security audit: verify stalled Pod requests in shared legacy ownership joins outside guest cutover.
- [x] Security audit: verify forwarding grant updates with mixed proven and uncertain legacy endpoints.
- [x] Security audit: verify mixed UID-owned and uncertain legacy endpoints during revocation; preserve partial quarantine and address barriers.
- [x] Security audit: verify proven-owner revocation during core API failure and preserve legacy ownership requirements.
- [x] Security audit: verify migration FabricIP joins; scope target/legacy claim retrieval by local node, consumer namespace and full container ID.
- [x] Security audit: bound guest-announcement API stalls; retain the per-Port listener through bounded cutover work and verify child cancellation with a real HTTP client.
- [x] Security audit: scope bulk revocation FabricIP claim retrieval by Pod UID and full sandbox/interface and measure copied rows and allocations.
- [x] Security audit: bound repeated migration source-forward scheduling and timer/goroutine retention by current forwarding entries and verify expiry ownership.
- [x] Security audit: bound Pod-label snapshots before serialization in CNI and VM cutover writers; preserve complete selector identity and pinned IP/MAC.
- [x] Security audit: protect pod-namespace interfaces from stale DEL when a namespace path is reused; verify live host peer sandbox ownership.

## Immediate roadmap — what's genuinely open

### CRD distribution and security follow-up — 2026-10-06

- [ ] Merge the optional distroless control-plane target and chart image
  selection. Private amd64/arm64 builds and scans passed; the controller and
  admission ran on the Talos lab. Retain Debian for networking's external tools.
- [ ] Review and publish the full `api.mode: crd` distribution, eleven generated
  tenant schemas, shared admission strategies, TLS rotation and matching
  two-phase PackageSource variants. Seventeen actual API cases passed on the
  three-node Talos lab, including webhook outage/recovery and normal cleanup.
  Review/merge and the required CRD CI lane remain open.
- [ ] Complete regional certification beyond the acquired lab proofs: IPv4/IPv6
  intra-VPC, split-horizon DNS, ServiceVIP, IPv4 Internet and FloatingIP closure,
  directed peering revocation, automatic DHCPv6, VM migration and restart.
  The lab's IPv4 DNS/underlay cannot certify native IPv6 DNS or Internet.
- [ ] Adopt the published, scanned image pins in the release CI. Private lab
  control-plane source `88423a3` and networking source `8146dce` were pulled
  and exercised; the standard lab CI does not yet build the separate distroless
  target. Unit/race checks and the global gosec scan passed. Short idle/load
  memory windows do not certify absence of a long-running heap leak.

- [x] SecurityGroup reference budgets: bound admission and legacy controller,
  cache and agent consumers before hashing/lookup; preserve cleanup, immutable
  VPC anchors and unrelated tenants' policies (SEC-226).

- [x] ServiceVIP candidate lookup: replace the whole-VPC Port copy with bounded
  indexed Pod candidates; verify current-generation/sandbox fences, missing-index
  refusal, retarget/deletion, and a cache dataset exceeding 250 MiB (SEC-225).

- [x] Security audit: verify and enforce concurrent first-allocation uniqueness for a persistent VM NIC across nodes; preserve one pinned IP/MAC and staged target binding.

- [x] Security audit: coalesce agent metrics collection into an immutable one-second response snapshot; verify burst collection counts, refresh, failure retries and bounded response size.

- [x] Security audit: exclude malformed/oversized legacy VPCs from peering grants and network delivery replay so they cannot retain unrelated historical routes; verify informer replay and controller readiness.

- [x] Security audit: bound and validate VPC CIDR input in aggregated admission and CNI; isolate oversized legacy VPCs from healthy network replay and retain legacy cleanup updates.

- [x] Security audit: reclaim counters of disappeared VPC VNIs from bounded kernel maps; preserve live per-CPU values and prevent stale seeders from restoring retired scopes.

- [x] Security audit: preserve a same-UID Port rebound during failed CNI ADD rollback with resourceVersion preconditions; verify conditional deletion and successful local annotation updates using fake clients.

- [x] Security audit: confirm persistent VM launcher absence live before Port GC; verify delayed cache, UID ownership, failed reads, finalizer and identity preservation.
- [x] Security audit: revoke fallback/appliance gateway projections on boundary-only changes; require effective boundary authority and preserve appliance doors without NAT allocation.
- [x] Security audit: avoid repeated identical VPC status writes while retaining live duplicate-VNI checks and allocation/repair updates.
- [x] Security audit: index peering controller reciprocal and VPC-event cache reads by complete current references; verify scoped copies, retarget, deletion and consent.
- [x] Security audit: remove quadratic CIDR overlap reparsing shared by peering agent/controller/responder; verify parity against pairwise definition and measure actual allocations.
- [x] Security audit: reap terminal Pod FabricIP and ephemeral Port claims even while Pod history remains; verify live reader confirmation, nonterminal preservation and VM identity exemption.
- [x] Security audit: scope fallback Gateway reconciliation to the current VPC boundary index; verify copied rows and oldest-first withdrawal/recovery with fake clients.
- [x] Security audit: index VPN credential Secret notifications by namespace/current reference; verify scoped copies, all authentication modes, reference removal and deletion revocation.

- [x] Security audit: reject CNI attachment/claim/rebind against a terminating or unassigned VPC before mutation; fake-client resolution and persistent identity preservation verified locally with real CNI veth tests enabled.

- [x] Security audit: require current VPC/VNI and non-terminating canonical Port claims in the gateway map; real informers with a fake clientset locally verify VPC deletion/recreation and claim recovery.

- [x] Security audit: bound VPN pool/DNS/BGP and per-connection prefix admission before validation loops, and apply gateway collection preflight to legacy objects; real validator benchmark and boundary/refusal tests verified locally.

- [x] Security audit: preflight managed VPN prefix input before configuration, check quotas before expansion/filtering and bound rejection diagnostics; local fake-client tests verify authorization withdrawal and recovery.

- [x] Security audit: stop VPNConnection status observations from immediately scheduling another appliance poll; fake-client status reflection and real workqueue tests retain config/deletion/retarget notifications locally.

- [x] Security audit: index VPN VPC/Port notifications and peer lookups by current references; local fake-client tests verify scoped copies, retarget/deletion and keep live quota checks.

- [x] Security audit: withdraw owned VPN appliance/grant/endpoints on VPNGateway or VPC deletion start, observe VPC lifecycle, and locally verify creation refusal and existing authorization cleanup.

- [x] Security audit: scope VPCGateway conflict and VPC/Port event cache lookups to the referenced VPC; fake indexed client verifies copied rows, unrelated gateway exclusion and reference changes locally.

- [x] Security audit: withdraw ingress/NAT and retire owned gateway resources when a VPC starts deleting; verified locally with projection and fake-client lifecycle tests, without deployment or commit.

- [x] Security audit: index route/appliance Pod notifications by selector namespaces and match labels; verify scoped cache rows, cross-namespace selection and label-removal events.

- [x] Security audit: index FloatingIP conflict/event lookups by scoped target and reconcile Ready contenders on retarget; verify event fan-out and copied rows with fake cache indexes.

- [x] Security audit: share FloatingIP oldest-binding arbitration between controller and agent; reject stale losing status, normalize targets and verify pending winner/deletion promotion.

- [x] Security audit: withdraw stale FloatingIP SNAT on retarget and reconcile both map directions including orphan reverse entries; verify real kernel maps, ownership and capacity refusal.

- [x] Security audit: verify current live VPC/VNI and canonical non-terminating target claims for FloatingIP controller and agent; test recreation/deletion and preserve cluster-wide delivery.

- [x] Security audit: remove recursive EndpointSlice family replacement through a stale informer cache; test FloatingIP/NAT replacement and ownership conflicts.

- [x] Security audit: enforce current VPC claims in managed VPN single/active-active appliance resolution; verify legitimate ownership chain and stale VNI/address/deletion.

- [x] Security audit: bound controller route inputs/work/diagnostics and index candidate Ports by pod identity; verify refusal, recovery and benchmark actual resolution.

- [x] Security audit: scope VPC/VPN route projection to the gateway's current live VPC VNI and canonical Port claims; verify stale VNI/ref/address and deletion with actual informers.

- [x] Security audit: enforce the sole VPC boundary for explicit routes in controller and agent, and prevent losing gateways from clearing the winning appliance door; test promotion and stale status.

- [x] Security audit: resolve VPC route/appliance next hops only from current pod-UID and VPC-VNI claims; test predecessor, deletion and replacement behavior.

- [x] Security audit: apply the VPN route CIDR deny-set to directly authored VPCGateway routes; verify reserved/default/invalid and configured internal prefixes with controller behavior tests.

- [x] Security audit: host-firewall updates retain default-deny when map
  synchronization fails, including first enable and partial replacement; verify
  actual BPF ingress and egress with deliberately undersized rule maps.

The sections below are the full ledger, and most of it is ticked. This is the
short list: what is actually left, in rough priority order. Revised **2026-07-14**,
once the north-south arc closed (one declared boundary, metered, with the tenant's
own egress identity; cozyplane attracts nothing) and the multi-tenancy rules were
built (a tenant persona, a tenant that can see itself, a ceiling).

**Regression — the black-hole is fixed; the identity gap is the reserved design**

0. **[x] v6 VPC egress no longer black-holes with a pooled `VPCGateway`** ([#15](../../issues/15); unit-tested + **dev4-validated**).
   The bug: `ensureNATAddress` was **family-blind** (it took `firstFreeAddress(pool.Spec.
   CIDRs, …)` and never looked at the VPC's family, so a v6 VPC could be handed a *v4*
   NAT address); the gateway controller then deleted the gateway Deployment the moment
   `status.natAddress` was set; no pod ⇒ no `.1` Port ⇒ **no `gateways[vni]` entry**. But
   `from_pod` guards the eBPF NAT with `!p.is_v6`, so a v6 packet skipped it, fell to the
   isolation block, reached the gateway path, **missed, and dropped**. Dual-stack was the
   nastiest case — v4 kept working, so the VPC looked healthy while v6 silently blackholed.
   **Fixed** by gating on *family*: `ensureNATAddress` now allocates a **v4** address (the
   only kind `vpc_nat_snat` can wear) and only for a VPC that has a v4 CIDR; the pod is
   kept whenever the VPC has a v6 CIDR. It composes, because `from_pod` tries
   `vpc_nat_snat` **before** the isolation block — on a dual-stack VPC, v4 takes the eBPF
   NAT and never reaches the pod, v6 falls through to it. So a v6/dual-stack VPC now keeps
   its pod and **launders its v6 egress into the node's address** (tenet 8) — that is the
   status quo restored; **tenet 8 for v6 is now satisfied by item 1 (v6 VPC NAT, below)**.
   Dev4 before/after (same objects, only the controller image rolled): a dual-stack VPC's
   gateway pod went **ABSENT → PRESENT** (v6 path restored) while a pure-v4 VPC's stayed
   absent (eBPF NAT). Still open: a **v6 gateway-egress phase in `vpc-e2e.sh`** (the controller logic is
   unit-tested, but real-cluster v6 egress is only covered by the kind-only, already-broken
   `test/e2e.sh`, item 14) (§3, §8).
1. **[x] v6 VPC NAT — a per-family egress identity** ([#15](../../issues/15); unit-tested + **dev4-validated**:
   the agent loaded the new datapath (verifier gate passed on the Talos 6.x kernel), a
   dual-stack VPC drew both a v4 and v6 identity and **shed its gateway pod entirely**, and
   every agent programmed both addresses; end-to-end v6 egress needs a v6-uplink cluster). A VPC now wears a v4 address for its v4 egress **and** a v6 address for its v6
   egress: `vpc_nat` holds both (`ip`/`ip6`), `vpc_nat_snat6`/`vpc_nat_reverse6` mirror the
   v4 twins, `ensureNATAddress` allocates per family into `status.natAddress`/`natAddress6`,
   and the gateway pod is retired once **every** family the VPC has is served in eBPF. The
   reserved v4/v6 asymmetry is resolved by treating the families identically — a family the
   pool cannot cover keeps the pod, a fully-covered VPC has none (§3, §6a). **`nat_of` and
   `nat_owner` were already `addr128`-keyed, so only `vpc_nat` grew a second address and the
   port shards are shared** (the v4/v6 masquerade precedent). This **unblocks retiring
   `cmd/gateway`** (item 7): it reduces to requiring an assigned address for every family.

**Features**

2. **Retire `ExternalPool`; an external address comes from a delegated Service** —
   **[external-addresses.md](external-addresses.md)**. cozyplane used to allocate
   external addresses itself (`firstFreeAddress` over the pool's CIDRs) and
   **nothing attracted what it allocated** — the pool was a CIDR list nothing routes.
   The fix: cozyplane sources **no** address. A `FloatingIP` owns a
   `Service type: LoadBalancer` labelled `service-proxy-name: cozyplane`; the
   allocator/fabric allocates + attracts (the same contract LoadBalancer ingress already
   lives by), every proxy skips the datapath (the kpr fix, done), and cozyplane consumes
   `status.loadBalancer.ingress` and delivers. A `VPCGateway`'s NAT identity owns a
   **backend-less** such Service (`etp: Cluster`; its replies still need attracting via
   `vpc_nat_reverse`). Reservation (the address-controller's `IPAddressClaim`,
   [community#35](https://github.com/cozystack/community/pull/35)) is an **optional**
   layer: a reservation is an `IPAddress` ledger object, never a Service; binding is
   one association annotation on the consumer's own Service, and the driver enforces
   one claim, one workload (external-addresses.md §7).
   `FloatingIP` **survives** as the binding/datapath object; `ExternalPool` and the
   `attach` verb retire; governance moves to Service RBAC + the allocator's scoping.
   **The eBPF does not change at all.** Increments: **FloatingIP→Service (done,
   dev4-validated end-to-end: an external OCI VM on the node VLAN reached a VPC pod
   via its FloatingIP, MetalLB allocating + advertising the address off a synthesized
   EndpointSlice)**, **NAT identity→Service (done, dev4-validated — a VPC pod egressed
   as its VPCGateway's owned-Service NAT address and the reply round-tripped via the
   self-addressed EndpointSlice + `vpc_nat_reverse`; the #15 pod fallback holds)**,
   **delete `ExternalPool` (done — the kind, its storage, the `attach` verb and both
   deprecated `poolRef` fields are gone; the pool's second job, triggering the
   uplink attach on every node, is now derived from the addresses that exist:
   floating, NAT identities, and LB ingress IPs via a Services watch)**, then
   **reservation (done, dev4-validated with the full stack — address-controller +
   metallb-iad + MetalLB + cozyplane: a FloatingIP naming a claim wore exactly the
   reserved address, survived delete-and-rebind with the same address, and was
   externally reachable throughout)**: `addressClaimName` fields copied into the
   association annotation on the owned Service(s) — a pure pass-through, fully
   functional with the mechanism absent (§3). **The arc is complete.**
3. **Public IPs on the default network — supersede cozy-proxy** ([#14](../../issues/14)) —
   **[public-ip.md](public-ip.md)** (design, awaiting review). Cozystack today gives a
   net-0 VM a real public address (all ports in, and egress *as that address*) with
   [cozy-proxy](https://github.com/cozystack/cozy-proxy)'s nftables 1:1 NAT. Cozyplane
   takes over the default network, so that has to go — and it cannot coexist: it is
   nft, against the pure-eBPF invariant. (**Increment 0 done:** `cozyplane-kpr` now
   honours `service.kubernetes.io/service-proxy-name`, so it no longer fights another
   proxy over the same Service.) The capability is **already in the
   datapath** — it is the EIP path, which is net-scoped and merely declines to run at
   net 0 (`from_pod` guards the egress SNAT with `if (srcnet && !dstnet)`). Drop-in:
   the same Service + label + `wholeIP` annotation, **no new kind**. The real
   constraint is **NetworkPolicy**: `to_pod` answers a `floating` hit *before* the
   net-0 NP gate, so a naive port would let a public-IP'd pod bypass policy entirely —
   worse than what it replaces. Fix: hoist the whole-IP DNAT into the tail-called
   `lb_ingress`, so `to_pod` sees an ordinary packet and NP applies unchanged (§6).
4. **Per-VPC metadata endpoint + guest autoconfiguration** — design drafted in
   [vm-provisioning.md](vm-provisioning.md), awaiting review (§3).
5. **Site-to-site VPN** ([#6](../../issues/6)) is implemented through managed
   WireGuard and route-based IPsec (the latter needs `CONFIG_XFRM_INTERFACE`);
   **cross-family v4↔v6 translation** ([#9](../../issues/9)) remains a design draft
   (§3, §4).
6. **SecurityGroup v2 leftovers**, all low priority: ICMP rules; peer-existence
   validation for peer refs; and **a real connection table to replace the TCP
   SYN-gate** — that last one is shared with NetworkPolicy and HostFirewall, so it
   wants solving once for all three layers rather than three times. FQDN egress is
   **rejected**: it needs a DNS-snooping engine, which is out of scope (§3).

**North-south residue** — the arc is built; these are the ends it left loose.

7. **The address-less gateway pod still exists, and it still launders** — a
   `nat.enabled` `VPCGateway` family whose owned LoadBalancer Service has no
   assigned address (no LB implementation, or one that cannot serve the family)
   has no identity to wear, so the controller still spawns the per-VPC gateway pod,
   and that pod's egress is SNATed to its fabric IP and then re-SNATed by the
   cluster masquerade to the **node's** — precisely the tenet-8 violation
   increment 2 set out to end. `cmd/gateway` and its netns iptables are therefore
   still in the tree and still reachable. Deleting them means requiring a working
   LB implementation for NAT egress (fail closed: no address, no egress), or
   keeping the pod as the no-LB fallback and saying in writing why a tenant may
   wear the platform's identity then. Leaning toward requiring the LB
   implementation — Cozystack always ships MetalLB — but decide it deliberately (§3).
8. **The gateway's DNS door** — the gateway pod proxies cluster DNS on `:53`; the
   split-horizon resolver already serves VPC pods, so it is probably vestigial.
   Folded into (7): confirm before deleting, or tenant DNS breaks with the pod —
   [north-south.md](north-south.md) §7.
9. **Per-VPC NAT port-pool exhaustion** — each node SNATs a VPC's pods from its own
   shard (`NAT_SHARD_SPAN` 4032, 16 shards). Nothing accounts for a tenant
   exhausting it, and a node-set change reshuffles shards and breaks live flows.
   Known and accepted at prototype scale; it needs a story before it is not
   ([north-south.md](north-south.md) §7).
10. **Inbound MTU on an encapsulated north-south path** — clamp the TCP MSS in the
   inbound SYN at the encapsulating node. Shared by the EIP request half and
   `etp: Cluster` DSR, so solve once — [floating-ha.md](floating-ha.md) §7 (§3).

**Hardening**

11. **Node-origin path-trust** — all three policy layers still recognise node
   origin by *source address* (`np_nodes` / `hf_self` / `NS_MARK`-absence). The v6
   masquerade-laundering bug proved the class is exploitable; the fix is to trust
   the *channel* (host→veth same-node, `node_remotes` overlay cross-node,
   TLV-authenticatable) instead. Cheap first step: per-layer
   `*_node_exempt_total` counters, so the exemption is at least visible.
   **Net-0 RPF for NetworkPolicy identity** is the same one-lookup shape as the
   `from_pod` RPF SG v2 shipped — the natural follow-on (§6).
12. **NP egress vs VPC-pod fabric IPs** — a decision, not a build: either drop VPC
   pods from `np_ident` (fabric IPs become `ipBlock` territory) or document the
   corner as intended (§6).

**Test gaps**

13. **VM-migration e2e** — none exists, anywhere; and the cutover path changed when
    `Port.spec.fabricIP` was normalized away (the controller's fabric-IP copy was
    deleted). Real-cluster hand-validation is the only coverage (§5, §8).
14. **`test/e2e.sh` is unrun since the API-group split** — its floating-IP phases
    were rewritten to the delegated-Service model (the e2e plays the allocator by
    patching the owned Service's LB ingress, and the attractor by configuring the
    address on a node) so they *apply* again, but the script has not been run
    end-to-end since, and by construction it cannot run on a real cluster (its
    "external" clients are containers on kind's docker network). The real-cluster
    coverage for the same paths is the dev4 hand-validation (an external OCI VM on
    the node VLAN — external-addresses.md §11). Two honest options: give a real
    test cluster a permanent off-cluster client, or run e2e.sh on kind in CI and
    accept its scope. Until one happens, the external ingress paths have no
    *automated* coverage (§8).

**Deferred by decision** — not gaps; recorded so they aren't re-litigated:
**BGP** (§3 — a CNI holds no routing sessions; attraction is the platform's job);
multi-tenancy **R3** (address-thinking — tenet 4 says identity, not addresses) and
**R8** (**dissolved** — in Cozystack a tenant *is* a namespace; where one spans
namespaces, `export` + `VPCBinding` already serves it, so cozyplane needs no
`Tenant` kind and learns tenancy from no platform —
[multitenancy.md](multitenancy.md)); the **stopped-VM address**
(multitenancy R1's one uncovered case — a persistent Port outlives its launcher, so
there is no pod to carry the annotation; the fix couples us to KubeVirt or costs a
projected read, so decide when a VM tenant asks); the CRD-storage shim (§7 — no
longer forced, now the built-in etcd is PVC-backed); `NodeFabric` (it would restate
`Node` and fix nothing); name-based addressing (§3 — judgement pending on what the
split-horizon resolver already gives).

---

## 1. Foundation & control plane

- [x] Object model: `VPC`, `Port`, `VPCBinding`, `VPCPeering`, `FloatingIP` (~~`ExternalPool`~~ — retired, [external-addresses.md](external-addresses.md) §9)
- [x] CRD-served API (prototype) with RBAC and validation
- [x] Aggregated apiserver (extension API) — built and served
- [x] Durable etcd (operator-managed, TLS/headless) with a built-in single-pod fallback
- [x] Default-deny VPC attachment: a `VPCBinding` authorizes use, the VPC's namespace is ownership
- Migration cutover adopts the Kube-OVN model (replaces the `/migrate`+`/bind` subresource idea — the only caller is our own controller, and Kube-OVN exposes no such API) — `live-migration.md`
  - [x] Stage 1 — cutover follows `VMI.status.nodeName` (phase-explicit, degrades to the pod label without KubeVirt; dev-cluster-validated with a real migration)
  - [x] Stage 2 — source→target forward during the migration window (`migrate_fwd` map + `from_overlay` re-encap; 15 s grace; closes the cross-node cutover gap; OVN's `requested-chassis=src,target`)
  - [x] Stage 3 — guest-announcement cutover: `AF_PACKET` listener on the staged target veth flips `spec.node` on the guest's gratuitous ARP / unsolicited NA (OVN's `activation-strategy=rarp`); VMI-watch is the fallback
- [ ] ~~Observability subresource(s) (e.g. `/ports`)~~ — **the motivation was multi-tenancy, and it is now recorded**: `Port` is cluster-scoped (the IPAM claim is atomic *because* the name is globally unique), so a tenant can never be granted a read on it. But the tenant-facing requirement it was meant to serve — "list the ports of my VPC" — is **dropped** on reflection: it is address-thinking, and tenet 4 says identity, not addresses. What a tenant actually could not do is learn **its own** address — and the CNI now stamps that on the pod (R1, built). See [multitenancy.md](multitenancy.md) R1/R3
- [x] **Multi-tenancy R1+R2: a tenant persona, and a tenant that can see itself** ([multitenancy.md](multitenancy.md); `test/tenant-e2e.sh` 19/19 dev-cluster). The CNI stamps a VPC pod with the address and MAC it allocated (`sdn.cozystack.io/vpc-ip` / `-mac`) — a tenant could not previously learn its own address AT ALL, because `status.podIP` is the *fabric* IP and the real identity lives only on the cluster-scoped `Port`. Aggregated `cozyplane-tenant-edit`/`-view` roles carry **only namespaced kinds**, so R2 holds structurally: a RoleBinding grants nothing cluster-scoped, and `list ports` is unreachable from a tenant role by construction. Removed a loaded gun — the sample `cozyplane-vpc-owner` granted `list ports` (cluster-scoped): inert under a RoleBinding, but one ClusterRoleBinding from handing every tenant the fleet's topology
- [x] **Multi-tenancy R5: the ceiling** — [multitenancy.md](multitenancy.md); `test/tenant-e2e.sh` 23/23 dev-cluster. Nothing bounded a tenant's consumption of VPCs (hence VNIs), pool addresses, ServiceVIPs or Ports, and `attach` is a **binary** grant: hold it, drain the pool. **The fix needed no new kind:** plain Kubernetes `ResourceQuota` with `count/vpcs.sdn.cozystack.io` etc. What was missing is that the kube-apiserver's quota admission cannot see an aggregated API's kinds — so cozyplane's apiserver enforces it via the quota **`Evaluator`** interface (an object-count evaluator per tenant-created kind, the stock ResourceQuota plugin in our admission chain, and a PluginInitializer supplying the Configuration, since the evaluators are necessarily ours). Usage is counted by LISTing through the loopback client, not a shared informer — staleness in a quota means over-admission, and creates here are rare enough to buy exactness at a price nobody pays. A tenant's fourth VPC is refused by the same machinery, with the same error, as its eleventh ConfigMap — and `status.used` reports observed usage, so it is a real quota rather than a gate. `Port`/`ServiceVIP` are deliberately not bounded: a tenant creates neither, and `count/pods` / `count/services` already bind them
- [x] Agent token rotation: the plugin kubeconfig references a host-visible tokenFile the agent refreshes as kubelet rotates the projected SA token (the embedded-once copy only worked via the API server's expired-token grace)
- [x] **Multi-tenancy model** — the API had no tenant in it; it does now (R1/R2/R5 above, [multitenancy.md](multitenancy.md)). **A namespace *is* the tenant** — cozyplane learns tenancy from no platform, and takes no Cozystack specifics. One case is open by choice, not oversight: the pinned address of a **stopped VM** (a persistent Port outlives its launcher pods, so no pod carries the annotation) — decide when a VM tenant asks

## 2. Datapath core

- [x] eBPF tc datapath: `from_pod` / `to_pod` / `from_overlay` / `from_uplink`
- [x] Geneve overlay delivery (collect-metadata, per-node device)
- [x] Per-pod dual-address bridge (fabric IP ↔ VPC IP), unique fabric IP per pod
- [x] Overlapping VPC CIDRs: net-scoped (VNI-keyed) delivery, no collision
- [x] eBPF bridge NAT for cozyplane north-south (VPC gateways, floating IPs) — no iptables, no fwmark, no policy routing
- [x] Cluster-egress masquerade: eBPF by default (`iptables`/`off` modes available)
- [x] North-south ICMP through the bridge: echo, and IPv4 ICMP *errors* with embedded-header NAT — port-unreachable/traceroute outward, frag-needed (PMTU) inward, fabric + floating (e2e: UDP traceroute end-to-end) — [#3](../../issues/3)
- [x] Per-VPC traffic counters in the datapath hooks (metering/billing foundation): a PERCPU `vpc_counters` map keyed by net, `count_dir` in `from_pod` (tx) and `to_pod` (rx east-west); the agent serves them as Prometheus text on `:9411/metrics` labeled by VPC (e2e-covered) — [#2](../../issues/2)
- [x] **North-south metering — every crossing, by the door it used** ([north-south.md](north-south.md) increment 0; closes #2's north-south half; dev-cluster-measured). `ns_packets[door][in]`/`ns_bytes[door][in]` on the same per-VPC counter, served as `cozyplane_vpc_ns_{bytes,packets}_total{...,door,direction}`. Until now the boundary was unaccounted: a tenant could pull terabytes out through a floating address or a LoadBalancer Service and cozyplane could not say it happened. The constraint that had blocked it: every door's *egress* leaves through `from_pod`, which hosts **no BPF-to-BPF callee** (its frame is ~496 of the 512-byte limit — the reason `count_dir` lives in `to_pod`), so `count_ns` is `__always_inline` on the narrow terminal paths only. Loads on 6.8 and 6.12. Also surfaced: an **in-cluster client never crosses the LB door** — socket-LB rewrites its `connect()` to the backend, so it takes the fabric bridge instead
- [x] Netfilter made conditional (#10): cluster-egress masquerade moved to eBPF (`--masquerade=bpf` default; ct-tracked SNAT at the uplink incl. ICMP echo + errors, e2e-proved with the kernel rule absent), and the FORWARD ACCEPT installs only where kube-proxy's `KUBE-FORWARD` exists — **cozyplane touches netfilter only if the cluster's kube-proxy does**. It cannot be removed entirely under an iptables kube-proxy: ClusterIP replies must traverse the client node's conntrack — [#10](../../issues/10)
- [ ] **Flow observability — per-flow events with verdicts and reasons** ([observability.md](observability.md), design accepted as increment 0 of its own plan): a `flow_events` ring buffer (the repo's first) + `flow_seen` LRU dedup, emission at the ~20 policy/routing drop sites (including the two isolation drops that are silent today, and the anti-spoof drop finally distinct from `sg_drops`) and per-flow allow verdicts at the `count_dir`/`count_ns` points; agent-side enrichment (VNI→VPC, address→pod via the responder's indexer pattern), raw `/flows` + `/flows/stream` on the node loopback (operator-only via `flowctl` exec), `cozyplane_flows_total{verdict,reason,direction,...}` plus `port_distribution`/`tcp_flags`/`icmp` distribution series on `:9411/metrics`, and DNS metrics from the resolver on `:9413`. Operator-only (R9); chart default off; kind-6.8 verifier is the gate. **Scope line held: no L7 HTTP/Kafka/Envoy — that is Cilium's `kubeovn-cilium` variant, which never coexists with cozyplane; only DNS is instrumented, from the resolver that already sees it**
- [x] **Cross-node node↔pod on a spoof-guarding underlay (OCI)** — the pod's *reply* to a hostNetwork client (pod→node) fell to the kernel and left the wire pod-sourced, which OCI anti-spoofing drops; every cross-node admission webhook hung, wedging cert-manager + ~60 HRs. Fix: a `node_remotes` map (node address → its Geneve endpoint) + `from_pod` encapsulates a default-network pod's traffic to a node over the overlay (gated to the pod-veth path so the uplink-egress hook doesn't re-encap Geneve outer frames); agent learns node addresses from InternalIPs + a `cozyplane.io/node-addresses` annotation (covers multi-NIC nodes where the host sources from a non-InternalIP NIC). Also `CFG_MASQ_IP`: the cluster-egress masquerade SNATs from the **default-route** address, not the InternalIP, so a masqueraded packet is valid for the NIC it egresses (fixed pod→internet on the dev cluster). dev-cluster-validated: full platform converges (90/90 HRs). Diagnosis in [bringup-field-notes.md](bringup-field-notes.md#5-admission-webhooks-fail-cross-node--podnode-reply-un-encapsulated-fixed)

## 3. VPC features — peering, egress, floating IPs

- [x] VPC peering: symmetric halves, native cross-VPC datapath, status controller
- [x] ~~Per-VPC egress NAT gateway (gateway-attach, per-VPC gateway pod)~~ — **superseded** by `VPCGateway` + eBPF VPC NAT (below). The pod survives only for a gateway family with **no assigned NAT address**, which has no identity to wear and so still launders into the node's address; retiring that path is open work (see the immediate roadmap)
- [x] Floating IPs: eBPF bridge extension (no gateway pod), true public IP both directions — closes [#5](../../issues/5) (which proposed gateway-anchored iptables NAT; shipped eBPF-native instead)
- [x] ~~Floating-IP advertisement in eBPF (`from_uplink` ARP/NDP responder)~~ — **deleted 2026-07-14** (north-south increment 3): cozyplane attracts nothing. Readiness is still gated on a live target Port; *delivery* survives and is what makes platform-side attraction work
- [x] Gate `VPCPeering` creation on a `peer` virtual verb on the local VPC — strategy-enforced in aggregated mode (which also closed the `export` gap there: admission never sees aggregated resources), VAP twin for CRD mode — [#1](../../issues/1)
- [x] **Floating-IP HA: attraction separated from delivery** — **[floating-ha.md](floating-ha.md)** (BUILT 2026-07-13; dev-cluster-validated with the decisive asymmetric triangle: address announced by node2, pod on node1, external client on node0 — three distinct nodes). Before, one node attracted (answered ARP), delivered (hosted the pod) and egressed, because all three were the same decision: the agent programmed the `floating` map only on the target Port's node, and `floating_arp` answered only when the pod was `local_of` — *"programming the map is the advertisement"*. The cost was not ops-comfort but correctness: a live-migrating VM's public address was re-pointed by exactly **one** unacknowledged, never-repeated gratuitous ARP, and losing it black-holed the address for an ARP-cache lifetime — on the feature whose whole promise is a sub-second cutover with the address preserved. It also made "sits on the pool's L2" an undeclared scheduling constraint on any floating-IP target
  - [x] Increment 0 — a robust announcement: `AnnounceAddress` sends a spaced burst (RFC 5227's shape) instead of one best-effort frame, and re-sends when a node newly *wins* an address. An unacknowledged protocol has repetition and nothing else
  - [x] Increment 1 — decouple: every node programs `floating`; a new `float_announce` map (present only on the elected announcer) is the sole ARP/NDP gate; `from_uplink` gained the remote arm it never had (`remote_of(fe->net, fe->vpc_ip)` → `encap`); `from_overlay`'s VPC branch gained a floating probe **before** the `gateways` lookup (a public inner dst otherwise **mis-delivers into the VPC's gateway pod** — not a drop); `to_pod` DNATs it unchanged (it keys on the destination, so it cannot tell an overlay-arrived floating packet from an uplink-arrived one); and the reply needed no code at all — the host already SNATs its egress to the public address out its own uplink, so replies go straight to the client (DSR), never via the announcer. Attraction is a rendezvous-hash election over the `Ready` nodes that can serve the pool's link (each publishes its own FIB answer as a node annotation) — no lease, no leader: `announcerFor` takes no "self", so agreement between agents is structural. A migration now makes no L2 claim at all. `cozyplane_floating_announced` exposes who attracts what. Verifier-gated on 6.8 (the encap fits `from_uplink` inline; no tail-call slot needed)
  - [x] ~~Increment 2 — BGP~~ **REJECTED 2026-07-13** (decision, not a deferral — see [north-south.md](north-south.md) §6). A CNI has no business holding routing sessions with the fabric. The practical tell came first: it cannot be validated on a real cluster at all (OCI gives compute instances no BGP peer — 179 closed on both gateways), so it would have been provable only against a synthetic FRR fabric on kind — and needing a fake fabric to believe your own feature is the design telling you the feature is in the wrong process. **The same reasoning retires the L2 announcement we already ship** (`float_announce`, `floating_arp`/`floating_ndp`, `AnnounceAddress`, the election): it is MetalLB-L2 reimplemented inside a CNI. Attraction belongs to the platform (CCM / MetalLB / a static route / an OCI secondary VNIC address); cozyplane consumes an address and *delivers* it — which is exactly what [lb-ingress.md](lb-ingress.md) already says for LoadBalancer IPs. **Increment 1's delivery decoupling is what makes that possible** (any node can now receive an external address and reach the pod), so it survives; the attraction layer it shipped alongside is what goes. `ExternalPool.spec.advertisement` (`L2 | BGP`, dead code) gets deleted rather than implemented
- [x] **A floating target takes exactly one address** — the reverse map (`floating_egress`) is keyed by the target's `{net, VPC IP}` alone, so a second FloatingIP on the same target overwrote the first's egress entry and the first address began replying *from the second* — its clients dropped the reply and the address went silently dead. Nothing in the datapath can detect that, so the controller refuses the later binding (oldest wins, `TargetExclusive=False` on the loser, no address allocated). Pre-dated the HA work; surfaced by its e2e — [floating-ha.md](floating-ha.md) §8
- [x] **`VPCGateway` — the VPC's declared north-south boundary** ([north-south.md](north-south.md) increment 1; dev-cluster-validated deny-then-admit: refused with no gateway, refused with a gateway that declines, delivered the moment it admits — the Service unchanged throughout). A kind, not a field: `VPC.spec.egress.natGateway` was a bool on an object the tenant owns, so **a tenant granted itself internet**. Creating a gateway needed the **`attach` verb on the referenced `ExternalPool`** then (the `export`/`peer` escalation-gate pattern); both retired with the pool — address governance is Service RBAC + the allocator's scoping ([external-addresses.md](external-addresses.md)). A VPC has exactly one boundary (oldest wins; `EffectiveGateway` lives in the API package because the controller, the CNI and the agent must agree on it without coordinating). **Tenet 7 is enforced:** `vpc_ingress[net]` gates `lb_ingress`, so a `Service type=LB` can no longer open a door into a tenant's VPC just by naming its pod as a backend — refusals counted in `ns_denied[door]`, kept out of the byte meter because a refused packet did not cross
- [x] **VPC NAT gateway in eBPF — a tenant egress identity** ([north-south.md](north-south.md) increment 2; dev-cluster-proven on the asymmetric triangle: SNAT on the pod's node, the address attracted by another, the client on a third). A VPC now leaves the cluster wearing **its own address**, drawn from its own pool — before, it was SNATed to the gateway pod's fabric IP and then re-SNATed by the cluster masquerade to the **node's**, so tenants were indistinguishable from the platform on the wire (tenet 8). The per-VPC **gateway pod is retired on the sanctioned path**: a gateway with a pool needs no pod, so no hairpin and no per-VPC SPOF. (It is *not* gone from the tree — a `nat.enabled` gateway with no `poolRef` still gets one, netns iptables and all, and still launders into the node's identity. Closing that is open work.) It could not simply be `masq_snat` with another address — that identifies a pod by its ADDRESS at the uplink, which is impossible for a VPC because tenant CIDRs overlap; the tenant is knowable only at the veth, which is what the gateway pod was really for. So the SNAT happens at the veth and the state lives on the pod's node, while the reply lands wherever the address is attracted — resolved by partitioning the port space per node (tenet 1 forbade the simpler "elect an egress node", which would have rebuilt the hairpin). `poolRef` and the `attach` verb carried the grant then; both retired with `ExternalPool` — the identity now rides owned delegated Services ([external-addresses.md](external-addresses.md))
- [x] **The announcement layer deleted; `FloatingIP` is an EIP under the gateway** ([north-south.md](north-south.md) increment 3). Cozyplane **attracts nothing** (tenet 3): `float_announce`, `floating_arp`/`floating_ndp`, `AnnounceAddress`, the announcer election, the pool-eligibility annotation, `--floating-ha` and `ExternalPool.spec.advertisement` are all gone — that was MetalLB's L2 mode reimplemented inside a CNI. Something else must attract (a CCM assigning the address to a VNIC, MetalLB, a static route, or an address configured on a node); **delivery does not care**, because `from_uplink` runs at tc ingress ahead of the kernel's routing decision, so whichever node the address lands on finds the pod through `floating`/`nat_of` and reaches it over the overlay. A FloatingIP briefly drew from its **VPC's gateway's pool**; with `ExternalPool` deleted it mints its own delegated Service and the LB implementation allocates ([external-addresses.md](external-addresses.md)) — every external address still crosses one counted boundary (tenet 2)
- [x] **Inbound MTU on encapsulated north-south and VPN paths** — a shared bounded TCP-option parser clamps oversized MSS on bare SYNs before FloatingIP, DSR, Geneve and VPN encapsulation. The generated object is kernel-verifier gated in CI; PMTU remains the non-TCP fallback — [floating-ha.md](floating-ha.md) §7
- [x] **A tenant appliance can be its VPC's door** (`VPCGateway.spec.appliance`) — the other half of the firewall story, and smaller than it looked. Off-VPC traffic is delivered to `gateways[vni]` **with its destination intact**, so whatever holds that entry already receives the VPC's egress and can route it; the entry is built from Ports carrying `spec.gateway`, and only `addGatewayLeg` could set it — agent namespace, reserved `.1`. Now the VPCGateway (already the VPC's one declared boundary) names the workload, the controller moves the flag onto that workload's Port **in this VPC**, and cozyplane runs no gateway pod alongside. No CNI change, no datapath change. Receiving is not sending: emitting a foreign source stays the `export`-gated `VPCBinding.allowForwarding` (docs/multi-attach.md). Dev-cluster-validated end to end — two VPCs, an appliance with a leg in each declared the door of both, ICMP at 0% loss and TCP gated by the source VPC's egress rule *and* the destination VPC's ingress rule
- [x] Site-to-site and roadwarrior VPN: scoped forwarder, per-VPC routes,
  managed WireGuard/IPsec, cert/EAP pools, live status/alerts, warm standby,
  KubeVirt live-migration form factor and active-active ECMP+BGP/BFD; managed
  multi-VPC hub via `VPNGateway.spec.additionalVPCRefs` (one leg, binding and
  route set per served VPC; disjointness enforced). External
  firewall/BGP and real migration exercises remain environment validation, not
  missing implementation — [vpn.md](vpn.md)
- [ ] Network policy / security groups within a VPC — **v1 + peered-group refs + north-south (world) done** ([security-groups.md](security-groups.md)): east-west group-to-group ingress, destination-side eBPF (`sg_members`/`sg_rules`, TCP SYN-gate, per-VPC id allocation, membership from stamped pod labels); **peered-VPC group refs** (`from: {group, vpc}`) authoritative via a Geneve identity TLV; **north-south `from: {cidr}`** (AWS-strict default-deny, kubelet exempt by NS_MARK path; all-addresses via SG_WORLD, specific ranges via an `sg_cidr` LPM); **east-west egress** (`egress: {to: {group, vpc}}`, symmetric default-deny, `sg_egress` mirror enforced beside ingress in to_pod + the TLV path); **north-south/external egress** (`egress: {to: {cidr}}`, source-side default-deny at `from_pod`'s gateway path via a loop-free `ns_egress_ok` + `sg_egress_cidr` LPM — plus the off-VPC-transit fix so the pod→gateway hop isn't re-gated as east-west, which had silently broken all grouped-pod TCP/UDP north-south egress) — all dev-cluster-validated. **label-follows membership DONE 2026-07-12** (live pod labels, not the claim-time snapshot; the snapshot survives as the fallback for a Port with no live pod, so a persistent VM Port holds membership steady between launchers — dev-cluster-validated: relabel a running pod out of its group and back). **v2 tail DONE 2026-07-13:** `from_pod` source-IP RPF (anti-spoof — a pod can no longer forge a co-VPC neighbour's address to borrow its groups; the fix closes it on every path, since the cross-node TLV's srcmap was itself computed from the spoofable source; dev-cluster-validated by delivery-capture), overlapping north-south CIDR union across groups ([#11](../../issues/11), compiler `unionContaining`, unit-tested), and floating-pod egress gating (`ns_egress_ok` now covers the floating path too). Still outstanding (lower priority): ICMP rules, peer-existence validation for peer refs, and a real connection table to replace the TCP SYN-gate (shared with NetworkPolicy and HostFirewall — solve once for all three, not three times). FQDN egress is **rejected** — a DNS-snooping engine is out of scope
- [ ] Per-VPC metadata endpoint + guest autoconfiguration — **design draft: [vm-provisioning.md](vm-provisioning.md)** (awaiting review; also closes #8)
- [x] Services in a VPC: per-VPC service VIPs + split-horizon DNS + net-scoped service NAT — **design: [services-in-vpc.md](services-in-vpc.md)** (reviewed; prioritized ahead of the KPR work)
  - [x] Increment 1 — split-horizon resolver: DNS steering in the datapath (`dns_steer`/`dns_return` + the `dns_ct` socket-LB coexistence twist), per-node responder, annotation-gated headless answers as VPC IPs, authoritative NXDOMAIN for the rest of the cluster domain, upstream forwarding (e2e-covered; validated on the dev cluster under Talos + Cilium KPR)
  - [x] Increment 2 — `ServiceVIP` + the net-scoped `svc_vips` data plane: controller-materialized VIP per attached Service (annotation + VPCBinding gate), live-union allocation walking opposite ends from the CNI, flow-pinned DNAT/rev-NAT with a hairpin loopback, resolver answers, peered clients included (e2e-covered)
  - [x] Hardening — cross-kind fail-closed at the aggregated registry (design layer 2): `Validate` pins the name to the claim (`v<vni>.<ip>` / `sv<vni>.<ip>`, canonical `spec.ip`, immutable on update), `BeginCreate` 409-rejects a create whose *twin name* exists under the other kind; the CNI's claim walk and the VIP controller treat the 409 as address-taken. CRD mode keeps layers 1+3
  - [x] Increment 3 — v6 guest autoconfiguration: userspace RA (M=1) + per-veth DHCPv6 server in the agent handing out the exact pinned `/128` (Linux ignores a /128 PIO — vm-provisioning.md Q2 answered empirically), closes [#8](../../issues/8) for addresses; the v6-VPC-on-v4-cluster *DNS transport* still waits on cross-family (e2e: RA route received + the stock DHCPv6 client leased the pinned address)
- [ ] Name-based addressing / system-view DNS re-point — judgement pending: demo act 7 (`demo/07-dns.sh`) shows what the split-horizon resolver already does; decide from there whether anything beyond it is wanted. (The old `control-plane.md` §5 pointer described the superseded /migrate-era system-view DNS.)
- [ ] **Far future — VPC as the cloud fabric for tenant Kubernetes**: a tenant cluster running on VMs inside a VPC will configure its own network, and "direct-to-pod" load balancing (the AWS-VPC-CNI / GCP-alias-range shape) would need tenant pod addresses to be first-class routable VPC addresses — e.g. per-Port delegated secondary ranges (the nested analogue of a podCIDR route) and LB provisioning that targets VPC addresses. No design, no priority; recorded so the shape isn't forgotten when tenant-k8s networking comes up

## 4. IPv6 / dual-stack

- [x] Re-key every map/helper/hook to 128-bit addresses (v4 stored in RFC 6052 NAT64 form)
- [x] Parse IPv6 and deliver v6 VPC traffic over the overlay (intra-VPC, cross-node, isolation, peering)
- [x] IPv6 north-south fabric bridge (v6 masquerade, v6 NAT)
- [x] Dual-stack default network; v6 fabric IPs from the node v6 pod CIDR
- [x] Fabric-IP family decoupled from VPC family — a v6 VPC runs on a v4-only cluster (validated on the dev cluster)
- [x] IPv6 guest autoconfiguration: userspace RA (M=1) + per-veth DHCPv6 handing out the pinned `/128` (services-in-vpc increment 3; closes [#8](../../issues/8) for addresses; the v6-VPC-on-v4-cluster DNS *transport* still waits on cross-family)
- [ ] Cross-family (v4↔v6 translation) — **design draft: [cross-family.md](cross-family.md)** — [#9](../../issues/9). Lower priority, do in time: the likelier first need is a **v4 VPC on a v6-first cluster**, not the v6-VPC-on-v4 direction the draft leads with
- [x] ICMPv6 errors through the v6 bridge: packet-too-big (v6 PMTU — vital, v6 never fragments in flight), dest-unreach, time-exceeded, with embedded-header NAT (e2e: UDP traceroute6 end-to-end)
- [x] v6 floating IPs: stateless v6 DNAT/SNAT halves incl. ICMPv6 error rewrites (e2e: external HTTP/ping6/EIP-egress/traceroute6). The **NDP responder** that shipped with them (solicited+override NA from `from_uplink`) was **deleted 2026-07-14** — cozyplane attracts nothing; the platform arranges attraction and `from_uplink` delivers whatever lands
- [x] v6 gateway egress: dual-family gateway leg (`.1` in either family, `fe80::1` hop, NODAD), dual-family gateway netns firewall (with NDP accepts — ip6tables sees NDP, unlike ARP), and the v6 node masquerade (`masq_snat6`/`masq_reverse6`) that gives pod ULAs an off-cluster return path (e2e: v6 VPC → gateway → external container; isolation held). Superseded for pool-backed gateways by the eBPF VPC NAT (§3); it remains the pool-less path
- [ ] Cross-family VPC peering (v4 ↔ v6 via a NAT64/SIIT translator) — **design draft: [cross-family.md](cross-family.md)** (low priority, after #9)

## 5. Live migration (KubeVirt)

- [x] Persistent Port pins `{VPC IP, MAC}` to a VM NIC identity (`vm.kubevirt.io/name`)
- [x] CNI binds virt-launcher pods to the persistent Port (reuse IP, pin a stable `02:` MAC)
- [x] DEL preserves the persistent Port; local datapath state cleared by `(net, IP)`
- [x] Cutover controller re-points `spec.node` to the active launcher (`kubevirt.io/nodeName`)
- [x] GC the persistent Port when the VM's pods are all gone
- [x] IP + MAC preservation validated end-to-end on the dev cluster (both directions)
- [x] IPv6 VM live migration demonstrated on a v4-only cluster (IP+MAC preserved, sub-second cutover)
- [x] Staged locals: same-node delivery flips at cutover on both ends (target's entry gated on `spec.node`, programmed from the veth alias at cutover; source's removed symmetrically) — validated on the dev cluster with a bandwidth-throttled migration: target locals observed ABSENT mid-window, flip at cutover, gap patterns identical across observers (no path-asymmetric loss), IP+MAC preserved through two consecutive migrations
- [x] ~~Gratuitous ARP / unsolicited NA when a floating IP is programmed locally~~ — **deleted 2026-07-14** with the announcement layer (north-south increment 3). A migration now makes **no L2 claim at all**: every node can deliver a floating address, so a node move needs no cache flush and there is no unacknowledged frame to lose. (The *migration* GARP **listener** — stage 3's cutover trigger, `garp_listen` — is a different mechanism and survives: it hears the guest's announcement, it does not make one)
- [ ] VM-migration e2e test (cozystack has none)

## 6. Services (kube-proxy replacement)

**cozyplane owns Services.** The dev cluster runs `cozyplane-kpr` as its *only*
service proxy — kube-proxy and Cilium are both gone (verified 2026-07-10: no
`kube-proxy` DaemonSet, no Cilium install; `cozyplane-kpr` 3/3). With no
kube-proxy there is no `KUBE-FORWARD` chain, so `firewall.go`'s conditional
install installs nothing — [#10](../../issues/10)'s endgame.

- [x] Import Cilium's LB control plane + socket LB (`pkg/loadbalancer`, `pkg/socketlb`, pre-compiled `bpf_sock.o`) as the separate `cozyplane-kpr` component — **design: [kube-proxy-replacement.md](kube-proxy-replacement.md)**: lbcell reconciles Services→pinned LB maps, committed `bpf_sock.o` at the cgroup root; proven on a `kubeProxyMode: none` kind cluster (`test/kpr-e2e.sh`: TCP + UDP ClusterIP + cluster DNS with no other proxy present); `svc_vips` feed made event-scoped (workqueue + owned-keys index, no full-map rebuilds); deployed as the sole service proxy on the dev cluster
- [x] Per-packet ClusterIP fallback for clients socket-LB can't reach (VM guests / raw sockets, net 0): `svc_forward`/`svc_return` un-gated for net 0, fed by the kpr reconciler into the same pinned `svc_vips` — dev-cluster-validated with a raw, socket-LB-bypassing TCP SYN to a ClusterIP
- [x] Retire kube-proxy — done on the dev cluster (removed together with Cilium); `firewall.go` installs nothing there
- [x] **LoadBalancer ingress + external NodePort** — **[lb-ingress.md](lb-ingress.md)**: *delivery only* — cozyplane consumes `status.loadBalancer.ingress` (whoever wrote it: CCM, MetalLB, a human), honours `ipMode`, and DNATs at `from_uplink` (a tail-called program) to node-local ready backends with the client source preserved (`externalTrafficPolicy: Local`; allocation/announcement/provisioning are the LB implementation's job). Both families; VPC-pod backends via a `bridges` hop (no client masquerade, SG-gated at the DNAT point); `loadBalancerSourceRanges` as an `lb_src` LPM; NodePort = the same rows keyed by node addresses. **`etp: Cluster` via DSR** (strictly opt-in: `CLUSTER_DSR=true` on kpr — the fleet-wide LB-IP spoof permission it needs is an underlay property; ungated, Cluster degrades to node-local delivery) — remote backends reached by Geneve-encap with the frontend identity in an option; the reply exits the backend's own node *as the LB IP*, so the client source is preserved in every mode (the agent serves the link carrying every LB ingress address on every node for this). e2e-covered (incl. source-preservation, the kube-proxy-counter-flat proof, and Cluster delivery via a backend-less node) + dev-cluster-validated (MetalLB composition; the asymmetric client/announcer/backend triangle over the OCI VLAN) — [#13](../../issues/13)
- [x] **Default-network `NetworkPolicy`** — the production blocker Cilium's removal left open. **Decision 2026-07-11: build native; the Cilium-policy-only spike is dropped.** Design: **[network-policy.md](network-policy.md)** — upstream `networking.k8s.io/v1 NetworkPolicy` consumed as-is, **kept a distinct kind from `SecurityGroup`** (tenant/system RBAC separation; VPC pods aren't clean siblings of net-0 pods); same enforcement *shape* as SG (destination-side in `to_pod`, SYN-gate) but net-0 twin maps with coordination-free 64-bit label-hash identities, label-follows from day one
  - [x] Increment 1 — ingress with pod/namespace selector peers: identity compiler in the agent, `np_ident`/`np_allow`/`np_nodes`, `to_pod` net-0 gate (noinline + per-CPU scratch), stateful UDP via the `np_ct` reply-pin written at `from_pod`, kubelet/node exemption, churn-label filtering, fail-closed unserved constructs. e2e 128/128 incl. label-follows both ways, v6, probes-stay-Ready, isolated-pod DNS
  - [x] Increment 2 — `ipBlock` (+`except` as longer deny prefixes in the `np_cidr` LPM), egress enforcement (pod-to-pod at the destination's `to_pod`, identity-less destinations inline at `from_pod`; node-destined egress exempt by design). e2e 138/138 incl. ipBlock-through-LB with the source preserved, egress DNS rule, external-cidr egress; dev-cluster-validated live. Verifier lesson recorded: sibling callees not nested ones near the 512B cliff, zero bpf-to-bpf calls in `from_pod`
  - [x] Increment 4 — **entity peers** (`policy.cozyplane.io/entity: nodes | local-pods | local-node` as a reserved namespaceSelector label — in-schema, so a policy stays portable and fails closed elsewhere): the vocabulary upstream lacks. The node exemption **narrowed to the LOCAL node** (`np_nodes` carries a locality bit) — remote-node origin (apiserver→webhook) is now gated and readmitted with the `nodes` entity, shrinking the address-minting surface from "any node address" to "this node's own" ([policy-layers.md](policy-layers.md) § trust model). `local-pods` admits co-scheduled net-0 pods (author-declared placement dependence — tenet 6 forbids *enforcement* from silently inferring co-location, not the author from naming it); it is also an egress `to` peer, while `nodes`/`local-node` in egress are refused (node-destined egress is HostFirewall's contract)
  - [x] Increment 3 — `endPort` via the `np_allow` port-suffix LPM (ranges = O(log) prefixes, hot path CHEAPER: one LPM probe per peer id); **cyclonus conformance 89/90 on the dev cluster** (every tag family 100%; the single miss is a named-port-in-disguise `update-policy` case — named ports are a documented fail-closed non-goal); compile scale ~5.9ms per full recompute at 5k pods / 200 policies. `test/cyclonus.sh` is the rerunnable harness (pod-ip destinations, TCP/UDP servers — see the doc's harness notes)
- [x] **Host firewall** — the node-scoped sibling of default-net NetworkPolicy — **[host-firewall.md](host-firewall.md)**: cluster-scoped, operator-only `HostFirewall` (tenants get no access — the third policy layer beside NetworkPolicy/net-0 and SecurityGroup/VPC) makes selected nodes host-ingress default-deny with cidr/except + port/endPort allow rules. Enforcement is one tail-called `hf_ingress` program (lb_prog slot 2) reached from every fall-through that hands a packet to the host stack, armed per node by `CFG_HF_ENABLED`; node sources, ICMP, the Geneve transport, and established TCP are never gated, and node-originated UDP returns via `hf_ct` reply-pins written at the three egress crossings. The e2e caught two real holes before they shipped: `from_uplink`'s v6 exit bypassed the gate, and the cluster-egress masquerade *laundered* v6 pod→node flows into the node exemption (fix: `node_remotes` is dual-family now, so v6 pod→node rides the overlay like v4 — also closing the latent v6 twin of the OCI anti-spoofing gap). e2e 160/160; dev-cluster-validated live (a control-plane node isolated behind the LB: pod→node scrapes dropped and counted, node Ready, kubectl/etcd/DNS pins unharmed, per-CIDR reopen, clean delete)
- [x] **Host firewall egress** (increment 2) — `policyTypes: [Egress]` makes a node's OWN new TCP/UDP flows default-deny, opened by `egress: to: [{cidr, except}]` rules: node→external is gated in `hf_ingress`'s node-originated arm, node→remote-pod (the one node-origin path that never reaches a host-stack fall-through) via a new tail-called `hf_egress` at `from_pod`'s remotes-hit encap. **node→node and node→local-pod stay structurally exempt** — kubelet↔apiserver, etcd, the agent's own API access, and kubelet probes ride them, so egress isolation cannot self-lock-out. `hf_ct` pins are written on both admitted directions, so each direction's reply passes the other's gate. Directions arm independently (an Egress-only object leaves ingress open) — [host-firewall.md](host-firewall.md)
- [x] **`spec.externalIPs`** — [lb-ingress.md](lb-ingress.md) § `spec.externalIPs` (2026-09-22). kpr wrote rows for ClusterIPs, LB-ingress IPs and NodePorts but never read `spec.externalIPs`, so an address published that way answered nothing — and that is Cozystack's *stock* host-ingress publishing on clouds whose routable address is not a Kubernetes node address, which made every public hostname refuse connections on 443 while the same node served 6443. kube-proxy and Cilium both implement it; kpr replaces them, so it must too. Handled like LB-ingress IPs (same backend selection — a remote backend without DSR would reply with the wrong source) except that any Service type may carry them, the frontend is the service port, and `loadBalancerSourceRanges` does not apply. The agent ensures a floating uplink for them too, so an externalIP landing on a secondary NIC is intercepted like an LB address
- [ ] **kpr gets its node name from the chart** (code landed, awaiting a retest on the stand) — [bringup-field-notes.md](bringup-field-notes.md) §11 (FIXED 2026-09-23, stand-diagnosed). `chart/cozyplane-kpr` never set `NODE_NAME`, so every chart-based deployment ran kpr unable to tell which endpoints were node-local: no LoadBalancer-ingress, NodePort or `spec.externalIPs` row was ever written, on any node. ClusterIP rows come from the cluster-wide backend set and were unaffected, which is why kpr looked healthy and three unrelated fixes were aimed at the symptom first. Confirmed on the stand: 117 `svc_vips` rows, none for any published external address. `CLUSTER_DSR` is now a chart value too, and kpr falls back to the hostname rather than silently serving nothing. Verified by rendering the chart; **no post-fix observation on the stand yet** — the interim ingress proxy was left running, so nothing was retested there
- [x] **An LB reply leaves by the link its request arrived on** — [lb-ingress.md](lb-ingress.md) § "The reply leaves by the link the request arrived on" (2026-09-24). `lb_return` egressed via `cfg(CFG_FLOAT_IFINDEX)` — one link for the whole node — so on a node carrying external addresses on two links the replies for one of them left the wrong segment with a source that link cannot source, and the fabric dropped them: a hang, not a refusal, which is why it read as "not intercepted". Measured on the integrations stand (node0): `CFG_UPLINK_IFINDEX=8` (eth0, carrying the published `10.20.0.16/24`) but `CFG_FLOAT_IFINDEX=9` (eth1, the MetalLB VLAN) with `CFG_FLOAT_NH=10.20.100.1`. The arrival link is now recorded per flow in `svc_rev_val.ifindex` from `skb->ingress_ifindex` at the DNAT, and `CFG_FLOAT_NH` applies only when the reply actually leaves the floating link. Map-ABI change (value 20 → 24 bytes), so the pinned `svc_rev` is recreated on agent load. DSR flows arrive over the overlay and keep the node-wide slot. **Behaviourally proven** by `test/two-link-e2e.sh`, which attaches a second docker network to a kind node, publishes one external address on each link and requires both to be served. It discriminates: against the pre-change selection the second link's address still works while the default uplink's times out — the same one-of-two asymmetry that made this read as "never intercepted" in the field
  - [ ] Floating-IP and VPC-NAT egress pick their link per address — **[lb-ingress.md](lb-ingress.md) § "The egress link is a property of the address"**: an `ext_links` LPM trie keyed by the external address (a host prefix per address, plus each link's subnet, so a routed pool delivered via a secondary link resolves too), replacing the node-wide `CFG_FLOAT_*` cells at the two v4 egress sites, with `lb_return` falling back to it so DSR flows get a correct link for the first time, and stale entries pruned on each bind because an LPM entry outranks the fallback rather than sitting inert. **v4 only**: `EnsureFloatingUplink` returns early for a v6 address, so nothing writes a v6 entry and the v6 twins still follow the node-wide cell — per-address v6 needs v6 floating-uplink selection, which does not exist. Verifier-validated on kind, unit-tested at the key, prune and value seams, and `test/two-link-e2e.sh` asserts on a real two-link node that an address on the secondary link maps to that link, host key included, **and that a second address on the same link does too** — the case a per-node write path drops. **The four egress sites themselves are still not exercised by a packet**: they are pod-originated paths (a floating IP, a VPC NAT identity), so covering them needs a FloatingIP and a VPC in the fixture
- [ ] **Node-owned external addresses** (code landed, awaiting real-hardware validation) — [lb-ingress.md](lb-ingress.md) § "Node-owned external addresses" (2026-09-23). An external address that is one of the node's *own* was accepted by kpr but never delivered: the agent read the FIB's answer for it as "the link that carries this address", and for an owned address that answer is `local … dev lo` — so it bound the floating machinery to the loopback, which has no MAC, refused, and the packet fell through to the host stack and got an RST. That is the ordinary shape on clouds that NAT a public address onto the instance's primary private one (OCI, GCP, AWS), i.e. not exotic. The missing MAC was a *symptom*, not the gap: every real NIC has one. Two questions are now kept apart — which link the address **arrives** on (for an owned address, the link it is configured on, found by address lookup, since the FIB cannot answer it) and whether the kernel can resolve an **off-subnet** reply out of that link (only a default route can; any other needs `CFG_FLOAT_NH`). The common cloud case therefore programs nothing at all: the address arrives where `from_uplink` already is. No new hook behaviour was needed, and the loopback is now structurally unreachable as a binding target. **Unit-tested taxonomy; not yet exercised on a real cloud node, so the box stays unticked** (CLAUDE.md: tick it when it truly works).
  - [ ] (Open) The floating maps are single-cell — one non-default uplink per node — so a node with two claimants re-binds the slot on every resync rather than settling, leaving both reply paths nondeterministic and `from_uplink` attached to the loser — superseded for v4 by the per-address selection below, which gives each link its own entry, so what remains is the v6 egress path and the cell's own churn (logged per re-bind). Pre-existing (two floating VLANs contend identically); closing it means a per-ifindex map shape
  - [ ] (Open) `uplink_mac` and `float_uplink_mac` are vestigial — nothing has read them since the in-datapath ARP responder was removed. Still written so the pinned maps keep their shape; dropping a `PIN_BY_NAME` map strands a pin on every upgraded node, so it needs its own change
- [ ] **Node-origin path-trust** — replace the address-keyed node exemptions (`np_nodes`/`hf_self`/`NS_MARK`-absence) with channel provenance (host→veth same-node, `node_remotes` overlay cross-node, TLV-authenticatable like SG stage B): makes the masquerade-laundering class structurally impossible. First cheap step: per-layer `*_node_exempt_total` counters so the exemption is visible even while it is address-keyed — [policy-layers.md](policy-layers.md) § trust model
- [ ] **NP egress vs VPC-pod fabric IPs** — decision pending: an NP-egress-isolated net-0 pod dialing a VPC pod's fabric IP is gated only by the destination SG, not the client's own egress rules (the deferred destination-side gate never runs on the sanctioned north-south path). Either drop VPC pods from `np_ident` (fabric IPs become `ipBlock` territory) or document as intended — [policy-layers.md](policy-layers.md)

## 7. Deployment robustness

- [x] Cozystack chart integration (aggregated-apiserver mode, operator etcd, RBAC/CRDs)
- [x] **Two API groups: `local.sdn.cozystack.io` (CRDs) + `sdn.cozystack.io` (aggregated)** — **[api-groups.md](api-groups.md)** (BUILT 2026-07-12; dev-cluster-validated: `/openapi/v2` serves and `kubectl apply` of a cozyplane object works with client-side validation ON — the operation that was broken). Forced by a real bug: a CRD keeps publishing OpenAPI paths after an APIService takes its group over, the specs collide (`duplicated path .../vpcs/{name}`), the group's schema never serves, and `kubectl apply` of every cozyplane object fails client-side with "failed to download openapi" while core types keep working — latent since the chart split. Structural fix, not policed: disjoint kinds ⇒ disjoint paths ⇒ the collision cannot occur, and the takeover machinery is deleted rather than fixed. `local.` (not `fabric.`) because the group is *everything CRDs serve for us* — today the local layer, and possibly the storage substrate under the extension API if the **CRD-storage shim** (which would drop the etcd dependency) lands
  - [x] Increment 1 — `FabricIP`: fabric IPAM becomes an API claim (name = the address, atomic by name-uniqueness) with pod-UID-keyed GC, replacing the `host-local` file store — whose on-disk reservations are released only by a CNI DEL, so a pod that vanishes while kubelet is down leaks its address across the reboot, and a node's range eventually fills with ghosts ("no IP addresses available in range set"). `Port` already had this GC; the fabric side never had an object to reap
  - [x] Increment 2 (as built: the FLAT pool) — allocation moved to the cluster-wide supernet, `remotes` keyed per pod at net 0 (sized 131072: pods, not nodes), `nodeCIDRFor` and every read of `Node.spec.podCIDR` deleted. A node can no longer exhaust while the cluster has room, and a pod's underlay address is no longer tied to where it landed. kind-validated (cross-node v4+v6, DNS); dev-cluster-validated (a full 3-node reboot; every pod re-claimed, addresses spread across the /16)
  - [x] Increment 3 — tenant kinds go aggregated-only: their CRDs leave `chart/cozyplane`, the takeover machinery is deleted, clients resolve the extension group by discovery
  - [x] Increment 4 — `Port.spec.fabricIP` **normalized away** (no `fabricRef` either — a reference whose value *is* the address re-creates the stale-copy bug). The address lives only in `FabricIP`; `Port` and `FabricIP` both point at the pod, and the agent joins them on pod UID to feed the `bridges` map
  - [ ] (Open) CRD-storage shim for the extension registry — its own design. Its motivation was dropping the etcd dependency; with storage classes available and the built-in etcd now defaulting to a **PVC** (2026-07-13), that dependency is durable rather than painful, so the shim is no longer forced. Revisit if etcd's operational cost bites again
  - Interim for pre-split clusters: `--remove-bootstrap-crds` (default on) cleans the old single-group CRDs
- [x] Chart split: `chart/cozyplane` (CNI; serves the group as **bootstrap CRDs**, no cert-manager) + `chart/cozyplane-apiserver` (apiserver + etcd + certs; in Cozystack a separate component that `dependsOn` cert-manager, whose APIService atomically takes over the group from the CRDs) — closes field-note #1's deferred fix; [control-plane.md](control-plane.md) §0
- [x] Image digest-pinning in the chart
- [x] **The agent is quiet during that same window** (2026-09-22). Its eight `sdn.cozystack.io` informers each logged a reflector error every few seconds while the group was absent (`failed to list *v1alpha1.VPCGateway: the server could not find the requested resource`, and so on per kind) — a per-kind error stream through exactly the window an operator is reading the agent's logs to diagnose something else. They now sit behind the same `internal/apigate` discovery gate the controller uses, so an absent optional group is one line rather than a stream. What the informers do once the group exists is unchanged, and the gate is deliberately non-blocking: nothing in pod ADD may wait on this group (`cmd/agent/sdngate_test.go` asserts it, and the CNI plugin is a separate process holding no informer)
- [x] **The aggregated APIService is maintained, not asserted once** — [control-plane.md](control-plane.md) §0 (FIXED 2026-09-22, field-diagnosed). The apiserver registered its `APIService` in a post-start hook and never looked again. On an in-place switch to the cozyplane networking variant it registered first and took the object over; the previous owner's Helm release was then upgraded with the APIService no longer in its manifest, so Helm deleted it. The whole aggregated group vanished — every agent's informers and the sdn controllers lost their kinds — and nothing brought it back, because registration only ever happened at boot; recovery was a manual pod restart. Registration is now reconciled on a 30s resync for as long as the server serves the group, and a recreation is logged loudly because it means something outside this server deleted its own group's registration. The first pass is still blocking, so a server that cannot register fails at startup as before. (The other half is Cozystack's: hand the object over on the variant switch rather than deleting it)
- [x] **Controller survives — and works during — the CNI-first bootstrap window** — [control-plane.md](control-plane.md) §0a (BUILT 2026-08-25). The CNI installs before cert-manager, etcd and storage, so cozyplane's own aggregated apiserver necessarily lands later, and `sdn.cozystack.io` is absent on every fresh install for minutes. The controller used to crashloop through that window: controller-runtime treats an unresolvable kind as fatal, so `source.Kind` spun on `no matches for kind "VPC"`, the cache sync timed out, the manager exited — taking down the FabricIP GC, which needs nothing but the kube API and is most needed precisely while the platform installs. Now one process runs in two states: the ungated controllers start unconditionally and the pod is Ready, while a discovery gate (`internal/apigate`, 15s poll) registers the `sdn.cozystack.io` controllers on the *running* manager the moment the group answers — no restart, no second Deployment, and no change on a cluster that serves the group from the start. The group later disappearing is logged, not fatal
- [x] **An agent rollout no longer splits the datapath** — [bringup-field-notes.md](bringup-field-notes.md) §9 (FIXED 2026-08-25, dev4-diagnosed). tcx is a program list, and on kernel 6.18 removing a link's pin does **not** detach it, so every agent restart left the previous generation attached *ahead* of the new one, reading map objects nothing updated any more: pods predating the rollout became unreachable from remote pods, pods created after it unreachable from any node, same-node fine throughout — which stalled the platform install at the cert-manager webhook. The agent now adopts the link already at each hook and swaps its program in place, detaches extras, and heals an already-split node on rollout. Fell out of the same incident: program pins are swapped atomically (the re-pin gap failed ~250 sandbox creations), and a failed `releaseFabricIPs` is folded into the ADD error instead of being discarded — every failed ADD had been leaking its address silently, 100 for one pod, because the release 403'd on `deletecollection`, a verb the plugin's SA was never granted (the SA now holds it; see [bringup-field-notes.md](bringup-field-notes.md) §9)
- [x] **kpr no longer shadows the agent's pins on Talos** — [bringup-field-notes.md](bringup-field-notes.md) §10 (FIXED 2026-09-22). kpr's bpffs init container guarded its mount by grepping for the mount's *source* name `bpf`; Talos names its host bpffs `none`, so the guard mounted a second, empty bpffs over the real one and — under `mountPropagation: Bidirectional` — propagated it to the host, hiding every program/map/link the agent had pinned under `/sys/fs/bpf/cozyplane`. Every pod ADD then failed `open pinned from_pod program: no such file or directory`, cluster-wide (739 sandbox failures across 3 nodes), and the aggregated apiserver never started because its own pods could not get a sandbox. The init container is gone from both the chart and `deploy/`; kpr ensures bpffs in-process (`kpr/bpffs.go`), `statfs`-checking the mount **point** for `BPF_FS_MAGIC` as the agent already does — a source name cannot fool it. **Constraint to keep: never identify a mount by its source name**, and kind cannot reproduce this (its bpffs is conventionally named), so the mount decision is Talos-validated
- [x] Flat pool: the agent no longer requires `Node.spec.podCIDR` — the gate outlived the field it guarded, and on a cluster without node-ipam it emptied `node_remotes` and black-holed every cross-node flow (kind always assigns podCIDRs, so no e2e could see it)
- [x] Agent recreates incompatible pinned eBPF maps on load and rebuilds pod state from veth alias records — a map-ABI upgrade is a rolling DaemonSet update, no node reboots (e2e-covered) — [#7](../../issues/7)
- [x] Gateway `.1` Port reuse after an unclean death: the controller GCs live Ports whose claimant pod is gone (VM persistent Ports exempt), so the replacement's ADD retry claims the freed `.1` (e2e-covered)
- [x] Digest-reproducible release images: attestations off, SOURCE_DATE_EPOCH + rewrite-timestamp, digest-pinned bases — verified identical across CI reruns, and the pin-commit-rebuild loop converges — [#4](../../issues/4)
- [x] **This repo is a Cozystack package source** — all four charts under `chart/` (`cozyplane`, `cozyplane-kpr`, `cozyplane-apiserver`, `cozyplane-cilium-crds`, the last two ported in from the `cozystack/cozystack` fork branch) plus ready-to-apply `PackageSource` manifests in `packages/packagesources/`. A cluster consumes them straight from git via a Flux `GitRepository` — no OCI artifact build, no vendoring into the cozystack tree, and moving to a new build is a `ref.commit` change on one object. Two PackageSources because the CNI installs before everything and the aggregated apiserver must follow cert-manager + etcd-operator + storage. All four are library-free (no `cozy-lib`) and CI renders each standalone — [packaging.md](packaging.md)
  - [x] CI for the `ghcr.io/lllamnyp/cozyplane-kpr` image (2026-09-22): a from-source multi-stage `kpr/Dockerfile` plus a `kpr-image` job in `release.yml`, on the same triggers as the cozyplane image and with the same reproducibility measures — so the pin is refreshed from a job summary rather than by hand, and **arm64 clusters can run kpr**. Cilium's ~394-module tree was never the real blocker: nothing is emulated (builder pinned to `$BUILDPLATFORM`, cross-compiled via `GOARCH`, no `RUN` in the target-platform stage) and the embedded `bpf_sock.o` is architecture-neutral `--target=bpf` bytecode. `kpr/` is a separate module, so the root `go vet`/`go test` never reached it either; it now has its own `ci.yml` job, which is what runs its unit tests and the arm64 cross-compile check

## 8. CI & testing

- [x] CI: unit tests, lint, build-drift, image release, datapath e2e
- [x] **Cluster-agnostic suites** — `test/policy-e2e.sh` (NetworkPolicy incl. entities, HostFirewall ingress+egress, SecurityGroup label-follows), `test/vpc-e2e.sh` (VPC attach with Port/FabricIP as separate objects, east-west, isolation, **overlapping CIDRs proven by identity** — the same address resolves to a different pod in each VPC, the dual-address bridge, peering, split-horizon DNS, SG, revocation, the VPCGateway boundary and the EIP egress identity) and `test/tenant-e2e.sh` (the tenant persona: R1's self-view, R2's structural blindness, R5's ceiling). All take `KCTX=` and run on a real cluster
- [ ] **`test/e2e.sh` fails on its own install order** — it applies the aggregated apiserver and blocks on its rollout *before* installing the agent, so with no CNI the nodes never go Ready, the apiserver pod stays `Pending` and the wait times out (`error: timed out waiting for the condition`). The `e2e` workflow is red on `main` for this reason, so the suite is **failing, not merely unrun** (it was recorded here as the latter), and whatever else rotted since the API-group split is hidden behind it. Still true otherwise: its floating-IP phases were rewritten to the delegated-Service model (the suite plays the allocator by patching the owned Service's LB ingress, and the attractor by configuring the address on a node), no `ExternalPool` reference remains anywhere in `test/`, and it is kind-only by construction (its "external" clients are containers on kind's docker network). It is the **only** automated coverage for external floating-IP and LoadBalancer ingress — real-cluster coverage for those paths is the dev4 hand-validation (external-addresses.md §11). Item 14 above states the two honest options
- [ ] **A verifier-complexity budget, measured** — nothing tracks how much of the verifier's 1M state ceiling each program spends, so the datapath drifts toward it invisibly and fails on whichever kernel explores hardest. It has happened twice: `count_dir` on 6.12, and `from_pod` on 6.18 at 100% of budget for two months until a 0.18% commit tipped it ([bringup-field-notes.md](bringup-field-notes.md) §12, now 3.4% after flattening `addr128_eq`). Loading each program with `LogLevel: ebpf.LogLevelStats` and reading `processed N insns` off the successful load makes it a number. The catch: CI and kind run a kernel (6.8) that costs ~half what 6.18 does, so the gate can only be a **relative** guard — a ratchet against the committed numbers, which still catches a 14x regression — and an absolute budget needs a run on the newest kernel targeted
- [x] eBPF bindings check (static bpftool, libbpf-dev)
- [x] Cross-compiled release image
- [x] e2e coverage for the IPv6 north-south paths (cross-node pinned — this caught the missing ip6tables FORWARD ACCEPT)
- [ ] e2e coverage for live migration (needs KubeVirt; kind can't host it)

---

## Open issues index

- [ ] Managed-boundary DNS after socket LB: the Talos CRD recipe reproduced
  a query translated from the cluster DNS Service IP to its internal backend
  being dropped before split-horizon steering. Align the boundary exception
  with that steering predicate. Regression tests reproduce the old drop in both
  families; real Talos kernel packet tests now verify TCP/UDP rewriting and
  denial of other management/peer/external traffic. The rebuilt networking image
  was published, pulled and exercised on all three Talos nodes: UDP/TCP DNS and
  IPv4/IPv6 ServiceVIP pass. Merge remains pending.

- [ ] Guest IPv6 configuration through the managed boundary: narrowly allow
  local RS and DHCPv6 before a guest has its assigned VPC source. Old-object
  packet tests reproduce the drop; the regenerated object passes malformed
  packet and data-traffic denials on Talos. Actual DHCPv6 assigns the pinned
  address and IPv4/IPv6 migration passes with 60/60 replies per family.
  Source `8146dce` is published and running on the lab; merge remains pending.

- [ ] Registry pull eligibility for the CRD lab image: the Debian 13 runtime
  updates remove the observed CRITICAL findings, but unfixed HIGH findings
  still need review against the destination registry's policy. A green scan
  limited to fixable HIGH/CRITICAL findings is insufficient. The actual private
  registry accepted the final image under its operator-selected Critical policy,
  with no added CVE exception, and the three lab nodes pulled it. The full amd64
  scan reports 0 CRITICAL and 50 HIGH occurrences (13 distinct unfixed CVEs).
  Distribution review and production activation remain pending; see
  [packaging.md](packaging.md).
- [ ] Hardened active-active VPN routing: packaged FRR's privilege setup asks
  for `SYS_ADMIN`, which the hardened appliance profile deliberately excludes.
  Reproduced with both the previous Debian 12 image and Debian 13; do not add
  that capability to certify the profile. Adapt FRR startup within the existing
  capability boundary and verify the actual routing wrapper before certifying
  this optional profile.

- [x] Migration listener resource regression (B195): idle receive spin replaced
  with bounded readiness polling; completed child contexts released; cancellation
  and replacement ownership tested. Boundary notifications coalesced with bounded
  ACK contexts; identical map and status writes skipped while drift repair remains.
  Kernel, unit and race tests pass; corrective v4 image runs on the three lab agents.
  This does not certify absence of every production leak or close the VM recipe.

| # | Title | Area |
|---|-------|------|
| [#1](../../issues/1) | Gate `VPCPeering` creation on a `peer` virtual verb | Peering / RBAC |
| [#2](../../issues/2) | Per-VPC traffic counters in the datapath hooks | Datapath / metering |
| [#3](../../issues/3) | ICMP to a VPC pod's fabric IP is dropped (north-south ping / PMTU) | Datapath |
| [#4](../../issues/4) | Release digest non-determinism (closed: reproducible) | Packaging |
| [#5](../../issues/5) | Floating IPs: 1:1 public-address NAT on the per-VPC gateway (closed: shipped eBPF-native, no gateway pod) | Floating IPs |
| [#6](../../issues/6) | Site-to-site VPN: authorized-forwarder + per-VPC route table | Connectivity |
| [#7](../../issues/7) | Agent: recreate incompatible pinned eBPF maps on load | Deployment |
| [#8](../../issues/8) | IPv6 guests don't autoconfigure (no RA / DHCPv6) | IPv6 |
| [#9](../../issues/9) | North-south to a v6 VPC IP when the fabric IP is v4 | IPv6 |
| [#10](../../issues/10) | Netfilter dependency (closed: conditional; eBPF masquerade default) | Datapath / deployment |
| [#11](../../issues/11) | SG north-south `from.cidr` rules don't union across groups (FIXED: compiler-side union) | Security groups |
| [#12](../../issues/12) | Exclusive IPAM authority vs co-resident Cilium (closed: Cilium removed) | Deployment |
| [#13](../../issues/13) | LoadBalancer ingress (etp: Local, source-preserving); NodePort decoupled, low priority | Services |
| [#14](../../issues/14) | Public IPs on the default network: supersede cozy-proxy (1:1 NAT for a net-0 VM) | North-south / Services |
| [#15](../../issues/15) | v6 VPC egress dead with a pooled VPCGateway; v6 VPC NAT missing | North-south / IPv6 |

Security audit (2026-10-07): findings, local fixes and actual verification are recorded in SECURITY-AUDIT.txt. The following checked items indicate working-tree implementations verified locally, not merges or production rollouts. Isolated kernel tests cover tunnel-source authorization with real skb metadata and positive IPv6 NDP/DHCP paths. No live-cluster rollout or security-completeness claim has been made.

- [x] FabricIP sandbox ownership: ADD retry reuse, stale DEL isolation, Running-Pod stale-address GC after grace, and agent repair from rebuilt endpoint state. Fake-client behaviour tests and isolated Linux veth retry tests pass; no live-cluster rollout.

- [x] Verify pinned upstream CNI plugin archives during image construction; isolated amd64/arm64 CNI-stage builds pass.

- [x] Bridge owner witness and shared writer lock for DEL versus GC/address-reuse races; isolated kernel route/map/concurrency tests pass.
- [x] Preserve active Port sandbox identity during migration staging and update
  it from the active launcher's FabricIP at cutover; behaviour regression tests.
- [x] Select persistent local veths by sandbox at cutover; reject ambiguous
  legacy endpoints instead of resurrecting a stale sandbox.
- [x] Require controller leader election with one cluster-wide Lease to prevent
  duplicate tenant identities during HA and rolling updates; runtime test.
- [x] Protect guest-announcement cutover from stale Port listeners and address
  reuse with live UID/resourceVersion checks and behavioural tests.
- [x] SecurityGroup membership verifies Pod UID before following live labels;
  pod-name reuse cannot grant a predecessor the replacement's group identity.
- [x] APIService reconciliation revokes a previous insecureSkipTLSVerify setting
  when switching to verified TLS; behaviour test of existing registrations.
- [x] Validate SecurityGroup selectors and port bounds in the aggregated API;
  legacy malformed port rules fail closed in all four compiler paths.
- [x] Serialize locals ownership checks/deletes with SetLocal to prevent stale
  DEL/sever from removing an endpoint replaced during migration.
- [x] Restrict IPv6 link-local ingress exceptions to validated NDP/DHCPv6;
  reject link-local application sources rather than bypassing SecurityGroups.
- [x] Refuse FabricIP self-heal with ambiguous rebuilt sandbox ownership.
- [x] Verify default-network rebuild against effective host-route ownership;
  replace stale host routes during an authorized CNI ADD.
- [x] Keep selected pending SecurityGroups default-deny when group identities
  are exhausted, and retry allocation after capacity becomes available.
- [x] Reject workload impersonation of bridge and hairpin source addresses
  before any forwarding grant or RPF exception.

- [x] Security audit: policy compilers preserve pinned enforcement until all input caches synchronize; replay one complete snapshot afterwards.

- [x] Security audit: serialize FabricIP/node route reconciliation, revoke missing-node routes and prune stale pinned net-0 routes after initial list.

- [x] Security audit: migration-forward cleanup owns its installation, revocation clears it, and startup removes forwards whose timers died with the previous agent.

- [x] Security audit: VPC Port route notifications and migration moves reject obsolete cache events.

- [x] Security audit: binding reconciliation distinguishes raw port flags from stripped network identity, preserving platform gateway and quarantine state.

- [x] Security audit: idle guest-announcement listeners wait for socket readiness instead of consuming a CPU per staged VM.

- [x] Security audit: durable staged-local state and Port UID witnesses; revoke/synchronize all owned migration legs, including legacy endpoints with verified sandbox or launcher ownership.
- [x] Bound lifetime metric cardinality and warning caches during VPC/policy churn; verify overflow accounting and RA/DHCPv6 worker/socket lifecycle.
- [x] Serialize CNI forwarding publication with grant reconciliation; keep hooks fail-closed during initialization and prevent bridge recreation after revocation.
- [x] Coalesce policy notifications into bounded pending work; verify event bursts and updates received during compilation.
- [x] Arm policy bootstrap guards for new/recreated maps and interrupted first startup before exposing programs.
- [x] Drain old Port UID veths on replacement events and orphaned owned veths after complete cache sync, including missed migration-target deletions.
- [x] Bound NetworkPolicy pair/CIDR compilation and expanded desired policy maps before allocation exceeds map capacity; reject whole oversized snapshots under deny guard.
- [x] Bound SG CIDR containment work with a scoped prefix index and verify union semantics against the previous containment definition.
- [x] Preflight full SG and HostFirewall compilation budgets before peer/port products allocate large row arrays; retain deny guards on rejection.
- [x] Bound and cancel IPsec VICI status collection; refuse queued concurrent scrapes and oversized streams, close the HTTP server on shutdown.
- [x] Reject strongSwan implicit wildcard, subnet/range and encoded/regex identity forms consistently at API, controller and appliance boundaries.
- [x] Replace quadratic peering reciprocal scans with an index and coalesce cache-ready reconciliation without weakening two-sided consent.
- [x] Supervise and reap charon during bootstrap and shutdown; bound VICI initialization and configuration calls.
- [x] Bound auxiliary HTTP request bodies as well as headers/keep-alives; verify slow GET bodies release connections while flow streaming remains functional.
- [x] Detect equivalent IP/FQDN/email IKE identities before loading two differently authorized connections.
- [x] Extend authenticated-identity deduplication to certificate DN attribute aliases and spacing; reject ambiguous DN syntax.
- [x] Supervise FRR child death during socket readiness and reap all children after startup failure or shutdown.
- [x] Persist VNI reservations across VPC deletion and controller restart; bound allocation below Geneve flag bits and verify concurrent reservations.
- [x] Exclude reserved bridge/hairpin identities from FabricIP, Port and ServiceVIP allocation and explicit workload claims.
- [x] Bound authoritative DNS query concurrency, endpoint scans and synthesized SRV response products before large allocation.
- [x] Bound idle DNS TCP connections before per-connection worker/frame allocation and verify slot release over repeated connections.
- [x] Require current Service UID ownership for backend EndpointSlices in ServiceVIP and headless DNS.
- [x] Bind existing ServiceVIP claims to current Service/VPC UIDs and claim VNI; replace stale generations with conditional deletion.

- [x] Bound ServiceVIP backend construction and controller expansion, replace Cartesian scans with an index and coalesce cache-ready projection.

- [x] Admit and validate DNS UDP packets before the library creates per-packet workers; bound floods and verify malformed-input slot release.

- [x] Verify persistent Port claim VNI against the current VPC before rebinding; preserve pinned identity on generation mismatch.

- [x] Persist HostFirewall modes independently of params recreation, seed legacy state before pin reconciliation and restore missing host identity before program publication.

- [x] Require current VPC claim VNI and nonempty Pod target UID for ServiceVIP/headless DNS backends and current VPC identity for DNS query sources.

- [x] Bound automatic CNI Port allocation conflicts and check cancellation during address selection.

- [x] Apply pool network/gateway reservations to explicit and reused ordinary Ports; include the final usable ServiceVIP candidate in small pools.
- [x] Index exact DNS peering pairs, deduplicate declarations and bound per-query authorization work and retained peers.

- [x] Scope occupied-address checks to current VNI claims; avoid cluster-wide Port lists during ServiceVIP collision repair.

- [x] Bound live IPAM claim-list pages, scan counts and cancellation before constructing occupied-address state.

- [x] Prove SecurityGroup numeric membership with current group and Pod UIDs, rejecting recycled/duplicate IDs and stale legacy status.

- [x] Guard registered local VPC endpoints whose SecurityGroup membership is missing; publish explicit zero membership only after controller identity resolution.
- [x] Fence local SecurityGroup membership with Port UID and sandbox witnesses; keep CNI activation last during address replacement and verify stale-snapshot rejection/recovery in the kernel.
- [x] Index membership group/Port/pod reverse lookups and bound selector resolution before conversion; retain default-deny on oversized or malformed input and verify recovery.
- [x] Page and bound live SecurityGroup ID allocation/duplicate scans, consuming all continuations before assigning IDs.
- [x] Fence GC and binding-revocation Port deletes with UID/resourceVersion; confirm cache-missing Nodes live before releasing sever barriers.
- [x] Keep VPCBinding targets immutable so retargeting cannot discard the original revocation/reaping barrier; verify aggregated and actual admission CEL behavior.
- [x] Verify receiving veth ownership before it can consume a replacement endpoint's SecurityGroup permissions, including fabric/floating address translation and default-network reuse.
- [x] Index GC reverse lookups by claiming Pod and Node so ordinary workload/heartbeat events do not copy every cluster claim.
- [x] Confirm remaining binding grants and revocation targets with complete bounded live scans before releasing reap barriers.
- [x] Bound sandbox witness hashing and eliminate its measured per-Port snapshot heap allocation without changing valid digests.
- [x] Release guest-announcement child contexts when listeners finish naturally, including socket failures and successful announcements.
- [x] Filter unrelated guest-announcement traffic in the kernel and verify receiver CPU under a real ARP flood as well as IPv4/IPv6 announcement acceptance.
- [x] Bound auxiliary HTTP connections before allocating workers; verify admission recovery and shutdown while the budget is exhausted.
- [x] Gate unsupported SCTP traffic so selected NetworkPolicy/SecurityGroup endpoints cannot bypass default-deny; retain existing unisolated and plumbing behavior.
- [x] Reject unsupported SCTP in selected HostFirewall directions, including node-to-remote-pod egress; keep UDP-only transport/reply exemptions and node plumbing separate.
- [x] Bound gateway, route, FloatingIP and service-uplink notification work, preserve pinned forwarding during incomplete initial lists, and replay complete caches.
- [x] Reconcile NAT reverse ownership and shards from complete bounded snapshots; remove rotated/orphan addresses and fence cleanup against replacement VPC ownership.
- [x] Refresh NAT shard routes on node underlay endpoint changes or withdrawals even when readiness stays unchanged.
- [x] Remove quadratic gateway projection scans within a namespace while preserving the oldest live boundary and namespace separation; measure CPU and allocations.
- [x] Keep HostFirewall/LB tail-call targets alive across agent descriptor closure and populate slots before CNI classifier publication; verify actual kernel lifetime.
- [x] Bound route compilation before copying/expansion and reject over-capacity route maps before deleting the last complete snapshot; test failure and recovery.

- [x] Keep a pinned DROP guard during live TCX reordering; kernel tests verify attach failure, retry, interruption cleanup and repeated link/FD lifetime.

- [x] Reap detached TCX bpffs pins after a missed CNI DEL; kernel tests cover deleted veths, directory batches, active hooks and foreign pins.

- [x] Harden the registered UsageStats helper with bounded live pages, deadline and lightweight identities; tests preserve exact counts and scan errors. Stock admission uses status.used rather than invoking this helper per create.

- [x] Bound FabricIP sandbox ownership lists at ADD/DEL, including UID-less teardown; tests cover complete pages and no partial-scan mutation.

- [x] Bound scoped forwarding grant unions and discard no large union for unrestricted grants; admission/CNI/kernel tests cover malformed legacy inputs, bounded errors and owner-authorized revocation.

- [x] Normalize IPv4-mapped CIDR masks once across route/forwarding/policy LPM keys and SecurityGroup containment; verify real kernel insertion and packet verdicts.

- [x] Page CNI binding authorization lists and retain only bounded matching forwarding state; incomplete scans must not grant attachment or forwarding.

- [x] Resolve cached binding grants once per local consumer/VPC key, skip unrelated grants and avoid forwarding unions for DNS attachment checks; measure CPU/heap and verify grant replacement/revocation.

- [x] Bound remaining CNI Port ownership and gateway consent lists; confirm complete scans before reuse, rebind or teardown and reject ambiguous persistent NIC claims without changing their identities.

- [x] Bound networks annotation decoding before allocating the full entry list; apply the same contract to delegates and reject duplicate interface pins with bounded errors.

- [x] Enforce NetworkPolicy and HostFirewall CIDR packet-family identity in the shared RFC 6052 address space; kernel tests reject cross-family authorization and retain valid IPv4/IPv6 permissions, exclusions and fail-closed legacy keys.

- [x] Enforce specific SecurityGroup ingress/egress CIDR family identity; real kernel packets verify positive permissions, cross-family rejection and legacy-key denial within the verifier stack budget.
- [x] Enforce scoped forwarding packet-family identity with a dedicated ifindex/family LPM key; real packets verify origin anti-spoof drops, map recreation/replay and descriptor lifetime across repeated clear/replay.

- [x] Reap obsolete ordinary primary-invocation Port sandbox claims after grace and live FabricIP/Pod confirmation; behavior tests preserve VM pins, legacy/delegate uncertainty, dual-stack transitions and the sever barrier.

- [x] Reconcile own VPC CIDRs without retained update/restart history; kernel and informer tests cover all prefixes, peering preservation, shared capacity preflight, concurrent writers and bounded replay after cache synchronization or capacity release.

- [x] Security audit SEC194: bound live VPN namespace-quota pages/time and compute oldest-wins rank without retained payloads/sorting; reject absent/replaced targets and partial/cancelled scans.

- [x] Security audit SEC195: resolve VPN appliance Ports by current spec pod index, avoid Port work without owned Ready pods, verify two replicas/retarget/removal and no broad fallback on a missing index.

- [x] Security audit SEC196: select the current sandbox for VPN and explicit/default VPC next hops when FabricIP status witnesses agree; verify reuse per pod version, cancellation and legacy compatibility.

- [x] Security audit SEC197: bound VPN object-reference names at admission and before legacy queue/index/lookup/configuration work; verify actual queue/cache behavior, diagnostics, teardown/recovery and valid reference compatibility.

- [x] Security audit SEC198: page and bound live VNI duplicate/bootstrap scans; preserve complete high-water, orphan/terminating claims and duplicate ownership proofs, rejecting partial results.

- [x] Security audit SEC199: reject false VNI reservation success when a retry helper loses an interrupted counter attempt; require an independently confirmed Lease write and preserve cancellation/request-timeout errors.

- [x] Security audit SEC200: bound VPCGateway VPC references on create/update, before legacy indexes/queues/lookups; verify real workqueue retention, cache removal/recovery and unresolved status cleanup.

- [x] Security audit SEC201: bound optional gateway selector namespaces and route inputs before admission/index expansion; preserve blackholes for legacy invalid next hops and verify cache/lookup/recovery behavior.

- [x] Security audit SEC202: avoid copying all VPC Ports for gateway healing; select only related claims for owned Ready system Pods, preserve deletion fences and verify missing-index/retarget/recovery behavior.

- [x] Security audit SEC188 availability: isolate route capacity overflow by owner namespace with fair budgets and explicit scoped fail-closed guards; verify unrelated IPv4/IPv6 NAT, protected-prefix drops, recovery and bounded guard memory/CPU.

- [x] Security audit SEC203: reproduce and close accepted VPN prefix fallback when credentials/configuration fail before the appliance is realized; preserve complete protected intent, retry errors, ownership fences and explicit withdrawal.

- [x] Security audit SEC204: bound WireGuard key/endpoint input before admission, legacy serialization and appliance parsing; behavior tests and allocation benchmarks, no key material in rejection diagnostics.

- [x] Security audit SEC205: stop route prefix work after an owner is already rejected, retaining all its current scope denials; actual admission/informer work-budget regression.

- [x] Validation follow-up: complete Linux race suite and Helm checks pass; all BPF/netlink packages pass with kernel gates enabled in isolated containers. Preserve failed/interrupted global invocations separately in the audit journal.

- [x] Security audit SEC206: reproduce and bound IPsec default proposal expansion across peers before credentials/serialization; gateway and connection admission plus legacy/appliance behavior tests and allocation measurements.

- [x] Security audit SEC207: measure and scope persistent Port launcher/VMI event lookups by consumer namespace and VM name; actual cache tests, retarget/deletion and pinned identity preservation.

- [x] Security audit SEC208: reproduce and bound repeated IPsec Secret credential payloads before JSON serialization; preserve exact valid credentials and verify VICI rejects oversized inputs without commands.

- [x] Security audit SEC209 hardening: bound auxiliary HTTP request headers below Go's default one-MiB budget; real TCP rejection, valid authentication header and recovery tests.

- [x] Validation follow-up SEC209: complete Linux agent consumer suite passes with race detection, including the isolated kernel-enabled run; prior WSL interruptions remain separately recorded.

- [x] Security audit SEC210: reproduce and bound IPsec identity/address scalars before admission, parsing, normalization and repeated serialization; preserve bounded exact identity compatibility and diagnostics.

- [x] Security audit SEC211: bound VPN remote-prefix admission Status diagnostics to the first invalid index without echoing input; native APIStatus and valid dual-family recovery tests pass. Linux race validation tracked in the audit journal.
- [x] Security audit SEC212: bound SecurityGroup admission diagnostic amplification; real APIStatus, valid rule recovery and immutable VPC anchors tested on Windows and Linux with race detection.
- [x] Security audit HARDENING213: bound HostFirewall invalid-rule API diagnostics and CIDR parsing; native valid exception/range recovery tests pass, Linux race follow-up recorded in the audit journal.
- [x] Security audit SEC214: bound VPN pool-overlap and invalid mode/spec API diagnostics; pool/DNS/BGP and mode recovery tests pass natively and on Linux with race detection.
- [x] Security audit SEC215: enforce VICI's one-byte pool section-name budget at API, controller and appliance boundaries; actual wire/encoder and pre-credential/pre-kernel tests pass with race detection.
- [x] Security audit HARDENING216: fix flowctl producer retention on scanner failure/cancellation; real pipe, valid stream recovery and producer joins pass five repetitions with Linux race detection.

- [x] Security audit SEC219: reject unusable peering references before authorization and legacy index/replay work; API, real cache, controller, agent and responder regression suites pass with race detection.

- [x] Security audit SEC220: bound binding references and immutable-target diagnostics before authorization and legacy NAD/grant-key work; bounded real APIStatus, exact legacy cleanup authority and healthy recovery pass with race detection.

- [x] Kernel validation transport: pace the 512-event sever fixture against informer-cache delivery in batches below the fake watcher's 100-event ceiling, without waiting for the blocked acknowledgement or handler; the complete agent kernel/race suite passes in its own fresh container.

- [x] Security audit SEC221: patch the separate KPR module's vulnerable dependencies; Cilium and its rebuilt socket-LB object use v1.19.8, static build/vet and complete kernel/race tests pass, the separate vulnerability scan reports zero findings and module hashes verify.

- [x] Security audit SEC222: replace the prototype KPR cluster-admin binding with explicit read-only API permissions established from its own reconciler and imported Cilium cells; actual manifest rule coverage verifies required reads and rejects mutations, credentials and RBAC management, including with race detection.
