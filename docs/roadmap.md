# cozyplane — roadmap

A living checklist of what is built and what is outstanding. It complements the
design docs (`design.md`, `control-plane.md`, `internals.md`, `live-migration.md`)
— those explain *how*; this tracks *what's done*.

**How to read it.** A ticked box is merged on `main` and exercised by the e2e
suite or validated on a real cluster; where a real-cluster validation happened
it's noted. An unticked box is planned work; where a GitHub issue tracks it, the
number is linked (e.g. [#7](../../issues/7)). Keep this file honest — tick a box
only when the thing actually works end to end, and add outstanding items here as
they're discovered rather than leaving them only in issues.

---

## Immediate roadmap — what's genuinely open

The sections below are the full ledger, and most of it is ticked. This is the
short list: what is actually left, in rough priority order. Revised **2026-07-14**,
once the north-south arc closed (one declared boundary, metered, with the tenant's
own egress identity; cozyplane attracts nothing) and the multi-tenancy rules were
built (a tenant persona, a tenant that can see itself, a ceiling).

**Features**

1. **Per-VPC metadata endpoint + guest autoconfiguration** — design drafted in
   [vm-provisioning.md](vm-provisioning.md), awaiting review (§3).
2. **Site-to-site VPN** ([#6](../../issues/6)) and **cross-family v4↔v6
   translation** ([#9](../../issues/9)) — design drafts exist; neither is urgent
   (§3, §4).
3. **SecurityGroup v2 leftovers**, all low priority: ICMP rules; peer-existence
   validation for peer refs; and **a real connection table to replace the TCP
   SYN-gate** — that last one is shared with NetworkPolicy and HostFirewall, so it
   wants solving once for all three layers rather than three times. FQDN egress is
   **rejected**: it needs a DNS-snooping engine, which is out of scope (§3).

**North-south residue** — the arc is built; these are the ends it left loose.

4. **The pool-less gateway pod still exists, and it still launders** — a
   `VPCGateway` with `nat.enabled` but **no `poolRef`** (the field is `+optional`)
   has no address to wear, so the controller still spawns the per-VPC gateway pod
   for it, and that pod's egress is SNATed to its fabric IP and then re-SNATed by
   the cluster masquerade to the **node's** — precisely the tenet-8 violation
   increment 2 set out to end. `cmd/gateway` and its netns iptables are therefore
   still in the tree and still reachable. Decide: require `poolRef` when
   `nat.enabled` (and delete `cmd/gateway`, the gateway controller's Deployment
   path, and the last netfilter outside `firewall.go`), or keep the pool-less door
   and say in writing why a tenant may wear the platform's identity. Leaning
   strongly toward the former (§3).
5. **The gateway's DNS door** — the gateway pod proxies cluster DNS on `:53`; the
   split-horizon resolver already serves VPC pods, so it is probably vestigial.
   Folded into (4): confirm before deleting, or tenant DNS breaks with the pod —
   [north-south.md](north-south.md) §7.
6. **Per-VPC NAT port-pool exhaustion** — each node SNATs a VPC's pods from its own
   shard (`NAT_SHARD_SPAN` 4032, 16 shards). Nothing accounts for a tenant
   exhausting it, and a node-set change reshuffles shards and breaks live flows.
   Known and accepted at prototype scale; it needs a story before it is not
   ([north-south.md](north-south.md) §7).
7. **Inbound MTU on an encapsulated north-south path** — clamp the TCP MSS in the
   inbound SYN at the encapsulating node. Shared by the EIP request half and
   `etp: Cluster` DSR, so solve once — [floating-ha.md](floating-ha.md) §7 (§3).

**Hardening**

8. **Node-origin path-trust** — all three policy layers still recognise node
   origin by *source address* (`np_nodes` / `hf_self` / `NS_MARK`-absence). The v6
   masquerade-laundering bug proved the class is exploitable; the fix is to trust
   the *channel* (host→veth same-node, `node_remotes` overlay cross-node,
   TLV-authenticatable) instead. Cheap first step: per-layer
   `*_node_exempt_total` counters, so the exemption is at least visible.
   **Net-0 RPF for NetworkPolicy identity** is the same one-lookup shape as the
   `from_pod` RPF SG v2 shipped — the natural follow-on (§6).
9. **NP egress vs VPC-pod fabric IPs** — a decision, not a build: either drop VPC
   pods from `np_ident` (fabric IPs become `ipBlock` territory) or document the
   corner as intended (§6).

**Test gaps**

10. **VM-migration e2e** — none exists, anywhere; and the cutover path changed when
    `Port.spec.fabricIP` was normalized away (the controller's fabric-IP copy was
    deleted). Real-cluster hand-validation is the only coverage (§5, §8).
11. **`test/e2e.sh` is now broken, not merely stale** — it has not run since the
    API-group split, and it still writes `ExternalPool.spec.advertisement: L2`, a
    field **deleted** with the announcement layer, so its floating-IP phases cannot
    even apply. It is the only coverage for *external* floating-IP and LoadBalancer
    ingress, and by construction it cannot run on a real cluster (its "external"
    clients are containers on kind's docker network). Two honest options: give a
    real test cluster a genuine off-cluster client, or repair it and accept
    kind-in-CI for exactly those phases. Until then, say plainly that the external
    ingress paths have no automated coverage (§8).

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

- [x] Object model: `VPC`, `Port`, `VPCBinding`, `VPCPeering`, `ExternalPool`, `FloatingIP`
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
- [x] **Cross-node node↔pod on a spoof-guarding underlay (OCI)** — the pod's *reply* to a hostNetwork client (pod→node) fell to the kernel and left the wire pod-sourced, which OCI anti-spoofing drops; every cross-node admission webhook hung, wedging cert-manager + ~60 HRs. Fix: a `node_remotes` map (node address → its Geneve endpoint) + `from_pod` encapsulates a default-network pod's traffic to a node over the overlay (gated to the pod-veth path so the uplink-egress hook doesn't re-encap Geneve outer frames); agent learns node addresses from InternalIPs + a `cozyplane.io/node-addresses` annotation (covers multi-NIC nodes where the host sources from a non-InternalIP NIC). Also `CFG_MASQ_IP`: the cluster-egress masquerade SNATs from the **default-route** address, not the InternalIP, so a masqueraded packet is valid for the NIC it egresses (fixed pod→internet on the dev cluster). dev-cluster-validated: full platform converges (90/90 HRs). Diagnosis in [bringup-field-notes.md](bringup-field-notes.md#5-admission-webhooks-fail-cross-node--podnode-reply-un-encapsulated-fixed)

## 3. VPC features — peering, egress, floating IPs

- [x] VPC peering: symmetric halves, native cross-VPC datapath, status controller
- [x] ~~Per-VPC egress NAT gateway (gateway-attach, per-VPC gateway pod)~~ — **superseded** by `VPCGateway` + eBPF VPC NAT (below). The pod survives only for a gateway with **no `poolRef`**, which has no identity to wear and so still launders into the node's address; retiring that path is open work (see the immediate roadmap)
- [x] Floating IPs: eBPF bridge extension (no gateway pod), true public IP both directions — closes [#5](../../issues/5) (which proposed gateway-anchored iptables NAT; shipped eBPF-native instead)
- [x] ~~Floating-IP advertisement in eBPF (`from_uplink` ARP/NDP responder)~~ — **deleted 2026-07-14** (north-south increment 3): cozyplane attracts nothing. Readiness is still gated on a live target Port; *delivery* survives and is what makes platform-side attraction work
- [x] Gate `VPCPeering` creation on a `peer` virtual verb on the local VPC — strategy-enforced in aggregated mode (which also closed the `export` gap there: admission never sees aggregated resources), VAP twin for CRD mode — [#1](../../issues/1)
- [x] **Floating-IP HA: attraction separated from delivery** — **[floating-ha.md](floating-ha.md)** (BUILT 2026-07-13; dev-cluster-validated with the decisive asymmetric triangle: address announced by node2, pod on node1, external client on node0 — three distinct nodes). Before, one node attracted (answered ARP), delivered (hosted the pod) and egressed, because all three were the same decision: the agent programmed the `floating` map only on the target Port's node, and `floating_arp` answered only when the pod was `local_of` — *"programming the map is the advertisement"*. The cost was not ops-comfort but correctness: a live-migrating VM's public address was re-pointed by exactly **one** unacknowledged, never-repeated gratuitous ARP, and losing it black-holed the address for an ARP-cache lifetime — on the feature whose whole promise is a sub-second cutover with the address preserved. It also made "sits on the pool's L2" an undeclared scheduling constraint on any floating-IP target
  - [x] Increment 0 — a robust announcement: `AnnounceAddress` sends a spaced burst (RFC 5227's shape) instead of one best-effort frame, and re-sends when a node newly *wins* an address. An unacknowledged protocol has repetition and nothing else
  - [x] Increment 1 — decouple: every node programs `floating`; a new `float_announce` map (present only on the elected announcer) is the sole ARP/NDP gate; `from_uplink` gained the remote arm it never had (`remote_of(fe->net, fe->vpc_ip)` → `encap`); `from_overlay`'s VPC branch gained a floating probe **before** the `gateways` lookup (a public inner dst otherwise **mis-delivers into the VPC's gateway pod** — not a drop); `to_pod` DNATs it unchanged (it keys on the destination, so it cannot tell an overlay-arrived floating packet from an uplink-arrived one); and the reply needed no code at all — the host already SNATs its egress to the public address out its own uplink, so replies go straight to the client (DSR), never via the announcer. Attraction is a rendezvous-hash election over the `Ready` nodes that can serve the pool's link (each publishes its own FIB answer as a node annotation) — no lease, no leader: `announcerFor` takes no "self", so agreement between agents is structural. A migration now makes no L2 claim at all. `cozyplane_floating_announced` exposes who attracts what. Verifier-gated on 6.8 (the encap fits `from_uplink` inline; no tail-call slot needed)
  - [x] ~~Increment 2 — BGP~~ **REJECTED 2026-07-13** (decision, not a deferral — see [north-south.md](north-south.md) §6). A CNI has no business holding routing sessions with the fabric. The practical tell came first: it cannot be validated on a real cluster at all (OCI gives compute instances no BGP peer — 179 closed on both gateways), so it would have been provable only against a synthetic FRR fabric on kind — and needing a fake fabric to believe your own feature is the design telling you the feature is in the wrong process. **The same reasoning retires the L2 announcement we already ship** (`float_announce`, `floating_arp`/`floating_ndp`, `AnnounceAddress`, the election): it is MetalLB-L2 reimplemented inside a CNI. Attraction belongs to the platform (CCM / MetalLB / a static route / an OCI secondary VNIC address); cozyplane consumes an address and *delivers* it — which is exactly what [lb-ingress.md](lb-ingress.md) already says for LoadBalancer IPs. **Increment 1's delivery decoupling is what makes that possible** (any node can now receive an external address and reach the pod), so it survives; the attraction layer it shipped alongside is what goes. `ExternalPool.spec.advertisement` (`L2 | BGP`, dead code) gets deleted rather than implemented
- [x] **A floating target takes exactly one address** — the reverse map (`floating_egress`) is keyed by the target's `{net, VPC IP}` alone, so a second FloatingIP on the same target overwrote the first's egress entry and the first address began replying *from the second* — its clients dropped the reply and the address went silently dead. Nothing in the datapath can detect that, so the controller refuses the later binding (oldest wins, `TargetExclusive=False` on the loser, no address allocated). Pre-dated the HA work; surfaced by its e2e — [floating-ha.md](floating-ha.md) §9
- [x] **`VPCGateway` — the VPC's declared north-south boundary** ([north-south.md](north-south.md) increment 1; dev-cluster-validated deny-then-admit: refused with no gateway, refused with a gateway that declines, delivered the moment it admits — the Service unchanged throughout). A kind, not a field: `VPC.spec.egress.natGateway` was a bool on an object the tenant owns, so **a tenant granted itself internet**. Creating a gateway now needs the **`attach` verb on the referenced `ExternalPool`** (the `export`/`peer` escalation-gate pattern), so the operator grants the pool and the tenant opens its own door onto it. A VPC has exactly one boundary (oldest wins; `EffectiveGateway` lives in the API package because the controller, the CNI and the agent must agree on it without coordinating). **Tenet 7 is enforced:** `vpc_ingress[net]` gates `lb_ingress`, so a `Service type=LB` can no longer open a door into a tenant's VPC just by naming its pod as a backend — refusals counted in `ns_denied[door]`, kept out of the byte meter because a refused packet did not cross
- [x] **VPC NAT gateway in eBPF — a tenant egress identity** ([north-south.md](north-south.md) increment 2; dev-cluster-proven on the asymmetric triangle: SNAT on the pod's node, the address attracted by another, the client on a third). A VPC now leaves the cluster wearing **its own address**, drawn from its own pool — before, it was SNATed to the gateway pod's fabric IP and then re-SNATed by the cluster masquerade to the **node's**, so tenants were indistinguishable from the platform on the wire (tenet 8). The per-VPC **gateway pod is retired on the sanctioned path**: a gateway with a pool needs no pod, so no hairpin and no per-VPC SPOF. (It is *not* gone from the tree — a `nat.enabled` gateway with no `poolRef` still gets one, netns iptables and all, and still launders into the node's identity. Closing that is open work.) It could not simply be `masq_snat` with another address — that identifies a pod by its ADDRESS at the uplink, which is impossible for a VPC because tenant CIDRs overlap; the tenant is knowable only at the veth, which is what the gateway pod was really for. So the SNAT happens at the veth and the state lives on the pod's node, while the reply lands wherever the address is attracted — resolved by partitioning the port space per node (tenet 1 forbade the simpler "elect an egress node", which would have rebuilt the hairpin). `poolRef` and the `attach` verb are now load-bearing
- [x] **The announcement layer deleted; `FloatingIP` is an EIP under the gateway** ([north-south.md](north-south.md) increment 3). Cozyplane **attracts nothing** (tenet 3): `float_announce`, `floating_arp`/`floating_ndp`, `AnnounceAddress`, the announcer election, the pool-eligibility annotation, `--floating-ha` and `ExternalPool.spec.advertisement` are all gone — that was MetalLB's L2 mode reimplemented inside a CNI. Something else must attract (a CCM assigning the address to a VNIC, MetalLB, a static route, or an address configured on a node); **delivery does not care**, because `from_uplink` runs at tc ingress ahead of the kernel's routing decision, so whichever node the address lands on finds the pod through `floating`/`nat_of` and reaches it over the overlay. A FloatingIP now draws from its **VPC's gateway's pool**, so a VPC with no boundary gets no external address at all — the `attach` verb governs *every* address a tenant can wear, and every external address crosses one counted boundary (tenet 2, finally true)
- [ ] **Inbound MTU on an encapsulated north-south path** — clamp the TCP MSS in the inbound SYN at the node that encapsulates it. Affects floating-HA's request half and `etp: Cluster` DSR identically (both Geneve-encap an external client's full-MTU packet; a v4 underlay fragments and reassembles, which works but costs). Shared, so solve once — [floating-ha.md](floating-ha.md) §7
- [ ] Site-to-site VPN: authorized-forwarder role + per-VPC route table — [#6](../../issues/6)
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
- [x] **LoadBalancer ingress + external NodePort** — **[lb-ingress.md](lb-ingress.md)**: *delivery only* — cozyplane consumes `status.loadBalancer.ingress` (whoever wrote it: CCM, MetalLB, a human), honours `ipMode`, and DNATs at `from_uplink` (a tail-called program) to node-local ready backends with the client source preserved (`externalTrafficPolicy: Local`; allocation/announcement/provisioning are the LB implementation's job). Both families; VPC-pod backends via a `bridges` hop (no client masquerade, SG-gated at the DNAT point); `loadBalancerSourceRanges` as an `lb_src` LPM; NodePort = the same rows keyed by node addresses. **`etp: Cluster` via DSR** (strictly opt-in: `CLUSTER_DSR=true` on kpr — the fleet-wide LB-IP spoof permission it needs is an underlay property; ungated, Cluster degrades to node-local delivery) — remote backends reached by Geneve-encap with the frontend identity in an option; the reply exits the backend's own node *as the LB IP*, so the client source is preserved in every mode (the agent serves every ExternalPool's link on every node for this). e2e-covered (incl. source-preservation, the kube-proxy-counter-flat proof, and Cluster delivery via a backend-less node) + dev-cluster-validated (MetalLB composition; the asymmetric client/announcer/backend triangle over the OCI VLAN) — [#13](../../issues/13)
- [x] **Default-network `NetworkPolicy`** — the production blocker Cilium's removal left open. **Decision 2026-07-11: build native; the Cilium-policy-only spike is dropped.** Design: **[network-policy.md](network-policy.md)** — upstream `networking.k8s.io/v1 NetworkPolicy` consumed as-is, **kept a distinct kind from `SecurityGroup`** (tenant/system RBAC separation; VPC pods aren't clean siblings of net-0 pods); same enforcement *shape* as SG (destination-side in `to_pod`, SYN-gate) but net-0 twin maps with coordination-free 64-bit label-hash identities, label-follows from day one
  - [x] Increment 1 — ingress with pod/namespace selector peers: identity compiler in the agent, `np_ident`/`np_allow`/`np_nodes`, `to_pod` net-0 gate (noinline + per-CPU scratch), stateful UDP via the `np_ct` reply-pin written at `from_pod`, kubelet/node exemption, churn-label filtering, fail-closed unserved constructs. e2e 128/128 incl. label-follows both ways, v6, probes-stay-Ready, isolated-pod DNS
  - [x] Increment 2 — `ipBlock` (+`except` as longer deny prefixes in the `np_cidr` LPM), egress enforcement (pod-to-pod at the destination's `to_pod`, identity-less destinations inline at `from_pod`; node-destined egress exempt by design). e2e 138/138 incl. ipBlock-through-LB with the source preserved, egress DNS rule, external-cidr egress; dev-cluster-validated live. Verifier lesson recorded: sibling callees not nested ones near the 512B cliff, zero bpf-to-bpf calls in `from_pod`
  - [x] Increment 4 — **entity peers** (`policy.cozyplane.io/entity: nodes | local-pods | local-node` as a reserved namespaceSelector label — in-schema, so a policy stays portable and fails closed elsewhere): the vocabulary upstream lacks. The node exemption **narrowed to the LOCAL node** (`np_nodes` carries a locality bit) — remote-node origin (apiserver→webhook) is now gated and readmitted with the `nodes` entity, shrinking the address-minting surface from "any node address" to "this node's own" ([policy-layers.md](policy-layers.md) § trust model). `local-pods` admits co-scheduled net-0 pods (author-declared placement dependence — tenet 6 forbids *enforcement* from silently inferring co-location, not the author from naming it); it is also an egress `to` peer, while `nodes`/`local-node` in egress are refused (node-destined egress is HostFirewall's contract)
  - [x] Increment 3 — `endPort` via the `np_allow` port-suffix LPM (ranges = O(log) prefixes, hot path CHEAPER: one LPM probe per peer id); **cyclonus conformance 89/90 on the dev cluster** (every tag family 100%; the single miss is a named-port-in-disguise `update-policy` case — named ports are a documented fail-closed non-goal); compile scale ~5.9ms per full recompute at 5k pods / 200 policies. `test/cyclonus.sh` is the rerunnable harness (pod-ip destinations, TCP/UDP servers — see the doc's harness notes)
- [x] **Host firewall** — the node-scoped sibling of default-net NetworkPolicy — **[host-firewall.md](host-firewall.md)**: cluster-scoped, operator-only `HostFirewall` (tenants get no access — the third policy layer beside NetworkPolicy/net-0 and SecurityGroup/VPC) makes selected nodes host-ingress default-deny with cidr/except + port/endPort allow rules. Enforcement is one tail-called `hf_ingress` program (lb_prog slot 2) reached from every fall-through that hands a packet to the host stack, armed per node by `CFG_HF_ENABLED`; node sources, ICMP, the Geneve transport, and established TCP are never gated, and node-originated UDP returns via `hf_ct` reply-pins written at the three egress crossings. The e2e caught two real holes before they shipped: `from_uplink`'s v6 exit bypassed the gate, and the cluster-egress masquerade *laundered* v6 pod→node flows into the node exemption (fix: `node_remotes` is dual-family now, so v6 pod→node rides the overlay like v4 — also closing the latent v6 twin of the OCI anti-spoofing gap). e2e 160/160; dev-cluster-validated live (a control-plane node isolated behind the LB: pod→node scrapes dropped and counted, node Ready, kubectl/etcd/DNS pins unharmed, per-CIDR reopen, clean delete)
- [x] **Host firewall egress** (increment 2) — `policyTypes: [Egress]` makes a node's OWN new TCP/UDP flows default-deny, opened by `egress: to: [{cidr, except}]` rules: node→external is gated in `hf_ingress`'s node-originated arm, node→remote-pod (the one node-origin path that never reaches a host-stack fall-through) via a new tail-called `hf_egress` at `from_pod`'s remotes-hit encap. **node→node and node→local-pod stay structurally exempt** — kubelet↔apiserver, etcd, the agent's own API access, and kubelet probes ride them, so egress isolation cannot self-lock-out. `hf_ct` pins are written on both admitted directions, so each direction's reply passes the other's gate. Directions arm independently (an Egress-only object leaves ingress open) — [host-firewall.md](host-firewall.md)
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
- [x] Agent recreates incompatible pinned eBPF maps on load and rebuilds pod state from veth alias records — a map-ABI upgrade is a rolling DaemonSet update, no node reboots (e2e-covered) — [#7](../../issues/7)
- [x] Gateway `.1` Port reuse after an unclean death: the controller GCs live Ports whose claimant pod is gone (VM persistent Ports exempt), so the replacement's ADD retry claims the freed `.1` (e2e-covered)
- [x] Digest-reproducible release images: attestations off, SOURCE_DATE_EPOCH + rewrite-timestamp, digest-pinned bases — verified identical across CI reruns, and the pin-commit-rebuild loop converges — [#4](../../issues/4)

## 8. CI & testing

- [x] CI: unit tests, lint, build-drift, image release, datapath e2e
- [x] **Cluster-agnostic suites** — `test/policy-e2e.sh` (NetworkPolicy incl. entities, HostFirewall ingress+egress, SecurityGroup label-follows), `test/vpc-e2e.sh` (VPC attach with Port/FabricIP as separate objects, east-west, isolation, **overlapping CIDRs proven by identity** — the same address resolves to a different pod in each VPC, the dual-address bridge, peering, split-horizon DNS, SG, revocation, the VPCGateway boundary and the EIP egress identity) and `test/tenant-e2e.sh` (the tenant persona: R1's self-view, R2's structural blindness, R5's ceiling). All take `KCTX=` and run on a real cluster
- [ ] **`test/e2e.sh` is broken** — kind-only by construction (its "external" clients are containers on kind's docker network), unrun since the API-group split, and it still sets `ExternalPool.spec.advertisement`, a field deleted with the announcement layer, so its floating-IP phases cannot apply. It is the **only** coverage for external floating-IP and LoadBalancer ingress; until it is repaired or replaced, those paths have no automated coverage
- [x] eBPF bindings check (static bpftool, libbpf-dev)
- [x] Cross-compiled release image
- [x] e2e coverage for the IPv6 north-south paths (cross-node pinned — this caught the missing ip6tables FORWARD ACCEPT)
- [ ] e2e coverage for live migration (needs KubeVirt; kind can't host it)

---

## Open issues index

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
