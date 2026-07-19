# External addresses — cozyplane sources none of them

**Status: BUILT** (increments 0–4, §11; 1–3 dev4-validated). Supersedes
[north-south.md](north-south.md) §9, unifies with [public-ip.md](public-ip.md), and
defines the contract the platform's address-reservation work (the address-controller,
`IPAddressClaim` — cozystack/community#35) and cozyplane build against together.

Every routable address a VPC wears — a `FloatingIP`, a `VPCGateway`'s NAT identity —
is today **allocated by cozyplane** out of an `ExternalPool` (`firstFreeAddress`) and
**attracted by nobody** (the operator routes the range out of band). This document
retires that. The principle is one sentence:

> **cozyplane allocates no external address, attracts no external address, reserves
> no external address, and never shares one address across two Services. It consumes
> an address and delivers it.**

That is already how cozyplane treats a `Service type: LoadBalancer` (it reads
`status.loadBalancer.ingress`, [lb-ingress.md](lb-ingress.md)). This extends the same
stance to *every* external address.

---

## 1. Why cozyplane should source none of them

Allocation and attraction belong to the fabric, not the CNI:

- **Attraction** is tenet 3 — the CNI does not announce; a CCM/MetalLB/static route
  puts the address on a node, and `from_uplink` (tc ingress, ahead of routing)
  delivers it wherever it lands. We already deleted the announcer for this.
- **Allocation** is the same argument one level up. cozyplane picking `203.0.113.7`
  out of a CIDR list does not put it on the wire; something else must. An
  `ExternalPool` is an allocator with no attraction of its own — an address that
  exists in etcd and nowhere on the wire until an operator arranges routing by hand.

The Kubernetes ecosystem already has the machinery: an operator runs an allocator +
attractor (MetalLB, a CCM), a user creates a `Service type: LoadBalancer`, and the
allocator does the rest. **cozyplane should reuse exactly that**, and add only the
datapath a Service cannot express.

## 2. The mechanism: a delegated Service

A routable address is sourced by a `Service type: LoadBalancer` that carries
**`service.kubernetes.io/service-proxy-name: cozyplane`**:

1. The allocator (MetalLB/CCM, selected by `loadBalancerClass`) **allocates** the LB
   IP and **attracts** it, writing `status.loadBalancer.ingress`.
2. Every service proxy — kube-proxy, Cilium, **cozyplane-kpr** (it now honours the
   label, [kube-proxy-replacement.md](kube-proxy-replacement.md)) — **skips** the
   Service's datapath.
3. cozyplane reads the assigned address and applies its **own** datapath (`floating`
   + `floating_egress` for an EIP; `vpc_nat` for a NAT identity).

This is not new or speculative: **cozy-proxy ships exactly this in production** — a
`service-proxy-name`-labelled `type: LoadBalancer` Service still gets an LB IP
allocated and announced, while cozy-proxy owns the datapath. cozyplane's version is
that model generalized and made allocator-agnostic. (Portability caveat to record: an
allocator that *also* skips labelled Services cannot back this; the common ones —
MetalLB — do not.)

## 3. The contract is allocator-agnostic

cozyplane touches **only generic Kubernetes surface** — no `metallb.io/*`, no
provider knowledge:

| field | role | who reads it |
|---|---|---|
| `spec.type: LoadBalancer` | "allocate + attract an address" | any allocator |
| `spec.loadBalancerClass` | *which* allocator (GA since 1.24) | the allocators |
| `service.kubernetes.io/service-proxy-name: cozyplane` | "proxies, skip the datapath" | kube-proxy / Cilium / kpr |
| `spec.externalTrafficPolicy` | attraction scope (fabric-dependent, §6) | the allocator |
| `status.loadBalancer.ingress` | the allocated + attracted address | **cozyplane** |

`loadBalancerClass` is the agnostic "which fabric mechanism" selector; the pinning of
a *reserved* address (§7) is delegated through one backend-agnostic annotation on the
owned Service — the claim contract's, never a provider's (the driver translates it
into the backend's raw pin). **cozyplane's entire outward surface is: create a
generic LB Service, read one status field.**

## 4. FloatingIP — an EIP, sourced by a Service it owns

`FloatingIP` survives as the tenant-facing **binding + datapath** object. `spec.poolRef`
and `spec.address` are removed; an optional `addressClaimName` (§7) replaces them.

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: web-eip, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  target: 10.90.0.5                  # the VPC IP / Port this fronts
  loadBalancerClass: metallb         # optional; which allocator
  addressClaimName: my-eip           # optional; empty ⇒ dynamic (§7)
status:
  address: 203.0.113.7               # read back from the owned Service
```

The controller renders a Service the FloatingIP **owns**:

```yaml
apiVersion: v1
kind: Service
metadata:
  generateName: web-eip-            # FloatingIP.name + "-"
  namespace: team-a
  labels:
    service.kubernetes.io/service-proxy-name: cozyplane
    sdn.cozystack.io/floating-ip: web-eip     # how cozyplane finds its own Service
  ownerReferences: [{kind: FloatingIP, name: web-eip, controller: true, blockOwnerDeletion: true}]
spec:
  type: LoadBalancer
  loadBalancerClass: metallb         # passed through
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Local       # default; §6
  selector: {}                       # selectorless — cozyplane owns the endpoints and datapath
```

- **`generateName`, found by label, owner-ref'd.** The name is never known ahead of
  time; cozyplane lists its own Services by `sdn.cozystack.io/floating-ip`. Deleting
  the FloatingIP deletes the Service — there is nothing to reclaim, because the
  reservation was never the Service's job (§7).
- **Endpoints, not a selector.** For `etp: Local` the address must be announced on the
  target's node, so cozyplane manages the Service's **EndpointSlice** directly — one
  endpoint, the target Port's fabric IP. The Service is selectorless; cozyplane owns
  its endpoints.
- **The datapath is bidirectional.** cozyplane programs `floating` (ingress DNAT,
  source-preserving) *and* `floating_egress` (the pod leaves *as* the address) — the
  egress identity a Service cannot express (tenet 5). The Service only supplies the
  address; cozyplane does the 1:1.

## 5. The VPCGateway NAT identity — a backend-less sibling

A NAT identity is **not** egress-only. When a VPC pod egresses SNAT'd to it, the reply
comes back *addressed to it*, and that reply must be attracted to a node for
`vpc_nat_reverse` to un-NAT it. So the NAT identity needs the **same** allocation +
attraction as a FloatingIP — it rides a Service too. It differs in two ways, neither
being "no Service":

1. **`etp: Cluster`, with a self-addressed endpoint.** There is no single target pod to
   hang an EndpointSlice on — the replies fan out by port shard across nodes — so the
   Service is `etp: Cluster` and cozyplane demuxes: the reply lands on whichever node
   attracts the address, `from_uplink` there runs `vpc_nat_reverse`, the port's shard
   names the owning node, and the packet is forwarded over the overlay to it. This is
   exactly what `vpc_nat_reverse` already does — "the reply arrives at whichever node
   attracts the address; the port says who owns the flow."
   The one thing this Service still needs is a **ready endpoint**: MetalLB (verified at
   increment 1) advertises a LoadBalancer address only while its Service has one —
   `etp: Cluster` does **not** exempt it (the earlier "announces unconditionally"
   assumption was wrong). Since there is no target, cozyplane synthesizes a single
   endpoint that is a pure **advertisement trigger**, not a delivery target: its address
   is the assigned NAT address itself and it is `Ready` whenever the gateway is the VPC's
   legitimate (exclusive) boundary. Nothing dials it — every proxy skips the Service via
   `service-proxy-name`, and the real reverse path is `vpc_nat_reverse`. The endpoint
   exists only to flip MetalLB's advertise gate; the reply path is unchanged.
2. **Prefers reservation.** A VPC's egress identity churning under live flows is bad,
   so the NAT identity is the strong candidate for a **claim** (§7) rather than a
   dynamic address. That is a preference for stability, satisfied by the claim layer —
   not a structural difference.

The `VPCGateway` owns this Service the way a FloatingIP owns its own;
`status.natAddress` / `natAddress6` are read back from the Services, not allocated,
and reservation is per family (`nat.addressClaimName` / `nat.addressClaimName6`, §7). Because the eBPF NAT is per-family
(`vpc_nat_snat` v4, `vpc_nat_snat6` v6) and an address is single-family, a dual-stack
VPC's gateway owns **one Service per family** it has (`ipFamilies: [IPv4]` / `[IPv6]`,
`SingleStack`), each yielding one identity — the same per-family split the pooled
allocator already made (#15). A family the cluster cannot serve a LoadBalancer for
(e.g. an IPv6 VPC on a v4-only cluster) simply gets no address, and that family keeps
the gateway pod — the #15 fallback, unchanged.

## 6. Attraction rides the fabric — `etp` is not a default

Whether an address may be announced on *any* node is an **underlay property**, exactly
the reason `etp: Cluster` DSR source-preservation is opt-in (`CLUSTER_DSR`,
[lb-ingress.md](lb-ingress.md)). So:

- **`etp: Local` is the default** for a FloatingIP: cozyplane's EndpointSlice puts the
  address on the target's node; nothing is announced anywhere the target is not.
- **`etp: Cluster` is opt-in**, for fabrics that permit arbitrary-node announcement.
- **The NAT identity leans on `etp: Cluster`** (backend-less; nothing to trigger
  `etp: Local` announcement). On a strictly `etp: Local` fabric it needs a native
  reservation that attracts (a cloud EIP) — a real asymmetry, recorded honestly: the
  target-less egress identity is harder to attract on a restrictive bare-metal fabric
  than an EIP with a target is.

## 7. Reservation — the claim layer

`IPAddressClaim` is implemented: the **address-controller**
(`local.sdn.cozystack.io` — deliberately cozyplane's CRD group; these are facets of
one theme) is the PVC/PV/StorageClass split for addresses. An `IPAddress` (cluster)
**is** the reservation — a ledger object, one per IP; an `IPAddressClaim`
(namespaced) binds one, or one per family; an `IPAddressClass` names the per-class
driver that provisions. The core never touches a Service.

Reservation is orthogonal to attraction and **strictly optional**: cozyplane
functions identically with or without the mechanism installed. Without a claim there
is simply no guarantee of a specific address — the LB implementation auto-assigns.

**Association** — attaching a bound address to a workload — is the driver's job,
through one backend-agnostic annotation on the *consumer's own* Service:
`local.sdn.cozystack.io/ip-address-claim: <claim>` (a claim in the Service's own
namespace). The driver translates it into the backend's raw pin (MetalLB: an
`autoAssign: false` pool over the class range, plus `metallb.io/loadBalancerIPs` on
the Service) and enforces **one claim, one workload**. Deleting the Service un-pins;
the address stays `Bound` — reserved, inert. Deleting the *claim* is what releases
the address, via its reclaim policy.

This dissolves the hazard the reservation design used to defend against ("a dummy
Service holding the IP plus a second Service trying to use it"): **a reservation is
never a Service**, so there is no IP to share, and the earlier claim-owns-the-Service
/ object-contributes-endpoints choreography is gone with it. What remains:

- **Dynamic (no `addressClaimName`):** the FloatingIP/VPCGateway owns its one
  Service; the LB implementation auto-assigns; the address lives for the object's
  lifetime.
- **Reserved (`addressClaimName` set):** the **same** owned Service, plus the one
  annotation. The driver pins the claim's address onto it, and cozyplane consumes
  `status.loadBalancer.ingress` exactly as in the dynamic case — reserved and
  dynamic are one code path. The address lives for the **claim's** lifetime and
  survives the FloatingIP — the AWS-EIP semantics.
- **Per family:** association is one-claim-one-Service and the gateway's Services
  are single-family, so the NAT identity takes one single-family claim per family
  (`nat.addressClaimName` / `nat.addressClaimName6`).

Two independent gates, each in its right place: the **claim** governs reservation;
the **EndpointSlice readiness** governs announcement (held-but-dark when the target
dies). Neither knows about the other.

cozyplane's entire claim surface is that annotation, written as an opaque string —
no dependency on the claim CRDs, no informer, no module import (the repos are
private and the API alpha; a Go import would couple builds). The annotation key
mirrors the address-controller's `well_known.go` constant, with the authority named
at the mirror.

## 8. Governance moves off cozyplane

The `attach` verb and `ExternalPool` retire. "Who may mint a public address" becomes
**Service RBAC + the allocator's own scoping** (MetalLB's `serviceAllocation`
namespace/label restriction on its pool). That is correct — cozyplane should no more
govern addresses than allocate them — and it folds into the field-vs-RBAC gap (R10,
[multitenancy.md](multitenancy.md)), which is the platform's to close for *all*
Services, not cozyplane's to special-case.

## 9. What is removed, and what is not

**Removed:** the `ExternalPool` kind; `firstFreeAddress`; `ensureNATAddress`'s
allocation; `FloatingIP.spec.poolRef`; `VPCGateway.spec.poolRef`; the `attach` verb.

**Replaced, not dropped — the pool's second job.** Pools also told the agent *which
L2 links every node must serve*: `ensurePoolUplinks` attached `from_uplink` to the
link covering each pool CIDR on every node, because an LB frontend or NAT reply
arrives wherever the fabric attracts it — including nodes hosting no floating
target (found live: a MetalLB-announced LB IP black-holed on a node with no local
attach trigger). With pools gone, the trigger derives from the **addresses that
actually exist**, each ensured on every node via the FIB (`EnsureFloatingUplink`):
floating addresses (`watchFloatingIPs`, already), VPC NAT identities
(`watchVPCGateways`), and LB `status.loadBalancer.ingress` IPs (a Services watch).
Strictly better than pools: exactly the links carrying real addresses, no CIDR
list to keep in sync.

**Unchanged — this is the tell that the boundary is right:** the eBPF datapath. `floating`,
`floating_forward`, `floating_egress_snat`, `vpc_nat`, `vpc_nat_snat{,6}`,
`vpc_nat_reverse{,6}` all key on an address that arrives from somewhere and never cared
who picked it. This is an API and control-plane change with **zero** datapath change.

## 10. Non-goals (cozyplane's hard boundaries)

- cozyplane **allocates** no address (the allocator does).
- cozyplane **attracts** no address (the allocator/fabric does).
- cozyplane **reserves** no address (the claim layer does).
- cozyplane **shares** no address across two Services (one owned Service per
  address; the driver's one-claim-one-workload rule guards the reserved case).
- cozyplane **knows no backend** (MetalLB vs cloud vs anything is behind
  `loadBalancerClass` and the claim).

cozyplane's job is a datapath keyed on an address it was handed. Nothing more.

## 11. Increments

0. **[done] kpr honours `service-proxy-name`** ([public-ip.md](public-ip.md) increment
   0). The enabling primitive — proxies skip a delegated Service.
1. **[done, dev4-validated] FloatingIP → owned Service (+ synthesized EndpointSlice).** The
   controller renders + owns a selectorless `service-proxy-name: cozyplane`
   `type: LoadBalancer` Service (`generateName: <fip>-`, `etp: Cluster`, node-ports
   off), reads `status.loadBalancer.ingress` into `status.address`, and gates Ready
   on {Service exists, address assigned, target Port live, target exclusive}. The
   agent still programs the datapath from `status.address`; `spec.poolRef`/`address`
   are deprecated/ignored (kept until ExternalPool is deleted). Dynamic only — no
   claim yet.
   Because the Service is selectorless, cozyplane also synthesizes its single
   EndpointSlice: **verified on dev4, MetalLB advertises a LoadBalancer address only
   while the Service has a ready endpoint** (a backend-less Service is allocated an
   IP but never ARP-answered). The endpoint's address is the target tenant IP, its
   `nodeName` is the target's node (so a later `etp: Local` can pin advertisement
   there for source-IP preservation), and its `Ready` condition tracks the live
   Port — so advertisement follows liveness (held-but-dark when the target is gone),
   matching the datapath. Delivery is still the eBPF datapath, never this endpoint
   (every proxy skips the Service via `service-proxy-name`).
   *dev4 e2e:* a MetalLB pool on the node VLAN + a FloatingIP on a VPC pod →
   `status.address` gets the VLAN IP, MetalLB ARP-answers it, and a genuinely
   external host on the VLAN (an OCI VM, not a cluster node) reaches the pod
   through it (`from_uplink` DNAT + overlay + reverse SNAT). Inbound and its
   replies work end-to-end; pod-*initiated* egress-as-floating still needs a
   VPCGateway on the VPC (unchanged by this increment).
2. **[done, dev4-validated] VPCGateway NAT identity → owned Service(s).** The gateway owns one
   `service-proxy-name: cozyplane` `type: LoadBalancer` Service **per family** its VPC has
   (`ipFamilies: [IPv4]`/`[IPv6]`, `SingleStack`, `etp: Cluster`, node-ports off), reads
   each `status.loadBalancer.ingress` into `status.natAddress`/`natAddress6`, and
   synthesizes a self-addressed ready EndpointSlice per Service so MetalLB advertises
   (§5 — `etp: Cluster` is not exempt from the ready-endpoint rule). The pod reconciler
   and agent are unchanged (they still read `status.natAddress{,6}`), so the #15 pod
   fallback holds: a family with no assigned address keeps the gateway pod.
   `spec.poolRef` deprecated/ignored; the cross-resource used-address de-dup retires
   (MetalLB owns allocation, one Service per address).
   *dev4 e2e:* a NAT-enabled VPCGateway drew `natAddress` from its owned Service; a VPC
   pod egressing to an on-VLAN host was seen as that address (SNAT), and the reply
   round-tripped (HTTP 200) — the self-addressed EndpointSlice made MetalLB advertise
   it, so `vpc_nat_reverse` could un-NAT the return.
3. **[done] Delete `ExternalPool`** + the allocator. The kind, its aggregated
   storage, the `attach` verb, and both deprecated `poolRef` fields are gone; the
   pool's uplink-attach job moved to the addresses that exist (§9); the e2e floating
   phases play the allocator by patching the owned Service's LB ingress.
4. **[done, dev4-validated] Reservation (`addressClaimName`)** — against the
   implemented address-controller (§7): `FloatingIP.spec.addressClaimName` and
   `VPCGateway.spec.nat.addressClaimName{,6}` are copied into the association
   annotation on the owned Service(s); the driver pins, cozyplane consumes the
   ingress unchanged. A pure pass-through — additive, opaque, and fully functional
   with the mechanism absent (no claim ⇒ auto-assign).
   *dev4 e2e, full stack (address-controller + metallb-iad + MetalLB + cozyplane):*
   a claim bound a reserved address from an `IPAddressClass` range; a FloatingIP
   naming it went Ready with exactly that address and an external VLAN host reached
   the pod through it; deleting the FloatingIP left the claim `Bound` (reserved,
   inert — zero cozyplane leftovers) and a recreated FloatingIP got the **same**
   address back, reachable again — the AWS-EIP round trip. Found and fixed in the
   process: `DelFloating` clobbered the egress entry of a reassigned live target
   (the claim handoff's transient auto-assign → pin move exposed it).
