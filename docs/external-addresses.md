# External addresses — cozyplane sources none of them

**Status: DESIGN — not implemented.** Supersedes [north-south.md](north-south.md) §9,
unifies with [public-ip.md](public-ip.md), and defines the contract the platform's
address-reservation work (`IPAddressClaim`, cozystack/community#35) builds against.

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
a *reserved* address (§7) is delegated through an opaque claim reference, never a
provider annotation cozyplane writes. **cozyplane's entire outward surface is: create
a generic LB Service, read one status field.**

## 4. FloatingIP — an EIP, sourced by a Service it owns

`FloatingIP` survives as the tenant-facing **binding + datapath** object. `spec.poolRef`
and `spec.address` are removed; an optional `addressClaimRef` (§7) replaces them.

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: web-eip, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  target: 10.90.0.5                  # the VPC IP / Port this fronts
  loadBalancerClass: metallb         # optional; which allocator
  addressClaimRef: {name: my-eip}    # optional; empty ⇒ dynamic (§7)
status:
  address: 203.0.113.7               # read back from the owned Service
  serviceRef: {name: web-eip-x7k2}   # the owned Service (generateName)
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

1. **Backend-less ⇒ `etp: Cluster`.** There is no single target to hang an EndpointSlice
   on — the replies fan out by port shard across nodes. So its Service announces
   **unconditionally** from the speaker (`etp: Cluster`), and cozyplane demuxes: the
   reply lands on whichever node attracts the address, `from_uplink` there runs
   `vpc_nat_reverse`, the port's shard names the owning node, and the packet is
   forwarded over the overlay to it. This is exactly what `vpc_nat_reverse` already
   does — "the reply arrives at whichever node attracts the address; the port says who
   owns the flow." So a backend-less `etp: Cluster` Service on the speaker node is
   sufficient, and the reply path is unchanged.
2. **Prefers reservation.** A VPC's egress identity churning under live flows is bad,
   so the NAT identity is the strong candidate for a **claim** (§7) rather than a
   dynamic address. That is a preference for stability, satisfied by the claim layer —
   not a structural difference.

The `VPCGateway` owns this Service the way a FloatingIP owns its own; `spec.poolRef`
becomes an `addressClaimRef`, and `status.natAddress` / `natAddress6` are read back
from the Service (or claim), not allocated.

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

## 7. Reservation — the claim layer, and the one-Service invariant

`IPAddressClaim` (cozystack/community#35) is the **reservation** layer, orthogonal to
attraction and strictly optional. Its whole interaction with cozyplane is one spec
field (`FloatingIP.spec.addressClaimRef`) and one status value
(`IPAddressClaim.status.address`).

**The invariant that makes this safe: at most one Service per address, ever.** Two
Services claiming one IP is IP-sharing, which MetalLB permits only conditionally
(`metallb.io/allow-shared-ip` + matching ports) and other allocators refuse. So the
reservation is **never** "a dummy Service holding the IP plus a second Service trying
to use it." Instead:

- **Dynamic (no `addressClaimRef`):** the FloatingIP/VPCGateway owns its one ephemeral
  Service. The address lives for the **object's** lifetime; deleting it releases the
  address.
- **Reserved (`addressClaimRef` set):** the **claim** owns the one thing that holds the
  address, and *how* it holds it is the claim's backend-specific private business that
  cozyplane never sees:
  - **bare metal (MetalLB):** a single backend-less Service (there is no non-Service
    reservation on MetalLB); `etp: Cluster` keeps it announced, or — on a fabric that
    won't allow that — the address is reserved but off the wire until bound, which is
    correct (an unassociated EIP routes nowhere).
  - **cloud:** a native reserved address (an EIP), no Service at all.
  A FloatingIP binding a claim does **not** mint a second Service. It binds by
  contributing *separate objects* — an **EndpointSlice** at the target's fabric IP
  (which drives `etp: Local` attraction onto the target's node when the fabric needs
  it) and the **datapath** programming. On unbind, cozyplane drops its EndpointSlice
  and datapath; the reservation stays, the address is held. The address lives for the
  **claim's** lifetime and survives the FloatingIP — the AWS-EIP semantics.

So the rule is one line: **whoever holds the longest-lived stake owns the single
Service — the claim if reserved, the object if dynamic — and binding is
add-an-endpoint-plus-datapath, never add-a-Service.**

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

**Unchanged — this is the tell that the boundary is right:** the eBPF datapath. `floating`,
`floating_forward`, `floating_egress_snat`, `vpc_nat`, `vpc_nat_snat{,6}`,
`vpc_nat_reverse{,6}` all key on an address that arrives from somewhere and never cared
who picked it. This is an API and control-plane change with **zero** datapath change.

## 10. Non-goals (cozyplane's hard boundaries)

- cozyplane **allocates** no address (the allocator does).
- cozyplane **attracts** no address (the allocator/fabric does).
- cozyplane **reserves** no address (the claim layer does).
- cozyplane **shares** no address across two Services (the one-Service invariant).
- cozyplane **knows no backend** (MetalLB vs cloud vs anything is behind
  `loadBalancerClass` and the claim).

cozyplane's job is a datapath keyed on an address it was handed. Nothing more.

## 11. Increments

0. **[done] kpr honours `service-proxy-name`** ([public-ip.md](public-ip.md) increment
   0). The enabling primitive — proxies skip a delegated Service.
1. **FloatingIP → owned Service.** The controller renders + owns a
   `service-proxy-name: cozyplane` Service, manages its EndpointSlice, reads
   `status.loadBalancer.ingress`, programs the datapath. `spec.poolRef`/`address`
   removed; dynamic only (no claim yet). Unblocked today.
2. **VPCGateway NAT identity → owned Service.** The same, backend-less + `etp: Cluster`.
3. **Delete `ExternalPool`** + the allocator once nothing draws from it.
4. **Reservation (`addressClaimRef`)** — when `IPAddressClaim` lands: the pin field, the
   claim-owns-the-Service / object-contributes-endpoints binding, the one-Service
   invariant. Additive; nothing above changes.
