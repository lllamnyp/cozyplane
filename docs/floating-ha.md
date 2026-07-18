# Floating IPs — separating attraction from delivery

A floating IP (an **EIP**) is a routable public address mapped 1:1 onto a pod's
`{net, VPC IP}`, with the external client's source preserved in both directions and
no gateway pod in the path (`internals.md` § floating IPs). It draws from its VPC's
`VPCGateway`'s pool, so a VPC with no boundary gets no external address at all
([north-south.md](north-south.md)).

This document is the record of one change, and it is worth keeping because the
change is not obvious in hindsight: **attraction and delivery used to be the same
decision.** Taking them apart is what let cozyplane stop announcing altogether.

> **Status.** The delivery decoupling (§4) shipped and is what the datapath does
> today. The *attraction* layer described in §5–§6 was built alongside it and then
> **deleted** — cozyplane attracts nothing. §2 and §3 are history, kept for the
> reasoning; §7–§9 are current.

---

## 1. The weld

Three facts, and they were all the same fact:

- **The agent programmed the `floating` map only on the node hosting the target
  Port.** No other node had the mapping at all.
- **The ARP/NDP responder answered only if the target pod was local** — `floating_arp`
  looked the address up and then demanded `local_of(fe->net, fe->vpc_ip)`.
- **The inbound datapath had no remote arm.** On a `floating` hit with no local pod,
  `from_uplink` gave up: *"advertised here but the pod moved: leave it to the kernel."*

Hence the design note that used to close `datapath/floating.go`: *"Programming the
map is the advertisement."* That identity is what had to break.

## 2. What the weld cost (history)

**Live migration hung off one unacknowledged broadcast.** A VM with a public address
migrated; the external switch learned the new location from exactly one gratuitous
ARP, never repeated, never acknowledged. Lose that frame and the address black-holed
until the peer's ARP cache aged out — minutes, on a feature whose entire promise is a
sub-second cutover with the address preserved. A *correctness* problem, not an ops
nicety.

**The pod's node had to sit on the external L2** — an undeclared scheduling
constraint no scheduler knew about. **No spreading**: every byte entered through one
node's uplink. **No failure independence**: announcement could only live where the
pod lived.

## 3. The model

| role | who | what it does |
|------|-----|--------------|
| **attractor** | **the platform** — a CCM assigning the address to a VNIC, MetalLB, a static route, or simply an address configured on a node | gets the packets to *some* node. Not cozyplane's job (north-south tenet 3) |
| **host** | the node with the target pod | receives the packet, DNATs public→VPC, delivers into the veth |
| **egress** | the host, again | sources the replies *as the floating IP*, straight out its own uplink |

Delivery is a property of the *pod* and follows it around the cluster. Attraction is
a property of the *address*, and belongs to whoever owns the fabric. Because the two
are now independent, a migration is invisible to the external network: **the address
does not move, and no L2 claim is made at all.**

## 4. The datapath (as built)

The machinery mostly existed; this was a rewiring, not a new subsystem.

### 4.1 `floating` is programmed on every node

Not just the pod's node. Cluster-wide, `publicIP → {net, vpcIP}` — it says where an
address *leads*, not who owns it. This is the precondition for everything else: a
node that receives a packet for an address it does not host must still be able to
resolve it.

### 4.2 Delivery: the remote arm in `from_uplink`

The `floating` value is a `bridge_ep{net, vpc_ip}` — precisely the key `remote_of()`
takes — so the hosting node is one lookup away:

```c
struct bridge_ep *fe = float_of(d128);
if (fe) {
        struct endpoint *l = local_of(fe->net, fe->vpc_ip);
        if (l)
                return deliver_local(skb, l);          // the pod is here
        __u32 *node = remote_of(fe->net, fe->vpc_ip);  // the pod's node
        if (node)
                return encap(skb, fe->net, *node, 0);  // Geneve, VNI = the VPC
        return TC_ACT_OK;                              // target gone
}
```

The inner packet crosses **verbatim** — public destination intact, client source
intact. Both families have the arm.

**This is the piece that makes platform-side attraction possible at all.** Because
`from_uplink` runs at tc ingress, *ahead of the kernel's routing decision*, it does
not matter how the address was attracted or which node it landed on: whichever node
sees the packet finds the pod and reaches it.

### 4.3 Delivery: the floating probe in `from_overlay`

This is the part that does *not* work by accident. A Geneve packet arriving with
`VNI = net` and a **public** inner destination misses `local_of(vni, p.dst)` (the
`locals` map is keyed by VPC IP) and then falls into the `gateways[vni]` lookup — so
on a node hosting that VPC's gateway pod it would be **delivered into the gateway
pod**. Not a drop: a mis-delivery.

So `from_overlay`'s VPC branch carries a floating probe, after the ordinary local-pod
lookup and its SG gate (a floating packet carries no identity TLV and must not be
judged as east-west traffic) and **before** the `gateways` lookup:

```c
struct bridge_ep *fe = float_of(p.dst);
if (fe && fe->net == vni) {
        struct endpoint *l = local_of(fe->net, fe->vpc_ip);
        if (l)
                return deliver_local(skb, l);
}
```

From there nothing new happens: the packet lands on the veth with the public
destination still on it, and `to_pod`'s floating path (`float_of` →
`floating_forward`) DNATs public→VPC and applies the north-south SecurityGroup gate
exactly as for a packet from the local uplink. **`to_pod` keys on the destination and
has no notion of provenance** — which is what makes the whole design cheap.

### 4.4 The reply: already correct

The reply needs **no new code**. It leaves the pod, hits `from_pod`, and
`floating_egress_snat` rewrites the source to the public address and redirects it out
that node's own uplink — statelessly, with the client as the destination. The reply
goes **direct to the client**, never touching whoever attracted the address.

That is DSR: the attractor carries only the (small) request half of each flow, while
the (large) response half leaves from the hosting nodes.

## 5. Attraction was an election — and then it wasn't

Built (2026-07-13), then **deleted** (2026-07-14). It is recorded because the
deletion is the point, not because the mechanism is worth reviving.

The elected-announcer design was sound on its own terms: eligibility published per
node from the FIB, the announcer chosen by **rendezvous (highest-random-weight)
hash** of `{node name, address}` so every agent reached the same verdict with no
coordination — no Lease, no leader. A `float_announce` map, present only on the
winner, was the sole ARP/NDP gate, and the winner emitted a spaced GARP/NA burst
(RFC 5227's shape) when it newly *won* an address.

**It was MetalLB's L2 mode, reimplemented inside a CNI.** A CNI has no business
attracting traffic; attraction is a fabric concern, and every fabric already has an
answer for it. So `float_announce`, `floating_arp`, `floating_ndp`, `AnnounceAddress`,
the election, the node eligibility annotation, the `--floating-ha` flag and
the pool's `advertisement` field are all gone (as, later, is `ExternalPool`
itself — [external-addresses.md](external-addresses.md) §9).

**BGP — the natural next step from an elected announcer — is rejected, not deferred**
([north-south.md](north-south.md) §6). The practical tell came first: it could not be
validated on a real cluster at all, so it would have been provable only against a
synthetic FRR fabric on kind — and needing a fake fabric to believe your own feature
is the design telling you the feature is in the wrong process.

What survives is §4. That was always the valuable half.

## 6. What the underlay must permit

The host node sources replies as the floating IP out of its own uplink, and it is
generally *not* the node the address was attracted to. A fabric enforcing strict IP
source guard or dynamic ARP inspection will drop those replies.

This is not a new requirement: it is exactly the property `etp: Cluster` DSR already
needs ([lb-ingress.md](lb-ingress.md): *"the fleet-wide LB-IP spoof permission it
needs is an underlay property"*), and it is validated on a real cluster — the
asymmetric client/attractor/backend triangle over an OCI VLAN. The agent configures
every node to serve the link carrying every address that actually exists — floating
addresses, NAT identities, LB ingress IPs — for precisely this reason
([external-addresses.md](external-addresses.md) §9).

Where the underlay refuses, the honest answer is to attract the address **onto the
pod's own node** (a static assignment), which collapses §4's remote arm into the
local one and costs nothing.

## 7. Known cost: the inbound MTU  — OPEN

The request half is Geneve-encapsulated between the attracting node and the host, so
an external client's full-MTU packet exceeds the underlay MTU by the tunnel overhead.
On a v4 underlay the outer packet is fragmented and reassembled by the receiving
node's IP stack — it works, at a cost, and only for the *inbound* half (pod→client
replies are un-encapsulated and bounded by the veth's overlay MTU, so they never
fragment).

The clean fix is to clamp the TCP MSS in the inbound SYN at the encapsulating node —
the standard load-balancer trick, and we see every SYN. Deliberately not done yet:
the `etp: Cluster` DSR path carries the identical exposure, so this wants solving
**once for both**, not twice. Tracked in the roadmap as such.

## 8. One target, one address

A floating IP is a **bijection**, and only its forward half is keyed by the public
address. The reverse half — `floating_egress`, which SNATs the pod's replies — is
keyed by the target's `{net, VPC IP}` **alone**. So two FloatingIPs bound to one
target do not coexist: the second overwrites the first's egress entry, and the first
address starts answering *from the second address*. A client that dialled the first
gets a SYN-ACK from an address it never contacted, drops it, and the first floating
IP is silently dead.

Nothing in the datapath can see this — the map simply holds whatever was written
last. It is refused in the controller instead: the oldest binding owns the target
(ties broken by name, so every controller replica agrees), and any later one stays
`Pending` with `TargetExclusive=False` rather than being allocated an address it
would only use to break its predecessor. Deleting the winner frees the target, and
the loser is re-queued and takes it.

This predates the decoupling — the reverse map was always keyed this way — and it
surfaced only because the e2e (wrongly) pointed four addresses at one pod.

## 9. Non-goals

- **Attracting anything.** Cozyplane delivers; the platform attracts. See §5.
- **Surviving the host node's death.** If the pod's node dies, the pod dies with it,
  and the address is dark until the pod is rescheduled — at which point delivery
  re-points and the address never moved. This is about decoupling, not about
  resurrecting a dead pod.
- **Delivering to an address with no live target.** An address whose target Port is
  not live anywhere leads nowhere, as before.
