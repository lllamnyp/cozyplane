# Floating-IP HA — separating attraction from delivery

A floating IP is cozyplane's public face: a routable address mapped 1:1 onto a
pod's `{net, VPC IP}`, with the external client's source preserved in both
directions and no gateway pod in the path (`internals.md` § floating IPs).

Today one node does everything for a floating address: it attracts the traffic
(answers ARP/NDP for it), it delivers the traffic (the target pod is local), and
it sources the replies. Those three jobs are welded together, and the weld is
what this document takes apart.

---

## 1. What is actually built today

Three facts, and they are all the same fact:

- **The agent programs the `floating` map only on the node hosting the target
  Port.** `desiredFloating` skips every Port whose `spec.node` is not this node
  (`cmd/agent/main.go`), so no other node has the mapping at all.
- **The ARP/NDP responder answers only if the target pod is local.**
  `floating_arp` looks the address up in `floating` and then demands
  `local_of(fe->net, fe->vpc_ip)` — *"not our pod (shouldn't be programmed here
  otherwise)"* (`bpf/overlay.c`). `floating_ndp` is the v6 twin.
- **The inbound datapath has no remote arm.** On a `floating` hit with no local
  pod, `from_uplink` gives up: `if (!l) return TC_ACT_OK;` — *"advertised here
  but the pod moved: leave it to the kernel"*.

Hence the design note that closes `datapath/floating.go`: *"Programming the map
is the advertisement."* That identity is exactly what has to break.

Movement is handled by a single gratuitous ARP / unsolicited NA, emitted once,
best-effort, by the node that newly acquired the address (`datapath/announce.go`,
fired from `watchFloatingIPs` on the `!current[pub]` edge).

## 2. What the coupling costs

**Live migration hangs off one unacknowledged broadcast.** A VM with a public
floating IP migrates; the external switch learns the new location from exactly
one GARP that is never repeated and never acknowledged. Lose that frame and the
address black-holes until the peer's ARP cache ages out — minutes, on a feature
whose entire promise is a sub-second cutover with the address preserved
(`live-migration.md`). This is the sharp edge, and it is a *correctness* problem,
not an ops nicety.

**The pod's node must sit on the external L2.** Only a node that owns the pool's
link can attract the address, so "may host a floating-IP-targeted pod" becomes an
undeclared scheduling constraint that no scheduler knows about.

**No spreading.** Every byte for a floating address enters through one node's
uplink, whatever the fleet looks like.

**No failure independence.** Announcement can only ever live where the pod lives.

## 3. The model

Split the one role into three, and let them land on different nodes:

| role | who | what it does |
|------|-----|--------------|
| **attractor** | the *elected announcer* — any eligible node | answers ARP/NDP for the address, so the fabric sends the packets here |
| **host** | the node with the target pod | receives the packet, DNATs public→VPC, delivers into the veth |
| **egress** | the host, again | sources the replies *as the floating IP*, straight out its own uplink |

Attraction becomes a property of the *address*, decided by an election over
healthy nodes. Delivery stays a property of the *pod*, and follows it around the
cluster. Migration therefore becomes invisible to the external network: the
announcer never moves, and the internal delivery target flips at cutover exactly
as it already does.

## 4. The datapath

The machinery mostly exists; this is a rewiring, not a new subsystem.

### 4.1 Attraction: a new `float_announce` map

The ARP gate moves out of "is the pod local" and into an explicit, per-address
statement of intent:

```c
// float_announce: public IP -> 1, present ONLY on the elected announcer.
struct { ... } float_announce SEC(".maps");   // hash, key addr128, value __u8
```

`floating_arp` / `floating_ndp` consult **`float_announce` alone**. That is one
map lookup where there used to be two (`floating` + `locals`), and it says what
it means: *this node has been elected to attract this address*. A node that is
not the announcer stays silent, exactly as a non-hosting node does today.

The election is a control-plane decision, so no `CFG_*` feature bit is needed:
the datapath's behaviour is fully determined by which node holds the entry.

### 4.2 Delivery: a remote arm in `from_uplink`

`from_uplink`'s floating hit gains the arm it never had. The `floating` value is
a `bridge_ep{net, vpc_ip}` — precisely the key `remote_of()` takes — so the
hosting node is one lookup away:

```c
struct bridge_ep *fe = float_of(d128);
if (fe) {
        struct endpoint *l = local_of(fe->net, fe->vpc_ip);
        if (l)
                return deliver_local(skb, l);          // as today
        __u32 *node = remote_of(fe->net, fe->vpc_ip);  // the pod's node
        if (node)
                return encap(skb, fe->net, *node, 0);  // Geneve, VNI = the VPC
        return TC_ACT_OK;                              // target gone
}
```

`remotes` is already fed per-pod at `scope = VNI` for every non-local Port
(`cmd/agent/main.go`, `SetRemote`), so this resolves on any node. The inner packet
crosses **verbatim**, public destination intact, client source intact. Both
families get the arm (`from_uplink`'s v4 and v6 blocks).

Every node programs the `floating` map now, not just the host — which is what
makes the lookup on the announcer possible in the first place.

### 4.3 Delivery: a floating probe in `from_overlay`

This is the part that does *not* work by accident, and it is worth being explicit
about why. A Geneve packet arriving with `VNI = net` and an inner destination
that is a **public** address misses `local_of(vni, p.dst)` (the `locals` map is
keyed by VPC IP) and then falls into the `gateways[vni]` lookup — so on a node
that happens to host that VPC's gateway pod, **it would be delivered into the
gateway pod**. Not a drop: a mis-delivery.

So `from_overlay`'s VPC branch gains a floating probe, placed after the ordinary
local-pod lookup and its SG gate (a floating packet carries no identity TLV and
must not be judged as east-west traffic) and **before** the `gateways` lookup:

```c
struct bridge_ep *fe = float_of(p.dst);
if (fe && fe->net == vni) {
        struct endpoint *l = local_of(fe->net, fe->vpc_ip);
        if (l)
                return deliver_local(skb, l);
}
```

From there, nothing new happens: the packet lands on the pod's veth with the
public destination still on it, and `to_pod`'s existing floating path
(`float_of` → `floating_forward`) DNATs public→VPC and applies the north-south
SecurityGroup gate (`ns_sg_admit`) exactly as it does for a packet that arrived
from the local uplink. `to_pod` keys on the destination and has no notion of
provenance — which is what makes the whole design cheap.

### 4.4 The reply: already correct

The reply needs **no new code**. It leaves the pod, hits `from_pod`, and
`floating_egress_snat` rewrites the source to the public address and redirects it
out that node's own floating uplink. The host node already sources the floating
IP today — this is the everyday egress path — and it does so statelessly, with
the client's address as the destination. The reply therefore goes **direct to the
client**, never touching the announcer.

That is DSR, and it means the announcer carries only the (small) request half of
each flow while the (large) response half spreads across the hosting nodes.

## 5. Attraction is an election

Each agent independently computes, for every floating address, the same answer:

- **Eligible nodes** are `Ready` nodes that can actually serve the pool's link.
  A node learns its own eligibility from the FIB (the pool address resolves
  on-link) and publishes it as an annotation on its own Node object —
  `cozyplane.io/external-pools` — reusing the mechanism the agent already uses to
  publish `cozyplane.io/node-addresses`.
- **The announcer** is chosen by **rendezvous (highest-random-weight) hash** of
  `{node name, address}`. Deterministic, so every agent reaches the same verdict
  with no coordination; and stable, so losing one node re-homes only the
  addresses that node held, rather than reshuffling the fleet.
- **If no node is eligible** (e.g. a routed pool, where an L2 announcement means
  nothing anyway), it falls back to today's behaviour: the target pod's own node.

No Lease, no leader, no coordination — the same property `lb-ingress.md` insists
on for LoadBalancer IPs (*"No allocator, no announcer, no election, no leader"*),
achieved here by making the election a pure function of state every agent already
watches.

The announcer emits the gratuitous ARP / unsolicited NA when it **newly wins** an
address — not when the pod moves, because under this design the pod moving does
not change who announces.

## 6. What the underlay must permit

The host node sources replies as the floating IP out of its own uplink, and under
HA the host is generally *not* the node whose MAC answered the ARP for that
address. A fabric enforcing strict IP source guard or dynamic ARP inspection will
drop those replies.

This is not a new requirement: it is exactly the property `etp: Cluster` DSR
already needs (`lb-ingress.md`: *"the fleet-wide LB-IP spoof permission it needs
is an underlay property"*), and it is already validated on a real cluster — the
asymmetric client/announcer/backend triangle over an OCI VLAN. The agent already
configures every node to serve every `ExternalPool`'s link for precisely this
reason (`ensurePoolUplinks`).

Where the underlay refuses, `--floating-ha=false` restores the old behaviour by
electing the target pod's own node, and everything downstream is unchanged.

## 7. Known cost: the inbound MTU

The request half is now Geneve-encapsulated between the announcer and the host,
so an external client's full-MTU packet exceeds the underlay MTU by the tunnel
overhead. On a v4 underlay the outer packet is fragmented and reassembled by the
receiving node's IP stack — it works, at a cost, and only for the *inbound* half
(pod→client replies are un-encapsulated and bounded by the veth's overlay MTU, so
they never fragment).

The clean fix is to clamp the TCP MSS in the inbound SYN at the announcer, which
is the standard load-balancer trick and which we are well placed to do — we see
every SYN. It is deliberately **not** in increment 1: the `etp: Cluster` DSR path
carries the identical exposure today, so this wants solving once for both, not
twice. Recorded in the roadmap as such.

## 8. Increments

**Increment 0 — a robust announcement.** `AnnounceAddress` sends one frame, once,
best-effort, and never repeats. Make it a spaced burst, and re-send when a node
newly wins an address. Independently valuable: it is a latent live-migration bug
today, regardless of everything else here.

**Increment 1 — decouple attraction from delivery.** §4 and §5: the
`float_announce` map and the ARP/NDP gate; the remote arm in `from_uplink`; the
floating probe in `from_overlay`; every node programs `floating`; the rendezvous
election in the agent, driven by a Node-informer resync; `--floating-ha` to switch
it off. The reply path is untouched.

**Increment 2 — BGP (not yet).** Once attraction is a standalone statement, "I can
attract this /32" is a thing several nodes can say at once: the fabric ECMPs
across them, BFD withdraws a dead one in milliseconds, and the whole thing works
on a routed fabric with no shared L2 at all. `ExternalPool.spec.advertisement`
already reserves the `L2 | BGP` enum for it (it is presently dead — nothing reads
it). The speaker belongs outside the datapath, as its own component, and it is
out of scope here.

## 9. Non-goals

- **Anycast / multi-node active-active on L2.** ARP resolves to one MAC; one
  announcer per address is the L2 ceiling. Active-active is what increment 2 buys.
- **Surviving the host node's death.** If the pod's node dies, the pod dies with
  it, and the address is dark until the pod is rescheduled — at which point the
  *announcer does not change*, and delivery re-points. HA here is about
  decoupling, not about resurrecting a dead pod.
- **Announcing addresses with no live target.** An address whose target Port is
  not live anywhere is not announced by anyone, as today.
