# North-south — one boundary

How traffic crosses between a tenant VPC and everything outside it: the internet,
the platform, and clients on the fabric. This document exists because cozyplane
grew *three* ways to do that, independently, and none of them is the boundary a
cloud actually needs.

It supersedes the north-south halves of [floating-ha.md](floating-ha.md) and
[lb-ingress.md](lb-ingress.md), and it re-parents `FloatingIP`.

---

## 1. The problem: three doors, no doorway

| door | who NATs | where policy lives | counted? | tenant identity? |
|------|----------|--------------------|----------|------------------|
| **VPC egress gateway** (a real pod, per VPC) | the gateway netns | gateway firewall | no | **no** — laundered into the node's address |
| **FloatingIP** (eBPF bijection) | `from_pod` / `to_pod` | `ns_sg_admit` / `ns_egress_ok` | no | yes (the public address) |
| **LoadBalancer ingress** (eBPF DNAT) | `from_uplink` / `lb_return` | SG check at the DNAT point | no | n/a (ingress) |

Three mechanisms, each re-implementing NAT, each re-implementing policy, sharing
no chokepoint. The consequences are not theoretical:

**The gateway is bypassed by design.** `floating_egress_snat` runs in `from_pod`
*before* the isolation branch — the comment says so outright: checked "before
isolation, which would otherwise send it to the gateway or drop it." A floating
pod's internet-bound traffic never touches its VPC's gateway. Only its
*cluster-internal* traffic falls through to it (via the `internal` LPM). The
gateway is not the VPC's door; it is one of three, and the one most easily
avoided.

**Nothing north-south is metered.** The per-VPC counters exist, but they are wired
into `from_pod`/`to_pod` for **east-west** only; north-south metering is still an
open follow-up on [#2](../../issues/2). So a tenant can pull terabytes through the
platform's uplink over a floating IP or a LoadBalancer Service and cozyplane
cannot say that it happened. In a real cloud that traffic crosses your IGW or your
NAT gateway, and it lands on your bill. Ours crosses nothing.

**Tenant egress wears the platform's identity.** A VPC pod egressing through its
gateway is SNATed to the gateway pod's fabric address — and then the *cluster*
egress masquerade rewrites it again, to the **node's** address. Tenant traffic
leaves the cluster indistinguishable from the platform's own. (The floating path is
the sole exception: it is the only egress today that carries an address the tenant
owns. That is a clue about which primitive is worth keeping.)

**A LoadBalancer Service into a VPC is a free ride.** It is attracted by the
platform, delivered by the platform's uplink hook, and DNATed straight to a VPC
pod — right past the tenant's own networking. From the client's side this is
correct and invisible, which is exactly why it is easy to miss that the tenant's
stack was never involved.

## 2. Tenets

1. **The gateway is a boundary, not a hop.** Packets are not detoured through a
   box. Enforcement stays where it is — in the four eBPF hooks — and the gateway is
   where the boundary is *declared*, *policed*, *named* (the NAT identity) and
   *counted*. Routing tenant north-south through a gateway pod would throw away
   source preservation, the DSR reply, and the conntrack-free fast path, and would
   hand every VPC a single point of failure. Cloud IGWs are not boxes you hairpin
   through either.

2. **One boundary per VPC, and everything crosses it.** Every packet moving between
   a VPC and the outside crosses that VPC's gateway *conceptually*, whatever
   mechanism carries it. One place for policy, one place for the NAT identity, one
   place for the counters. Three doors collapse into one doorway with three
   mechanisms behind it.

3. **The CNI does not announce.** *Attraction* — making the fabric deliver an
   external address to some node — belongs to the platform: a CCM, MetalLB, a
   static route, an OCI secondary VNIC address. Cozyplane consumes the address and
   **delivers** it. This is already what `lb-ingress.md` says for LoadBalancer IPs;
   it now holds for every external address. Corollaries: no BGP speaker, no ARP/NDP
   responder, no gratuitous ARP in the datapath.

4. **Ingress is `Service type: LoadBalancer`.** Reuse the Kubernetes primitive
   rather than inventing a second ingress object. It already works, it is already
   the shape the ecosystem announces for, and cozyplane already does the right
   thing with it on the default network.

5. **Egress identity is the one thing Kubernetes cannot express — that is what an
   EIP is.** A Service is an *ingress* object; nothing upstream says "this VM
   egresses as `203.0.113.7`." So a 1:1 public address bound to a Port survives —
   as an **EIP owned by the VPC's gateway**, not as a self-announcing mini-LB. This
   is precisely AWS's EIP, and it is what a `FloatingIP` was always actually for.

6. **If a path cannot be counted, it is not a sanctioned path.** Metering is not a
   feature bolted on later; it is the test of whether the boundary is real. Every
   north-south crossing is attributable to exactly one VPC, by construction.

7. **Nothing crosses by default.** A VPC with no gateway has no internet. A
   LoadBalancer Service pointed at VPC backends does not silently open a door —
   ingress to a VPC is something the VPC's boundary admits. (Default-deny is
   already the SecurityGroup stance; the gateway makes it the VPC's stance.)

8. **Tenant traffic never wears the platform's identity.** A VPC pod's egress
   carries the *VPC's* NAT address, not the node's. The cluster-egress masquerade
   is for default-network pods; it must not be the thing that carries a tenant to
   the internet.

## 3. The model

**`VPCGateway`** (a namespaced kind — built) declares the VPC's
north-south boundary: whether the VPC may reach the internet at all, which
`ExternalPool` its NAT identity is drawn from, the egress policy, and the counters
every crossing increments. Behind that one declaration sit three mechanisms:

**NAT gateway — many-to-one egress.** A VPC's pods reach the internet SNATed to an
address the *VPC* owns, drawn from its pool. This should be **eBPF at the uplink**,
with a per-VPC address and port pool, connection-tracked in the datapath's own
tables — exactly the shape the node masquerade already has (ports 16384–29999,
disjoint from host-ephemeral and NodePort). That retires the per-VPC **gateway
pod**: no hairpin, no SPOF, no netns firewall, and the tenant finally has an egress
identity of its own.

**EIP — one-to-one, pinned.** Today's `FloatingIP`, kept and re-parented: the eBPF
bijection stays (it works, it is fast, it preserves the client), but the address is
an address *on the gateway*, associated with a Port, and it is attracted by the
platform rather than announced by us.

**Ingress — `Service type: LoadBalancer`.** The platform attracts the LB address;
cozyplane delivers it to the backends, including VPC backends, gated and counted at
the boundary rather than waved through.

## 4. What this retires

- **The floating-IP announcement layer.** `float_announce`, `floating_arp`,
  `floating_ndp`, `AnnounceAddress`, and the announcer election — a MetalLB L2
  implementation living inside a CNI. Tenet 3 deletes all of it.
- **The per-VPC gateway pod**, replaced by eBPF SNAT with a per-VPC identity.
- **`ExternalPool.spec.advertisement`** (`L2 | BGP`) — presently dead code, read by
  nothing. Under tenet 3 it never becomes live. Delete the field.
- **`FloatingIP` as a top-level, self-sufficient object** — it becomes an EIP under
  a gateway.

## 5. What survives from the floating-HA work

The **delivery** decoupling, and it is load-bearing here. Until it landed, only the
node hosting the pod could receive a floating packet — an external announcer that
picked any other node would have black-holed the traffic. Now *any* node can receive
an external address and get it to the pod (locally, or encapsulated to the pod's
node), and the reply leaves the pod's own node directly. **That is the precondition
for letting someone else do the announcing**, which is what tenet 3 requires.

The attraction layer built alongside it — the election, the GARP burst, the ARP/NDP
responders — is the part that goes. It was a better version of something that should
not be in a CNI.

## 6. Rejected, with reasons (so they are not re-litigated)

- **A BGP speaker in cozyplane.** A CNI has no business holding routing sessions
  with the fabric. The tell was practical before it was philosophical: it could not
  be validated on the real cluster at all (OCI gives compute instances no BGP peer;
  port 179 is closed on both gateways), so it would have been provable only on kind
  — and needing a synthetic fabric to believe your own feature is the design telling
  you the feature is in the wrong process.
- **L2 announcement in cozyplane** (what we have today) — same reason, arrived at
  from the other end. It works, which is why it survived this long.
- **Hairpinning north-south through a gateway pod** — tenet 1.

## 7. Open questions

- **Where does the gateway's DNS door go?** The gateway pod opens `:53` to cluster
  DNS so tenant pods resolve with a stock `resolv.conf`. The split-horizon resolver
  (`dns_steer` + the per-node responder) already serves VPC pods. Is the gateway's
  DNS proxy now vestigial? Probably — verify before deleting.
- **Who attracts an EIP, concretely?** MetalLB and CCMs announce *Service* LB
  addresses; neither has a concept of "advertise this address because a cozyplane
  object says so." On OCI the right primitive is a **secondary private IP on a
  node's VNIC**, which is a CCM's job. On a bare-metal L2 fabric there may be no
  announcer at all — in which case the honest answer is a static route, not a CNI
  that pretends to be a router.
- **Does an EIP's ingress half survive at all**, or does `Service type: LB` cover
  every ingress case and leave the EIP a pure *egress identity*? (AWS's EIP is
  bidirectional; ours could be egress-only, which is simpler and cedes more to the
  k8s primitive.)
- **Per-VPC NAT port-pool sizing and exhaustion** — the node masquerade's pool is
  shared; a per-VPC pool needs its own accounting and a story for what happens when
  a tenant exhausts it.
- **Metering shape** — per-VPC byte/packet counters at the boundary, split by
  direction and by mechanism (NAT-GW / EIP / LB), closing [#2](../../issues/2)'s
  north-south half.

## 8. Sketch of the increments

Not a commitment; the order the pieces actually depend on each other.

0. **Meter the existing doors — DONE 2026-07-13.** Before changing anything, count
   what crosses. `vpc_counters` gained `ns_packets[door][in]` / `ns_bytes[door][in]`,
   and the agent serves `cozyplane_vpc_ns_{bytes,packets}_total{vni,vpc,node,door,direction}`.
   Every door is counted at the point where the packet demonstrably crosses:

   | door | out | in |
   |------|-----|-----|
   | gateway | `from_pod`, at the branch that hands the packet to the VPC's gateway | `from_pod`, the gateway pod handing traffic back into its own VPC |
   | eip | `floating_egress_snat` (v4+v6), after the SNAT to the tenant's address | `floating_forward` (v4+v6), after the DNAT to the pod |
   | loadbalancer | `lb_return`, a VPC backend answering as the frontend | `lb_ingress`, where the backend resolves to a VPC pod |

   **The constraint that had kept north-south unmetered:** every door's *egress*
   leaves through `from_pod`, which hosts **no BPF-to-BPF callee at all** (its frame
   is ~496 of the 512-byte combined-stack limit — the very reason `count_dir` lives
   in `to_pod`). So `count_ns` is `__always_inline`, placed only on the narrow
   terminal paths, keeping the verifier's path exploration cheap. It loads on both
   6.8 and 6.12.

   Dev-cluster measurement, one VPC, each door driven in turn (bytes):

   ```
   door          out        in
   gateway       4555      6070
   eip           4734      3771
   loadbalancer   290       560
   ```

   **A finding from driving it:** an *in-cluster* client (a hostNetwork pod) dialling
   a VPC pod's LoadBalancer IP never crosses the LB door at all — cozyplane-kpr's
   socket-LB rewrites its `connect()` straight to the backend, so the packet never
   reaches `from_uplink`. It takes the fabric bridge instead. Only a genuinely
   external client crosses the LB door, which is the right semantics — but it means
   the door's traffic can only be exercised with a socket-LB-bypassing raw SYN, and
   that anyone reasoning about "who can reach a VPC pod" must remember the socket-LB
   shortcut exists.
1. **`VPCGateway`: the boundary object — DONE 2026-07-13.** A namespaced kind
   naming its VPC and an `ExternalPool`, with `nat.enabled` and
   `ingress.loadBalancer`. Creating one requires the **`attach` verb on the pool** —
   the same escalation gate as `VPCBinding`'s `export` and `VPCPeering`'s `peer`,
   enforced in the aggregated registry. That closes a real hole: `VPC.spec.egress.
   natGateway` was a **bool on an object the tenant owns**, so a tenant granted
   *itself* internet. The field is deleted.

   A VPC has exactly one boundary — the **oldest** gateway (`EffectiveGateway`),
   which lives in the API package precisely because three things must agree on it
   without coordinating: the controller that realizes the gateway pod, the CNI that
   gives that pod its VPC leg, and the agent that opens the ingress gate.

   **Dev-cluster-validated (deny-then-admit):** with no gateway, 4 raw SYNs to a
   LoadBalancer IP whose backend is a VPC pod are refused (4 denied, 0 crossed);
   with a gateway that declines LB ingress, 4 more are refused (8 denied, still 0
   crossed); the moment the gateway admits, the *same unchanged Service* delivers
   (7 crossed, no new refusals) and an HTTP request returns 200.

   **Tenet 7 is now enforced, not aspirational:** `vpc_ingress[net]` is programmed
   only for a VPC whose gateway admits LoadBalancer traffic, and `lb_ingress` drops
   otherwise. An LB Service naming a VPC pod as its backend previously got a free
   ride — attracted by the platform, delivered by the platform's uplink hook, the
   tenant's networking never consulted. Refusals are counted separately from
   crossings (`ns_denied[door]`): a refused packet did **not** cross, so folding it
   into the byte meter would corrupt the one number the boundary exists to produce.

   Still deliberately absent: the per-VPC NAT **identity**. The gateway declares the
   door; egress still launders into the node's address until increment 2. Better to
   sequence that honestly than to ship a field the datapath ignores.
2. **NAT gateway in eBPF, per-VPC identity.** Retire the gateway pod.

   **Why the gateway pod exists at all** — worth stating, because it dictates the
   design. `masq_snat` (the cluster-egress masquerade) identifies a default-network
   pod by its *address* (`is_masq_src`), at the uplink. **That is impossible for a
   VPC**: tenant CIDRs overlap by design, so a source address at the uplink names no
   one. The tenant is knowable only at the **pod's veth**, where `ports[ifindex]`
   gives the net. The gateway pod is, in essence, a place to stand where identity is
   still known. Take it away and the SNAT has to happen at the veth.

   Which forces the real question: **the connection state then lives on the pod's
   node, but the reply comes back to whichever node attracts the NAT address.**
   Three ways out:

   - **Elect one egress node per VPC** and steer the VPC's egress to it (Cilium's
     egress-gateway shape). Simple, and the reply lands where the state is — but it
     is a *hop*, and tenet 1 says the gateway is a boundary, not a hop. It would
     re-introduce the hairpin and the per-VPC single point of failure we are
     retiring. **Rejected by our own tenet.**
   - **One NAT address per (VPC, node)**: replies land naturally on the right node,
     no demux. Costs N addresses per VPC — too expensive for a pool.
   - **One address per VPC, port ranges partitioned per node** (chosen). Each node
     SNATs its own pods to the VPC's single address, drawing ports from *its own*
     shard. The attractor demuxes a reply by port → owning node and forwards it over
     the overlay; the owning node reverses from its own `ct_rev`. Egress stays
     distributed (DVR), the VPC keeps one identity, and the boundary stays a
     boundary. Cost: the shard map, and a node-set change reshuffles ranges and
     breaks live flows — acceptable, and recorded.

   **Datapath**, reusing what exists rather than inventing:

   - `vpc_nat`: `net -> {nat_ip, port_base, port_span}` — *this node's* shard.
   - `nat_owner`: `{nat_ip, shard} -> node_ip` — for the attractor's demux.
   - `nat_of`: `nat_ip -> net` — so the attractor knows the tenant.
   - **Egress** (`from_pod`, pod veth, `srcnet && !dstnet`, after the EIP path
     misses): drop cluster-internal (`is_internal` — the tenant→system boundary the
     gateway's netns firewall enforced today), apply `ns_egress_ok` (the SG gate,
     exactly as the gateway path does), then allocate a port from this node's shard
     and SNAT with the **same `ct_fwd`/`ct_rev` machinery `masq_snat` already uses**
     — it is the same problem with `net` set and a per-VPC address instead of the
     node's. Keys go in **per-CPU scratch**, not on the stack: `from_pod` is at ~496
     of its 512-byte budget.
   - **Reply** (`from_uplink`): `nat_of(dst)` gives the tenant; the port's shard
     gives the owning node. Local → reverse from `ct_rev` and deliver. Remote →
     Geneve to that node, where a probe in `from_overlay`'s VPC branch reverses and
     delivers — the same shape as the floating probe.

   **What this buys:** a VPC's traffic finally leaves the cluster wearing *its own*
   address (tenet 8 — today it is SNATed to the gateway pod's fabric IP and then
   re-SNATed by the cluster masquerade to the **node's**, so tenants are
   indistinguishable from the platform on the wire), and `poolRef` and the `attach`
   verb become load-bearing rather than decorative. It also deletes the last netns
   firewall in the tree.

   **To verify first:** the gateway pod also proxies cluster DNS on `:53` (the one
   sanctioned internal door). The split-horizon resolver (`dns_steer` + the per-node
   responder) already serves VPC pods, so that door is probably vestigial — confirm
   before deleting it, or tenant DNS breaks with the pod.
3. **EIP re-parented onto the gateway**; delete the announcement layer, and with it
   `ExternalPool.spec.advertisement`.
4. **LoadBalancer ingress into a VPC crosses the boundary** — admitted and counted,
   not waved through.
