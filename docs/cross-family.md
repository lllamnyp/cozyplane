# Cross-family connectivity — NAT64 peering & north-south (design draft)

**Status: DRAFT — not implemented.** Covers cross-family VPC peering (a v4 VPC ↔
a v6 VPC) and issue #9 (north-south to a v6 VPC IP via a v4 fabric IP). Both are
the same primitive: **a stateless RFC 6052 translator between the two families**,
which the 128-bit map layout was built to accommodate from step 1.

## Why this is one problem

The datapath already stores every v4 address in **NAT64 form** `64:ff9b::a.b.c.d`
(internals.md §"Addressing"). So *within the maps* there is no family split — a
v4 pod and a v6 pod are both 128-bit keys; a v6 pod addressing a v4 pod as
`64:ff9b::v4` already **matches the stored entry**. What's missing is the packet
translation at the family boundary: a v6 packet must become a v4 packet (and
back) when it crosses from a v6 VPC to a v4 VPC, or from a v4 fabric to a v6 VPC.

RFC 6145 (SIIT — stateless IP/ICMP translation) is exactly this, and it's
stateless because the address carries its own mapping: `v4 ↔ 64:ff9b::v4`. No
connection table, no port allocation — unlike the masquerade/bridge NAT. That
makes it a good fit for the eBPF hooks.

## The translator

A packet needs translation when its source and destination families differ.
Two directions, both stateless:

- **v6 → v4** (a v6 pod sending to a `64:ff9b::v4` destination): build a v4
  header (copy TTL from hop-limit, protocol from next-header, addresses from the
  low 32 bits of each `64:ff9b::` address — both src and dst must be in NAT64
  form, i.e. the *source* v6 VPC pod is representable as v4, see "the
  addressability constraint" below), recompute checksums (v4 has an L3 checksum
  v6 lacks; L4 pseudo-header changes), and deliver as v4.
- **v4 → v6**: the inverse — build a v6 header, `64:ff9b::` both addresses,
  recompute L4 (no L3 csum in v6).

ICMP↔ICMPv6 translation (RFC 6145 §4) is the fiddly part — type/code mapping and
**embedded-header translation** for errors. The embedded-header machinery from
the #3/ICMPv6-errors work is directly reusable; the type/code table is new but
small.

### The addressability constraint

SIIT can only translate an address that has a v4 representation. `64:ff9b::v4`
does. A **native** v6 address (`fd00::5`) does not — you can't SIIT it to a v4
header, there's no v4 to put there. So:

- A v4 VPC peering a v6 VPC: the v4 side is `64:ff9b::v4` (fine), but the v6
  side's pods are `fd00::x` — **not** representable as v4. The v6 pod can reach
  the v4 pod (translate its own `fd00::x`→? — no v4 for it), but the v4 pod
  can't address the v6 pod.

This is the real design question, and it splits the feature:

- **(#9) North-south v4→v6** — a v4 fabric IP fronting a v6 VPC pod. Here the v6
  pod needs a v4 *representative*. Solution: allocate the v6 pod a **v4 fabric
  IP** (the fabric-family decoupling already lets a v6 VPC pod hold a v4 fabric
  IP on a v4-only node). The v4 client hits the v4 fabric IP; `to_pod`
  translates v4→v6 into the pod. The pod's `64:ff9b::client` reply translates
  back. **This works today's map layout with just the translator** — no new
  addressing. #9 is the cleaner half.

- **Cross-family peering** — a v4 VPC's pod addressing a v6 VPC's pod needs the
  v6 pod to have a stable v4 handle *inside the v4 VPC's address space*. That's
  a **per-peering v4 allocation** (like a floating IP, but internal): the v6 pod
  gets a v4 alias from a pool the peering defines, `64:ff9b::` maps it, and the
  reverse. This is stateful *allocation* (not stateful translation) — a small
  controller-managed map, `peer4_of[{v4-vpc-net, v4-alias}] = {v6-vpc-net, v6-ip}`.
  More design; call it the second increment.

## Datapath placement

The translator is a leaf both hooks call, like the bridge:

- **`from_pod`**: after isolation admits the packet (peers map / same-net), if
  `src.family != dst.family`, translate before delivery/encap. The overlay
  carries whatever family the *destination* is — so a v6→v4 packet is translated
  first, then delivered on the v4 destination's path (its `locals`/`remotes`
  entry is a `64:ff9b::` key, which the translated-then-rekeyed lookup finds).
- **`to_pod`** (#9 north-south): a v4 packet to a v6 pod's v4 fabric IP is
  translated v4→v6 and delivered.

Packet *size* changes (v4 header 20B ↔ v6 header 40B) — `bpf_skb_change_head`/
`adjust_room` handles the 20-byte delta. PMTU: a v6→v4 translation can produce a
packet needing fragmentation; SIIT sets DF and relies on ICMP errors — which we
now translate, so PMTU works through the translator (the #3/ICMPv6 investment,
again).

## Control plane

- **#9** needs no new API: it's implied by a v6 VPC pod having a v4 fabric IP.
  A flag or automatic-when-v4-fabric-present. (Review Q1.)
- **Cross-family peering** extends `VPCPeering`: when the two VPCs differ in
  family, the peering references a **v4 pool** (`ExternalPool`-like, but
  cluster-internal) for the v6 side's aliases, and the controller allocates a v4
  alias per v6 Port that a v4 peer might address. Asymmetric by nature — worth a
  hard look at whether it's worth the complexity vs. "peer within a family."
  (Review Q2.)

## Increments

1. **The SIIT translator + #9 north-south** — self-contained, kind-testable (a
   v4 client → a v6 VPC pod's v4 fabric IP), closes #9, and is the reusable core.
2. **ICMP↔ICMPv6 translation** — folds in the type/code table; PMTU + traceroute
   across families.
3. **Cross-family peering** — the per-peering v4 alias allocation, only if the
   asymmetry is worth it.

## Open questions (review)

1. **#9 trigger** — automatic when a v6 VPC pod holds a v4 fabric IP, or an
   explicit opt-in? (Automatic means any v6 VPC on a v4 cluster suddenly answers
   north-south on its fabric IP — a behavior change.)
2. **Cross-family peering — worth it?** The asymmetry (v6-native pods need v4
   aliases, allocated per peering) is real complexity for a case that "just peer
   within a family, or make both dual-stack" mostly sidesteps. Is this a genuine
   requirement or a completeness itch?
3. **NAT64 prefix** — the well-known `64:ff9b::/96` assumes public v4. Tenants
   use private v4 (RFC 1918), for which RFC 6052 mandates a **network-specific
   prefix** (NSP). Today it's one constant; cross-family makes the NSP choice
   real. Per-cluster config?
4. **Is this even a priority?** All three of the remaining IPv6 items (#8, #9,
   cross-family) are "nice"; none is blocking. Worth confirming the ordering
   against the other design docs (security groups, VM provisioning) before any
   of it gets built.
