# Multi-attach — several VPCs on one pod

*Design. The implementation is a separate change; nothing described here is built
yet. `design.md` §9 is the intent this fills in.*

A pod attaches to exactly one VPC today: `cmdAdd` reads a single annotation
(`sdn.cozystack.io/vpc`) and `addVPC` gives the pod one interface. That is enough
for a workload that lives in a network. It is not enough for a workload whose job
*is* the boundary between two — a tenant firewall, a router, an NFV appliance, a
workload that wants its storage traffic on a separate network. `design.md` §9 has
always said the CNI should understand several attachments; this is how.

## 1. The contract

The single-VPC annotation keeps working, verbatim, and stays the right way to
express the common case:

```yaml
sdn.cozystack.io/vpc: "tenant-a/front"
```

The multiple case is a JSON list:

```yaml
sdn.cozystack.io/networks: |
  [{"vpc": "tenant-a/front", "ip": "10.10.0.5"},
   {"vpc": "tenant-a/back",  "name": "eth1"}]
```

| field | required | meaning |
|-------|----------|---------|
| `vpc` | yes | `<vpc>` (owner namespace defaults to the pod's) or `<owner-ns>/<vpc>` — the same syntax the single annotation already takes |
| `ip` | no | the tenant address to pin. Empty lets IPAM allocate one |
| `mac` | no | the interface MAC to pin. Empty lets the veth keep its random one |
| `name` | no | the interface name inside the pod. Defaults to `eth<index>` |

**Both annotations on one pod is an error.** Not a precedence rule: a pod carrying
both is a pod whose author disagrees with themselves, and guessing which half they
meant is how you ship a workload attached to a network nobody asked for.

### Order is part of the contract

Entry 0 is not merely the first entry. It is the pod's **primary** attachment, and
three things follow from that:

- it carries the fabric bridge, so it is the interface `status.podIP` resolves to
  and the one kubelet's probes reach;
- it gets the **default route**. The others get an on-link route to their own VPC
  CIDR and nothing more;
- it is the interface the split-horizon DNS steer works from (see §5).

Reordering the list on a live pod therefore changes which network the pod's
untargeted egress leaves by. Treat the list as ordered, like a disk list, not as a
set.

Why one default route and not several: a pod with N default routes picks its
egress interface by whatever metric the kernel happened to assign, which is to say
nondeterministically, and the choice changes when an interface flaps. A router
wants to *decide* that, and it does so with its own routes. The CNI's job is to
not have made the decision for it.

## 2. Static addressing

`ip` on an entry pins the tenant address. This is the piece that could not be
expressed at all before: a Port's name **is** its address claim
(`v<vni>.<ip-dashed>`), allocated by walking the VPC CIDR from `.2`, so anything
that had to be reachable at a known address inside a VPC — a gateway, a resolver, a
database a peer is configured against — had no way to say so.

With `ip` set the walk is skipped: the Port name is composed directly and created.
An `AlreadyExists` is a **hard error**, not a cue to try the next address. The
caller asked for one address; handing them a different one silently is the failure
mode this field exists to remove.

`mac` behaves the same way. It is separate from a *persistent* Port (the VM
mechanism in `live-migration.md`), which pins `{IP, MAC}` to a VM identity across a
node move; `mac` here pins it to a pod spec.

## 3. Forwarding — and why it is a grant, not a field

Multi-attach alone does **not** make a firewall work, and the reason is worth
stating plainly because the failure is silent-looking from inside the guest.

`from_pod` runs a source-address RPF check per interface (`bpf/overlay.c`,
§ anti-spoof in `security-groups.md`): the source address a packet carries must
resolve, in `locals`, to the very veth it was emitted on. A VM routing from VPC-A
to VPC-B emits on the B interface with an A source address; `locals[{netB, srcA}]`
misses, and the packet is dropped at its origin veth. The destination end refuses
it too — `to_pod`'s isolation check sees a source that belongs to no network in the
destination's scope.

That check is not incidental. A pod's SecurityGroup identity is keyed on its source
IP, so a pod that could forge a co-VPC neighbour's address would inherit that
neighbour's groups. **Exempting an interface from RPF is granting it the ability to
impersonate any member of its VPC.** It is the same capability AWS spells
`sourceDestCheck: false`, and it belongs to whoever owns the network, not to
whoever runs the workload.

So it is a field on **`VPCBinding`**:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata:
  namespace: tenant-a          # the CONSUMER's namespace
spec:
  vpcRef: {namespace: tenant-a, name: back}
  allowForwarding: true
```

`VPCBinding` is already the grant object: creating one requires the `export` verb
on the referenced VPC, so it is authored by the VPC's owner and not by the tenant
consuming it. A capability that lets its holder spoof the VPC lands at exactly the
right level of authority, and it shows up in RBAC rather than hiding in an
operator's head.

Consequences to know before granting it, because the datapath's gateway flag
carries more than the RPF exemption. On a forwarding interface the datapath also:

- skips the cluster-DNS steer, so that interface gets no split-horizon view;
- skips ServiceVIP DNAT, so in-VPC service addresses do not resolve through it;
- skips the eBPF egress NAT, so it draws no north-south identity of its own;
- marks what it delivers as gateway-forwarded, which is what lets an off-VPC
  source through the destination's isolation check.

For a router those are all the right answers — a transit leg should not have its
DNS hijacked or its destinations rewritten. For anything else they are surprising,
which is another reason the flag is granted rather than requested.

## 4. What the datapath needs, and what it does not

The **interfaces** cost the datapath nothing, and that part is worth recording so
it is not re-investigated:

- `ports[ifindex] → net` and `locals[{net, ip}] → endpoint` are already keyed per
  interface. Nothing in them assumes one veth per pod;
- the four hooks attach per veth already — a second attachment is a second veth
  with its own `ports` entry, which the existing code reads without noticing.

**The forwarding grant does cost a datapath change**, and an earlier draft of this
document was wrong to say otherwise. It claimed `PORT_F_GATEWAY` already
implemented exactly these semantics and could simply be reused. It does not, and
the difference is a security hole rather than a detail: the gateway flag ALSO makes
`from_pod` stamp `GW_MARK`, and `to_pod` skips the east-west SecurityGroup gate on
`GW_MARK`. Reusing it would have silently disabled policy for the one workload
whose traffic most needs policing. Measured on a live cluster: with the grant, the
forwarder reached a peer on a port no rule allowed.

So tenant forwarding is its own flag, and the two diverge exactly where they
should:

| | gateway (`PORT_F_GATEWAY`) | tenant forwarding (`PORT_F_FORWARD`) |
|---|---|---|
| source RPF | lifted | lifted |
| what gets marked | everything the leg emits | only a packet whose source is genuinely foreign — the router's own traffic stays on the ordinary east-west path |
| mark | `GW_MARK` | `FWD_MARK` |
| destination isolation check | cleared | cleared |
| destination SecurityGroups | **skipped** | **enforced** |
| east-west metering | counted as the north-south gateway door | untouched |

A forwarded packet is judged by the destination's SecurityGroups as a
**north-south source**, through the same `ns_sg_admit` the fabric bridge and
floating IPs already use. That is not a shortcut. This VPC holds no identity for
an address it does not own: `srcnet` is 0, the source bitmap is empty, and the
east-west group test would deny everything with no rule able to allow it. A
tenant writes `from: {cidr: 10.10.0.0/24}` and means exactly this. An ungrouped
destination still passes, so forwarding works out of the box and tightens the
moment the destination joins a group.

`TUN_F_FORWARD` carries the mark across a Geneve hop, so real VNIs are now
`< 2^22` rather than `2^23` — four million, against an allocator that starts at
100.

Two lessons from making the change, recorded so they are not re-learned:

- the verifier rejected the first attempt with *"dereference of modified ctx ptr
  R2 off=8 disallowed"*. clang had folded one `skb->mark` test into a **variable**
  ctx offset; a ctx field must be loaded at a constant one. Hoisting a single read
  of the mark leaves clang no such choice, and is cheaper anyway.
- the veth alias is the rebuild record and encoded only `gw`. Without a `fwd` key
  a granted leg loses the flag on the first agent restart and starts dropping its
  own transit traffic on the RPF check — hours after the change that caused it.
  The key is optional on read, so an alias written by an earlier release still
  parses, as `fwd=0`, which is what it was.

## 5. Known limits, stated up front

- **DNS and probes ride entry 0 only.** One fabric IP is claimed per pod, bridged
  to entry 0's `{net, VPC IP}`. `dns_steer` resolves a pod's fabric handle through
  `fabric_of[{net, src}]`, which exists only for that pair, so a query sourced from
  a secondary interface misses the steer and falls through to that VPC's gateway.
  A router does not want a split-horizon view on its transit legs anyway; a
  dual-homed *application* that does would need a fabric handle per attachment,
  which is a larger change and deliberately not in this one.
- **North-south metering attributes a forwarding leg's traffic to the gateway
  door.** `count_ns(NS_GW)` fires on the gateway flag, which a tenant forwarding
  interface now also carries, so its east-west shows up under the VPC's
  north-south counters. The counter should key on the Port's gateway *role* rather
  than the datapath flag; until it does, a VPC running a tenant router reads high
  on `cozyplane_vpc_ns_bytes_total{door="gateway"}`.
- **Interface count is bounded** by the host veth name: `IFNAMSIZ` leaves 15
  characters and the existing `cph` + 11 of the container ID uses 14, so the index
  takes the one remaining character. Ten attachments per pod, which is well past
  any use we have.

## 6. The firewall topology — it routes, and it is policed

A first draft of this document said multi-attach gives a pod legs in two VPCs but
cannot make it a router between them, because `from_pod` resolves the destination
in the **source's** scope and an off-VPC destination therefore never follows a
next hop the guest chose. The first half is true. The conclusion was wrong, and
measuring it is what showed why.

An off-VPC destination is not dropped: it is delivered to `gateways[vni]`, **with
the original destination intact**. So a workload that is its VPC's gateway
receives that traffic by construction, and a workload with a leg in the other VPC
can forward it on. That is the whole firewall.

Validated end to end on a three-node cluster — an appliance holding a leg in each
of two VPCs and designated the gateway of both:

```
pod-a ──VPC1──▶ [ firewall: eth0 VPC1 / eth1 VPC2 ] ──VPC2──▶ pod-c
      (no route of its own; the datapath steers off-VPC to the gateway)
```

- ICMP round-trips, 0% loss, without pod-a carrying any route to VPC2;
- TCP is admitted on a port both ends allow and refused on one neither does.

**Policy applies at BOTH ends of the routed path, and each end judges what it can
see.** The source VPC gates the departure with the sender's own
`egress: {to: {cidr}}` — a grouped pod's north-south egress is default-deny, so
without that rule the connection never leaves, which is exactly how the TCP case
first failed. The destination VPC gates the arrival with
`ingress: {from: {cidr}}`, judging the packet as a north-south source because it
holds no identity for an address it does not own (§4). ICMP crosses ungated in
both directions, as it does everywhere in v1.

What was missing was **not** a per-VPC route table. It was a supported way to say
"this tenant workload is my VPC's gateway": `Port.spec.gateway` is what
`gateways[vni]` is built from, and only `addGatewayLeg` could set it — agent
namespace, `VPCGateway` with NAT required, and the reserved `.1`. The validation
above set it by patching the Port as cluster-admin, which is not a path a tenant
has.

That is closed by `VPCGateway.spec.appliance`, a follow-up change: the VPCGateway
names the workload and the controller moves the flag onto its Port **in this VPC**
(north-south.md §6b). It needed no CNI or datapath change — the door was always a
Port flag, and the question was only who may decide which Port carries it.

Note the split of authority, which is deliberate. Pointing your own VPC's door at
your own workload is yours to do; the right to emit a source you do not own stays
`VPCBinding.allowForwarding`, authored by whoever holds `export` on the VPC.
Receiving is not sending, and a firewall needs both.

## 6. Why not the `NetworkAttachment` CRD

`design.md` §9 and `control-plane.md` §2 both name a `NetworkAttachment` object as
the Multus replacement. It was never built, and `control-plane.md` already says to
treat it as vocabulary rather than API.

An annotation is the right shape here for the same reason the single-VPC attachment
is one: the thing being described is a property of *this pod*, authored with the pod
and dying with it. A separate namespaced object holding a copy of a pod's network
layout is the stale-copy problem this codebase has removed twice already — once by
deleting `ExternalPool`, once by normalising `Port.spec.fabricIP` away. The pieces
that genuinely outlive a pod — the network, the grant, the address claim — are
already objects: `VPC`, `VPCBinding`, `Port`.

What a CRD would add over the annotation is a reusable *template* referenced by
several pods. That is real, and it can be built later on top of this without
changing the datapath or the CNI: a controller that expands a template into the
annotation. It is not a reason to delay the mechanism.
