# VPC egress — NAT gateways and route tables

Status: **DESIGN 2026-11-06.** Egress becomes its own objects in the tenant API
instead of a field on `VPCGateway`. This design supersedes `VPCGateway.spec.nat`
([north-south.md](north-south.md) §3), the port-shard scheme of north-south.md
increment 2, and the ungated FloatingIP egress.

---

## 1. The problem

Traffic leaving a VPC follows one fixed order in `from_pod`: FloatingIP, then the
VPC's NAT address (if `VPCGateway.spec.nat.enabled`), then the gateway pod, then
drop. A tenant cannot send a partner's range out through a separate address,
black-hole a range, or deny a workload the internet.

FloatingIP egress has no gate: the check went with `ExternalPool`, and a pod with a
FloatingIP egresses as if through an implicit internet gateway.

The VPC SNAT ([north-south.md](north-south.md) increment 2) never expires connection
state (§4.2), evicts the two halves of a connection independently from LRU maps
shared with every tenant (§4.2), cuts ports into 16 shards by position in the sorted
list of Ready nodes so that a readiness change breaks other nodes' flows and a 17th
node cannot NAT (§4.3), falls through to the gateway pod uncounted when a shard is
full (§4.6), and drops ICMP errors about NATed flows (§4.5).

## 2. The objects

| object | group | scope | written by |
|--------|-------|-------|------------|
| `NATGateway` | `sdn.cozystack.io` (aggregated) | namespaced | tenant |
| `RouteTable` | `sdn.cozystack.io` (aggregated) | namespaced | tenant |
| `Route` | `sdn.cozystack.io` (aggregated) | namespaced | tenant |
| `NATPortBlock` | `local.sdn.cozystack.io` (CRD) | cluster | agents create and ack; the controller deletes |
| field `Port.spec.routeTable` | `sdn.cozystack.io` | — | the CNI |

### 2.1 NATGateway

A **NAT gateway** is a many-to-one egress identity with at most one address per IP
family. Each address comes from an owned, backend-less `Service type: LoadBalancer`
of that family, the way `VPCGateway`'s NAT address comes today, optionally reserved
by an `IPAddressClaim` ([external-addresses.md](external-addresses.md) §5, §7).

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: NATGateway
metadata: {name: partner, namespace: tenant-a}
spec:
  vpcRef: {name: vpc1}              # same namespace; immutable
  loadBalancerClass: ""             # optional; empty = cluster default
  addressClaimName: partner         # optional; the claim whose IPv4 address it wears
  addressClaimName6: partner        # optional; the claim whose IPv6 address it wears
status:
  id: 7                             # cluster-unique, controller-allocated (1..65535)
  address: 203.0.113.9              # v4 address; empty = none
  address6: ""                      # v6 address; empty = none
  blockSize: 1008                   # ports per block (§4.3)
  blocks: {leased: 3, free: 61}
  conditions: [VPCResolved, AddressAssigned, CapacityAvailable]
```

- **Families.** With no claim field set, the NAT gateway serves every family the
  VPC has, with addresses the LB implementation assigns. With either field set, it
  serves exactly the families whose field is set:

  | `addressClaimName` | `addressClaimName6` | serves |
  |---|---|---|
  | — | — | every VPC family, dynamic addresses |
  | `c` | — | IPv4 only, `c`'s IPv4 address |
  | — | `c` | IPv6 only, `c`'s IPv6 address |
  | `c` | `c` | both, from one `family: Dual` claim `c` |
  | `a` | `b` | IPv4 from `a`, IPv6 from `b` |

  Routes `0.0.0.0/0 → partner` and `::/0 → partner` can coexist; each is
  `Unresolved` (§3.3) while the NAT gateway has no address of its family.
- **A VPC may have several NAT gateways.** Routes choose among them, so different
  destinations see different source addresses: a partner allowlists `partner`, and
  other traffic leaves as `default`.
- **The Services behind the addresses.** The controller obtains each address by
  creating a `Service type: LoadBalancer`, as `VPCGateway` does today. To attach a
  reserved address, the Service names the claim in the
  `local.sdn.cozystack.io/ip-address-claim` annotation; the address-controller's
  driver then pins the claim's addresses onto it, and the LB implementation
  attracts them. Claims stay the address-controller's objects; the NAT gateway only
  names them.
  - Both fields name the same claim: one dual-stack Service serves both families.
  - The fields name different claims: one Service per claim.
  - No claim: one single-family Service per VPC family, with dynamic addresses.

  The driver pins every address of a claim onto the Service that names it, so the
  Service's families must cover the claim's. A `Dual` claim named only in
  `addressClaimName` therefore still gets a dual-stack Service; its IPv6 address is
  assigned but not served.
- **Reading the claim.** To choose a Service's families and to report failures, the
  controller reads each named claim's `status.addresses` with a plain GET (no
  informer, no Go import of the address-controller). If the claim API is not
  installed, it creates one single-family Service per set field; the annotation then
  has no effect and the LB implementation assigns the address.
- **Auto-claim.** With neither field set, a Service keeps a claim annotation that
  names a claim the Service controls: the one the address-controller's auto-claim
  creates for a LoadBalancer Service that names none. The platform's auto-claim
  class then supplies the NAT gateway's dynamic address. The controller removes any
  other claim annotation.
- **Failures** are per family: `AddressAssigned=False` with a reason, and that
  family's routes are `Unresolved` (§3.3).

  | reason | when |
  |---|---|
  | `ClaimNotFound` | the named claim does not exist |
  | `ClaimNotBound` | the claim is `Pending` or `Lost` |
  | `ClaimFamilyMissing` | the claim has no address of the field's family, e.g. an IPv6-only claim in `addressClaimName` |
  | `ClaimNotAttached` | the Service holds an address of the family that is not the claim's, e.g. because the claim is attached to another Service and the LB implementation assigned one from its pools; the address is neither published nor announced |
  | `FamilyNotInVPC` | the field's family is not one of the VPC's |
  | `AddressPending` | the Service has no address of the family yet |
- **`CapacityAvailable=False`** means no block of this NAT gateway is free (§4.3).

### 2.2 RouteTable

```yaml
kind: RouteTable
metadata: {name: public, namespace: tenant-a}
spec:
  vpcRef: {name: vpc1}       # same namespace; immutable
  default: false             # the table of every Port that names none (§2.4)
status:
  id: 12                     # cluster-unique, controller-allocated (1..2^24-1)
  conditions: [VPCResolved, Default]
```

A table holds no routes; `Route` objects reference it. A VPC has at most one
default table. If several set `default: true`, the oldest wins (the rule
`EffectiveGateway` applies to `VPCGateway`); the others report
`Default=False, reason=NotOldest` and act as ordinary tables.

### 2.3 Route

A route is one destination and one target in its own object, so different owners
can manage the routes of one table — the way Terraform manages `aws_route`
separately from `aws_route_table`.

```yaml
kind: Route
metadata: {name: partner, namespace: tenant-a}
spec:
  routeTableRef: {name: public}        # same namespace
  destination: 192.0.2.0/24            # canonical CIDR, v4 or v6
  target:                              # exactly one of (§3.2):
    natGateway: {name: partner}        #   SNAT through that NAT gateway
    # internet: {}                     #   leave as the Port's FloatingIP
    # blackhole: {}                    #   drop, counted
status:
  state: Active                        # Active | Unresolved | Conflict (§3.3)
  conditions: [Resolved]
```

### 2.4 A pod picks its table

A pod names its table with the annotation `sdn.cozystack.io/route-table: <name>`,
resolved in the VPC's namespace. A pod without the annotation gets the VPC's
default table, or no table if the VPC has no default.

Tables do not select pods: a selector would let two tables select one pod. A per-pod
table also covers the one use subnets had here, a route table per group of workloads.

The CNI copies the annotation into `Port.spec.routeTable` at ADD and when a
persistent Port is re-bound, so a VM keeps its table across a live migration. A
changed annotation takes effect at the pod's next ADD.

### 2.5 NATPortBlock

A **lease** is a `NATPortBlock`: one node's hold on one block of one NAT gateway's
port space (§4.3). The name is the claim, as with `FabricIP`:
`<natgateway-uid>.<block>`. Two agents racing for a block cannot both create it.

```yaml
apiVersion: local.sdn.cozystack.io/v1alpha1
kind: NATPortBlock
metadata: {name: 6f1c…-e2.3}
spec:
  natGatewayRef: {namespace: tenant-a, name: partner, uid: 6f1c…-e2}
  block: 3
  node: node-b
status:
  acks:                                  # listType=map, key node
  - {node: node-a, bootID: 3e1d…}
  - {node: node-b, bootID: 9a07…}
  - {node: node-c, bootID: c4f2…}
  active: true                           # set by the holder; never unset
```

### 2.6 Who may use a VPC, and who may configure it

A VPC is **used** from every namespace a `VPCBinding` names, and **configured** only
from the namespace it lives in.

- **Use.** A `VPCBinding` in a consumer namespace lets that namespace's pods attach
  to the VPC. Creating one takes `create` on `vpcbindings` in that namespace and the
  `export` verb on the VPC, so the VPC's owner grants it. A pod needs a binding even
  in the VPC's own namespace.
- **Configuration.** Every kind that configures a VPC references it by name in its
  own namespace (`vpcRef: {name}`): `NATGateway`, `RouteTable` (and through it,
  `Route`), `SecurityGroup`, `FloatingIP`, `VPCPeering` and `VPCGateway`. Only the
  VPC's namespace can hold them, so only its RBAC decides who configures the VPC. A
  consumer namespace cannot add a route, a NAT gateway, a FloatingIP or a
  SecurityGroup to a VPC it does not own.
- **Choosing a table is use.** Any attached pod, from any namespace, may name any of
  the VPC's tables (§2.4). The owner controls what the tables contain, not which pod
  uses which.

**RBAC.** The tenant role gains full access to `natgateways`, `routetables` and
`routes` in its namespaces, and read access to their status. All three are
ResourceQuota-countable, like the other tenant kinds. RBAC on Services and
the LB allocator's scoping still decide who may obtain a public address
([external-addresses.md](external-addresses.md) §8). On `natportblocks`, the agent
may create, delete and patch status, the controller may delete, and tenants have no
access.

## 3. Routing

### 3.1 Precedence

For a packet from a VPC Port:

1. **DNS and LoadBalancer replies first,** as today: DNS steering to the
   split-horizon resolver, and a VPC backend's reply to a LoadBalancer client.
2. **Cluster-internal destinations are not routed.** A destination in the
   cluster's pod, service or node CIDRs (the `internal` map) goes to the gateway pod
   if the VPC has one, and is dropped otherwise.
3. **Longest prefix match** in the Port's table, over:
   - the **local** route: each of the VPC's CIDRs, implicit;
   - **peer** routes: each peered VPC's CIDRs, implicit, so a peering needs no
     `Route`;
   - the table's `Route` objects.

   At equal length, local wins over a `Route`, and a `Route` wins over a peer route.
   A `Route` that lies inside the VPC's own CIDR (equal to it or more specific) is
   `Unresolved`; a shorter prefix that contains it, such as `0.0.0.0/0`, is not,
   because the local route is longer. A `Route` more
   specific than a peer route wins: with `10.50.0.0/16` peered and
   `10.50.99.0/24 → blackhole`, the /24 is dropped.
4. **No match: drop.** The exception is the gateway pod: a `VPCGateway` family with
   `nat.enabled` and no assigned address ([roadmap](roadmap.md) item 7) still
   receives the VPC's unmatched traffic of that family.

A Port with no table has only the local and peer routes. A route applies in one
direction; the peer needs its own route back.

### 3.2 Targets

- **`natGateway`** — SNAT to the NAT gateway's address of the packet's family, for
  every source, a Port with a FloatingIP included. Table `public` with
  `0/0 → internet` and `192.0.2.0/24 → natGateway partner` sends a FloatingIP
  workload out as its FloatingIP, and as `partner` toward the partner.
- **`internet`** — the internet gateway, a pseudo-target with nothing to configure.
  The packet leaves as the source Port's FloatingIP through the existing stateless
  1:1 rewrite; a Port with no FloatingIP of the packet's family is dropped and
  counted.
- **`blackhole`** — dropped and counted.

**A FloatingIP's inbound replies follow the route.** The FloatingIP rewrite keeps no
state, so the datapath cannot tell a reply to an inbound connection from a new
outbound flow. A client in a range routed to a NAT gateway that connects to a
FloatingIP receives its replies from the NAT gateway's address and drops them. AWS
behaves the same way.

### 3.3 Resolution and conflicts

The controller sets each Route's `state`:

| state | when | datapath |
|-------|------|----------|
| `Active` | the table is this VPC's and the target resolves | programmed |
| `Unresolved` | the table is missing or another VPC's; the destination lies inside the VPC's own CIDR; the NAT gateway is missing, in another VPC, or has no address of the destination's family | programmed as blackhole |
| `Conflict` | an older Route in the same table has the same destination | not programmed |

An `Unresolved` route drops its traffic rather than letting it fall to a shorter
route, such as a partner-bound prefix falling to `0/0` and leaving through the
default NAT gateway.

## 4. The SNAT mechanism

Running example: VPC network id 101; NAT gateway `default`, id 7, address
203.0.113.7; nodes a, b, c. Pod P (10.0.0.5) on node b connects to R
(93.184.216.34:443). The fabric delivers 203.0.113.7 to node a.

### 4.1 Distributed SNAT, and why the port names the owner

The SNAT runs at the pod's veth, the only place that identifies the tenant when VPC
CIDRs overlap, so the connection state lives on the pod's node. The reply arrives
wherever the fabric delivers the NAT gateway's address: a MetalLB L2 leader, any
node of a BGP ECMP set (re-hashed when a session flaps), or the node a cloud
controller chose. Upstream routers pick the reply's next hop by destination.

Of the reply's fields, only the destination address and port are ours, and every
node using the NAT gateway shares the address. The **port is therefore the only field
that can name the owning node**, so the port space is divided among nodes (§4.3).

**The caps.**

- At most `64512 / blockSize` nodes can NAT through one NAT gateway at once (64 at
  the default 1008). The cap counts nodes that hold a block of that NAT gateway, not
  nodes in the cluster.
- A node holds at most 8 blocks of one NAT gateway, so it has at most
  `8 × blockSize` concurrent flows to any one destination.

Lifting them is [#66](https://github.com/lllamnyp/cozyplane/issues/66).

The mapping is address-and-port-dependent: a port is reserved per remote
`{ip, port, proto}`, and the same port carries flows to different destinations at
once. This does not meet RFC 4787's endpoint-independent-mapping recommendation:
peer-to-peer NAT traversal (STUN-style hole punching) fails through it.

### 4.2 Connection state

Two maps hold NAT connection state. `ct_fwd`/`ct_rev` remain for the cluster-egress
masquerade and the fabric bridge.

| map | type | key | value |
|-----|------|-----|-------|
| `nat_fwd` | HASH | `{proto, net, pod ip, pod port, remote ip, remote port}` | `{natgateway id, port}` |
| `nat_rev` | HASH | `{proto, natgateway id, port, remote ip, remote port}` | `{net, pod ip, pod port, last_seen, state}` |

- **Hash maps, not LRU.** A full map refuses the new flow, which is dropped and
  counted; no existing flow is evicted. Only expiry frees space.
- **`nat_rev` is the flow; `nat_fwd` indexes it for egress.** An egress hit on
  `nat_fwd` must match a `nat_rev` entry naming this pod and port, and the NAT
  gateway the route now picks; otherwise a new port is allocated. The `nat_rev` key
  and value contain the whole `nat_fwd` key, so the agent deletes both together.
- **Expiry.** Every packet in either direction refreshes `last_seen`
  (`bpf_ktime_get_ns`, CLOCK_MONOTONIC) and `state`. A TCP flow is *established*
  once the reply direction has been seen and neither side has sent FIN or RST;
  otherwise it is *transitory*. Every 30 s the agent deletes expired flows from both
  maps. The timeouts are cluster-wide agent flags, defaulting to the RFC minimums:

  | flow | timeout | source |
  |------|---------|--------|
  | TCP established | 7440 s | RFC 5382 (≥ 2 h 4 min) |
  | TCP transitory | 240 s | RFC 5382 (≥ 4 min) |
  | UDP | 300 s | RFC 4787 (≥ 2 min, 5 min recommended) |
  | ICMP echo | 60 s | RFC 5508 (≥ 60 s) |

  The datapath only inserts, so two CPUs cannot claim one port; a port frees when
  the sweep deletes its flow, up to 30 s after expiry.
- **Quota.** `nat_flows[net]` counts a VPC's live flows on the node. Allocation
  increments it and refuses a flow beyond `--nat-vpc-flow-quota` (default 32768);
  the sweep recomputes it.

### 4.3 Port blocks

Ports 1024–65535 of a NAT gateway are cut into blocks of `status.blockSize` (the
controller's `--nat-block-size`, default 1008: 64 blocks), so every agent computes
`block = (port − 1024) / blockSize` with the same divisor. Both families of a NAT
gateway share one port space.

- **Owner table.** Every agent programs `nat_blk_owner[{natgateway id, block}] → node`
  for every lease, acked or not, because any node may receive any reply.
- **Claim.** An agent hosting a Port of the NAT gateway's VPC creates the lease for
  the lowest unleased block, trying the next on `AlreadyExists`, once the NAT
  gateway has an address. Claiming when the
  Port appears usually activates the block before the workload connects out.
- **Ack, then use.** An agent that sees a lease programs its `nat_blk_owner` entry,
  then server-side-applies its own entry into `status.acks` with the node's boot ID
  (`Node.status.nodeInfo.bootID`; one field manager per node, so agents never
  conflict). An ack from an earlier boot does not count, so a rebooted node acks
  every lease again. Once every Ready node has acked in its current boot, the
  holder sets `status.active` in the same apply as its ack, and allocates from the
  block. `active` is never unset: a reboot elsewhere does not stop a block in use.
  A Ready node that never acks holds back every new block in the cluster; the acks
  show which node it is.
- **Attraction.** The controller lists as the endpoints of each NAT Service the
  Ready nodes that have acked every active lease of the NAT gateway in their
  current boot, each with its `nodeName`, and the Service is
  `externalTrafficPolicy: Local`. The LB implementation therefore announces the
  address only from a node that can forward a reply for every leased port. A
  rebooted node attracts nothing until its agent has programmed the owner table and
  acked. If no node qualifies, every Ready node is an endpoint.
- **Allocation.** `nat_gw[natgateway id]` lists the node's active blocks, up to 8.
  The allocator makes up to 16 attempts at a random port of a random active block,
  inserting into `nat_rev` only if absent.
- **Pressure.** The datapath counts **deep allocations** (more than 8 attempts) and
  failed allocations per NAT gateway. When either rises between two agent polls,
  2 s apart, the agent claims another block, up to 8. Ports are reserved per
  destination, so a block can be full toward one service and empty toward the rest;
  attempts measure that, ports in use do not.
- **Release.** An agent deletes its lease once the node has hosted no Port of the
  VPC for one TCP-established timeout and the block holds no live flow. While it
  hosts the VPC, it keeps its first block and deletes any other that has held no
  live flow for 10 minutes since the sweep last saw one or since the lease was
  created. A NAT gateway without an address holds no block: its agents release
  every block without a live flow. The
  controller deletes the leases of a node one TCP-established timeout after its Node
  object is gone, and all leases of a deleted NAT gateway.
- **Readiness is not an input.** A NotReady node keeps its leases and flows, and no
  other node's blocks change.
- **No free block.** A node without a block drops and counts its traffic through
  that NAT gateway, which reports `CapacityAvailable=False`.

### 4.4 The walk

**Egress on node b, P → R:**

1. `from_pod` on P's veth: the source passes the anti-spoofing check, the
   destination is off-VPC, and P's table routes `0/0 → natGateway default` (§5.2).
2. `nat_fwd` misses. The allocator picks port 2400 in b's block 1 and writes
   `nat_rev` `{TCP, 7, 2400, 93.184.216.34, 443} → {101, 10.0.0.5, 40000, now, transitory}`,
   then `nat_fwd`, then increments `nat_flows[101]`.
3. The source becomes 203.0.113.7:2400, and the packet leaves through the link that
   `ext_links` names for 203.0.113.7.

Later packets hit `nat_fwd`, are checked against `nat_rev`, and refresh it.

**Reply on node a, R → 203.0.113.7:2400:**

1. `from_uplink`: `nat_addrs[203.0.113.7]` gives NAT gateway 7 and VPC 101.
2. Block `(2400 − 1024) / 1008 = 1`; `nat_blk_owner[{7, 1}]` gives node b. Node a
   Geneve-encapsulates the packet to b under VNI 101, unchanged.
3. `from_overlay` on b repeats the lookup, finds itself the owner, and reverses the
   packet from `nat_rev`: the destination becomes 10.0.0.5:40000, the packet gets
   `GW_MARK` (which admits an off-VPC source through `to_pod`'s isolation check), and
   it is delivered.

A packet to the NAT gateway's address with no matching `nat_rev` entry is not
delivered, so a NAT gateway admits no unsolicited inbound traffic.

### 4.5 ICMP errors

An ICMP error about a NATed flow (v4: destination-unreachable including
fragmentation-needed, time-exceeded; v6: packet-too-big, destination-unreachable,
time-exceeded) is addressed to the NAT gateway's address and embeds the packet the
NAT gateway sent. The reverse path finds the owner from the block of the **embedded**
source port, looks the flow up by the embedded tuple, rewrites the outer destination
and the embedded source back to the pod, and fixes every checksum. Path-MTU
discovery then works for NATed TCP. Errors about ICMP echo flows are dropped, as on
the fabric bridge.

### 4.6 Failure accounting

`nat_stats[{natgateway id, counter}]` counts every NAT refusal by reason:

| reason | meaning |
|--------|---------|
| `no_block` | the node holds no active block of the NAT gateway |
| `exhausted` | 16 attempts found no free port |
| `quota` | the VPC's flow quota on the node is spent |
| `table_full` | `nat_fwd` or `nat_rev` is full |
| `no_address` | the NAT gateway has no address of the packet's family, or serves another VPC |
| `unsupported` | not TCP, UDP or an ICMP echo request |

`route_drops[{net, reason}]` counts routing refusals per VPC: `blackhole`,
`unresolved`, `no_floating_ip` (an `internet` route from a Port without one), and
`no_route`. A refused packet is dropped; it never falls through to another egress
path.

## 5. Datapath

### 5.1 Maps

| map | type | key → value | written by |
|-----|------|-------------|-----------|
| `port_rt` | HASH | `{net, Port IP}` → table id | agent, for local Ports |
| `vpc_routes` | LPM | `{table id, prefix}` → `{kind, natgateway id}`; kind ∈ local, peer, nat, internet, blackhole | agent; local and peer entries are copied into every table of the VPC |
| `nat_gw` | HASH | natgateway id → `{v4, v6, net, active blocks[8], count}` | agent, this node's blocks |
| `nat_addrs` | HASH | address → `{natgateway id, net}` | agent, every node |
| `nat_blk_owner` | HASH | `{natgateway id, block}` → node IP | agent, every node |
| `nat_fwd`, `nat_rev` | HASH | §4.2 | datapath; the agent's sweep deletes |
| `nat_flows` | HASH | net → live flows on this node | datapath; the sweep recomputes |
| `nat_stats` | HASH | `{natgateway id, counter}` → count: refusals by reason (§4.6) and deep allocations (§4.3) | datapath |
| `route_drops` | HASH | `{net, reason}` → count | datapath |

Nothing reads or writes `vpc_nat`, `nat_of` or the shard-keyed `nat_owner` any
more. Their definitions stay, because removing or reshaping a pinned map strands or
rejects the pin on every upgraded node; for the same reason the new owner table has
a new name.

### 5.2 Hooks

`from_pod` is at the limit of the verifier's budgets (a ~496-byte frame of the
512-byte combined stack; an earlier `main` failed to load with "argument list too
long"), so the route decision runs in a tail-called program, `vpc_egress`, with its
own stack and instruction budget.

1. `from_pod` runs as today through DNS steering and the LoadBalancer reply. Then,
   for a VPC Port that is not a gateway leg, with a destination outside its own VPC,
   it tail-calls `vpc_egress`, unless the packet carries the `RT_DONE` mark.
2. `vpc_egress` sends cluster-internal destinations back (step 3 below). Otherwise
   it looks up the Port's table and the longest match:
   - **nat, internet, blackhole, unresolved** — handled here: SNAT and send (§4),
     FloatingIP rewrite and send, or drop and count.
   - **local, peer, no table, no match** — it sets `RT_DONE` (mark bit 18) and
     tail-calls `from_pod`, which continues past the tail call as today: east-west
     delivery, peered delivery, or the gateway pod and drop.
3. `from_pod` clears `RT_DONE` before the packet leaves. A pod cannot forge the mark:
   the kernel clears a packet's mark when it leaves the pod's network namespace.

The FloatingIP egress rewrite and the VPC SNAT move from `from_pod` into
`vpc_egress`. Every off-VPC or peered packet of a VPC Port pays one tail call, and
two when `vpc_egress` hands it back. On
the reverse path, `from_uplink` and `from_overlay` replace `vpc_nat_reverse` with
the block lookup of §4.4 and the ICMP-error translation of §4.5. `from_uplink`
passes a frame addressed to another host's MAC (`PACKET_OTHERHOST`) to the kernel
untouched: an underlay that floods frames, such as an OCI VLAN, would otherwise
deliver one reply per node that received it. The tail-call slots
are 4 and 5 of `lb_prog`, which is not pinned.

## 6. Who does what

**Controller**
- allocates `NATGateway.status.id` and `RouteTable.status.id`;
- owns the LoadBalancer Services that obtain each NAT gateway's addresses (§2.1)
  and their EndpointSlices, which list the NAT-ready nodes (§4.3), and writes the
  addresses, `blockSize` and the block summary into status;
- resolves Routes (§3.3) and the default table (§2.2);
- deletes leases (§4.3);
- performs the transition (§7).

**Agent**
- programs `port_rt` for local Ports, `vpc_routes` for every table of every VPC it
  hosts a Port of, and `nat_gw`, `nat_addrs` and `nat_blk_owner`;
- claims, acks, activates and releases leases (§4.3);
- sweeps `nat_rev` (§4.2) and serves the metrics (§8).

**CNI** — copies `sdn.cozystack.io/route-table` into `Port.spec.routeTable` (§2.4).

## 7. Transition from `VPCGateway.spec.nat`, and what breaks

`VPCGateway` is headed for deprecation. Until then, `nat.enabled: true` makes the
controller create, and own:

- a `NATGateway` named after the `VPCGateway`, with its `loadBalancerClass` and
  claims. It adopts the `VPCGateway`'s NAT Services by relabelling them, so the
  egress address does not change;
- a default `RouteTable`, if the VPC has none;
- a `Route` `0.0.0.0/0` and/or `::/0` to that NAT gateway in the default table, for
  each family the NAT gateway holds an address for. A family without one gets no
  route, so its traffic still reaches the gateway pod (§3.1 step 4); the route is
  created when the address appears.

`VPCGateway.status.natAddress`/`natAddress6` mirror the NAT gateway's addresses.
Setting `nat.enabled: false` deletes the created objects. A tenant may instead
create `NATGateway`, `RouteTable` and `Route` objects directly.

**What breaks:**

- **FloatingIP egress needs an `internet` route.** In the default table the
  transition creates, a FloatingIP workload egresses through the NAT gateway and
  answers its FloatingIP's clients from the NAT address (§3.2), breaking inbound
  connections. Migration: a table with `0.0.0.0/0 → internet` (and `::/0` for v6),
  named by the workloads' annotation. The controller cannot do it; the pod chooses
  its table.
- **A VPC Port without a table has no internet**, through a FloatingIP or otherwise.

## 8. Metrics

Served by the agent, per node:

- `cozyplane_nat_flows{natgateway, vpc}` — live flows in `nat_rev`;
- `cozyplane_nat_blocks{natgateway}` — active blocks;
- `cozyplane_nat_drops_total{natgateway, reason}` — §4.6;
- `cozyplane_nat_allocation_deep_total{natgateway}` — deep allocations (§4.3);
- `cozyplane_route_drops_total{vpc, reason}` — §4.6.

`cozyplane_vpc_ns_{bytes,packets}_total{door="gateway"}` continues to count NAT
traffic, and `door="eip"` counts `internet`-route traffic.

## 9. Failure modes

| failure | effect |
|---------|--------|
| the node receiving the address dies | the LB implementation moves the address; every node has the owner table, so flows survive |
| a SNATing node dies | its flows die; its leases go one TCP-established timeout after its Node object |
| a node goes NotReady | nothing changes |
| the controller is down | leases keep working; no new ids, Services, route resolution or lease deletion |
| a Ready node's agent is down | new blocks wait for its ack; the node stays an endpoint |
| a node reboots | it is no endpoint until it has acked every active lease in its new boot (§4.3); active blocks stay active |
| an agent restarts | the maps are pinned; leases are re-read |
| upgrade | NAT flows through the old maps are lost once |
| per-NIC anti-spoofing in the underlay | NAT egress is black-holed, as FloatingIP and DSR replies are today ([lb-ingress.md](lb-ingress.md), DSR caveats) |

## 10. Not in this design

Egress-node mode (centralised SNAT), more than one address per family per NAT
gateway, NAT64/NAT46, tenant appliances and forwarding grants as route targets,
route tables selected by anything but the pod, routes inside a VPC's own CIDR,
subnets, flow logs, and stateful tracking of inbound FloatingIP flows. Lifting the
SNAT caps (§4.1) is [#66](https://github.com/lllamnyp/cozyplane/issues/66).

## 11. Increments, in dependency order

1. **Connection state** — `nat_fwd`/`nat_rev`, expiry and the sweep, the quota,
   refusal counting (§4.2, §4.6).
2. **NATGateway and leases** — the kinds, claim, ack, activation and release, the
   owner table and the allocator (§2.1, §2.5, §4.3).
3. **Route tables** — `RouteTable`, `Route`, `Port.spec.routeTable`, `port_rt`,
   `vpc_routes`, `vpc_egress` and the `internet` target (§2.2–§2.4, §3, §5.2).
4. **ICMP errors** on the reverse path (§4.5).
5. **The transition** from `VPCGateway.spec.nat` (§7).
