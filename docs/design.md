# cozyplane — design

A multi-tenant, eBPF-based CNI for Cozystack. Cloud-style tenancy is the
backbone; the Kubernetes networking contract is satisfied as an internal
substrate, not exposed to tenants.

## 1. Why, and what we keep

Today Cozystack does VPCs with kube-ovn and policy with Cilium. The pain:

- It's effectively VM-only and fiddly to wire up.
- The **management network (the host cluster's pod CIDR) is visible inside
  tenant pods**. The moment you try to hide it, kubelet's health probes break,
  because kubelet probes a pod on its pod-CIDR IP and expects a reply on the
  flat pod network.
- Tenant isolation, identity, and policy are bolted on rather than fundamental.

What kube-ovn gets *right* and we must keep:

- **Pinned MAC + IP per port, declared up front.** This is non-negotiable for
  VM live migration: the VM's NIC identity must survive a move between nodes.

### Design tenets

1. **Tenancy first.** Every decision starts from "this is a cloud with mutually
   distrusting tenants," not "this is a cluster with a flat network we then
   carve up."
2. **The K8s contract is plumbing, not a user surface.** We satisfy it so
   Kubernetes keeps working; we do not let tenants stand in it.
3. **Identity, not addresses.** Membership, policy, and selection are by
   metadata/identity. IP ranges are an implementation detail and may overlap
   between tenants.
4. **Don't fight the kernel.** eBPF in the datapath, standard veth/netns, no
   exotic userspace forwarding on the pod fast path.
5. **One CNI, many postures.** System workloads get flat reachability; tenant
   workloads get isolated VPCs. Same CNI, selected per workload.
6. **Placement independence.** Enforcement never depends on whether two pods
   share a node. No same-node fast path that skips the policy hooks; locality
   affects transport only. (See §4 — the invariant.)

## 2. The three planes

We separate three things that kube-ovn/Cilium blur together:

- **System fabric (underlay).** The flat Kubernetes pod network: node IPs plus
  a non-overlapping cluster pod CIDR. This is where `status.podIP` lives, where
  Services/Endpoints resolve, where kubelet probes land, where system pods talk.
  It satisfies the Kubernetes contract. **Tenant pods never see it inside their
  netns.**
- **Tenant overlay.** Per-VPC encapsulated networks (Geneve). CIDRs may overlap
  across tenants. Carries the **stable identity** (MAC/IP) and is the only thing
  a tenant pod's processes can observe.
- **The bridge.** A per-pod eBPF NAT/forwarding shim on the node that connects
  the two so that the control plane can reach tenant pods *without* exposing the
  system fabric to them.

The user-facing network carries identity (as you wanted). The system fabric is
anonymous plumbing.

```
            ┌──────────────────────── node ───────────────────────┐
 kubelet ──▶│ system fabric (pod CIDR, unique cluster-wide)       │
 apiserver  │       │                                             │
 sys pods ─▶│  [eBPF bridge: DNAT podIP→vpcIP, SNAT src→gw]       │
            │       │                                             │
            │  ┌────┴─────┐        ┌──────────┐                   │
            │  │ tenant   │        │ system   │  veth (flat)      │
            │  │ pod netns│        │ pod netns│───────────────────┼─▶ fabric
            │  │  vpcIF   │        └──────────┘                   │
            │  └────┬─────┘                                       │
            │    Geneve VNI ──────────────────────────────────────┼─▶ other nodes
            └─────────────────────────────────────────────────────┘
```

## 3. Per-pod addressing — the core mechanism

Every tenant pod has **two identities**:

| | scope | overlaps? | who sees it | stable across migration |
|---|---|---|---|---|
| `status.podIP` (system-fabric addr) | cluster-wide | no | K8s API, kubelet, Services, system pods | no (new pod ⇒ new addr) |
| VPC IP/MAC (the port) | per-VPC | yes | only the tenant pod / VM | **yes** (PortBinding) |

Crucially, **the system-fabric address is never configured inside the pod's
netns.** It is a node-side handle. Inside the pod there is exactly one interface
with the VPC IP/MAC, a default route to a VPC gateway address, and nothing else.

### The kubelet-probe walkthrough (the thing that breaks today)

1. kubelet probes `status.podIP:port` (a system-fabric address, routable on the
   flat network — contract satisfied).
2. The packet reaches the node hosting the pod. eBPF **DNATs** the destination
   from the system-fabric address to the pod's **VPC IP**, and **SNATs** the
   source to the **VPC gateway address** (a reserved address inside the tenant's
   own subnet, e.g. the `.1`).
3. The packet is delivered to the pod's veth. The app (bound to its VPC IP or
   `0.0.0.0`) sees a connection **from the VPC gateway to itself**. It learns
   nothing about kubelet, the node, or the management CIDR.
4. The reply retraces the path; eBPF reverses the translation.

The same bridge serves any legitimate north→south flow: a system operator
dialing a tenant Postgres on its `status.podIP`, a Service backed by a tenant
pod, etc. From inside the pod, all such traffic appears to originate from the
VPC gateway.

### Why two addresses instead of one

- Tenant CIDRs **overlap** (every tenant gets `10.0.0.0/8` if they want), so the
  VPC IP cannot be `status.podIP` — the API/Services need cluster-unique IPs.
- The stable identity (what the VM keeps) must be the *VPC* address, not the
  fabric address — migration changes the pod (and thus the fabric address) but
  must not change the VM's NIC.

This is exactly the cloud model: the hypervisor host injects itself into the
tenant network as a hidden gateway; the tenant's "IP" is VPC-scoped and stable;
the control plane reaches the guest through the host, never the reverse.

## 4. Datapath

**Kernel eBPF for the fast path; userspace for control.** This is the
recommendation for both open questions about implementation.

- **Per-packet work in eBPF** (tc/`cls_bpf`, XDP where it helps, and
  socket/`cgroup` hooks): forwarding, the NAT bridge, encap/decap, policy
  enforcement, Service load-balancing. Proven by Cilium; keeps us in-kernel and
  out of Multus territory.
- **Userspace agent (per-node DaemonSet)** programs eBPF maps, runs local IPAM,
  handles CNI `ADD`/`DEL`, and reconciles CRDs into datapath state.
- **Userspace datapath (DPDK/VPP) is deliberately avoided on the pod path.** It
  fights the kernel, complicates the CNI contract, and isn't needed. The one
  place a userspace datapath may earn its keep is **dedicated gateway nodes**
  (VPC↔internet, heavy SNAT/NAT64, IPsec/WireGuard termination) — an optional,
  isolated role, not the common case.

### Placement independence (invariant)

**Every packet is policy-enforced at two hooks it always traverses regardless of
pod placement, and pod locality determines only transport — never whether a
packet is inspected.** Concretely:

- **Egress hook** — `from_pod`, at the source pod's host-veth ingress. Every
  packet a pod emits crosses it *before* any locality decision.
- **Ingress hook** — `to_pod`, at the destination pod's host-veth egress. Every
  delivery path leaves via the destination veth — same-node redirect, cross-node
  decap-then-route, and the node→pod bridge alike — so this hook sees all of it.

Same-node traffic is therefore **not** special-cased: it is delivered by an eBPF
redirect *through* the destination's ingress hook, not by a kernel-routing
shortcut that would skip enforcement. Co-located pods cannot bypass isolation or
(future) network policy; behaviour does not depend on the scheduler. This is a
deliberate rejection of the common "same-node fast path" optimization, which
makes behaviour placement-dependent and is a well-known source of policy-bypass
bugs and placement-coupled debugging. Locality changes only the transport
(direct redirect vs Geneve), and only because a remote destination *must* be
encapsulated.

Network policy / security groups live in these two hooks: egress rules in
`from_pod`, ingress rules in `to_pod`. Because both hooks are universal, a rule is
enforced identically no matter where source and destination are scheduled.

### Encapsulation

- **Geneve** for tenant overlays. VNI selects the VPC; a Geneve **option TLV
  carries the security identity** of the source port, so the receiving node
  enforces policy and demuxes to the right VPC **without** reverse IP lookups
  and without identities leaking across tenants.
- **System fabric** can be native-routed (if the underlay routes the pod CIDR)
  or itself lightly encapsulated; system pods don't need overlay isolation.
- Encryption (WireGuard or IPsec) is a per-VPC toggle over the Geneve underlay.

## 5. Stable identity & live migration

A `PortBinding` CRD pins `{VPC, IP, MAC}` to a workload identity (a VM name or a
stable selector), independent of which pod currently realizes it.

- On VM live-migration KubeVirt spins up a **target** pod. The target claims the
  **same** `PortBinding` ⇒ same VPC IP/MAC. The target pod gets a *new*
  system-fabric `status.podIP` (K8s tolerates this), but the VM's NIC identity is
  unchanged.
- Cutover is a control-plane operation: the overlay's location map (which node
  hosts which VPC IP/MAC) is updated atomically in the eBPF maps and propagated;
  no gratuitous-ARP storm needed because *we* own the overlay's forwarding tables.
- The VM only ever has the VPC identity, so from inside it the migration is
  invisible.

## 6. Multi-tenancy & isolation — the trust model

Direction matters:

- **System → tenant: allowed** (subject to policy). Operators, probes, Services
  reach tenant pods through the bridge, masqueraded as the VPC gateway.
- **Tenant → system: denied by default.** No route to the fabric exists inside
  the pod; eBPF drops anything that tries (anti-spoof, egress filter).
- **Tenant ↔ tenant (cross-VPC): denied** unless an explicit peering object
  exists. Different VNIs, no shared addressing.
- **Within a VPC: allowed** subject to security groups.

The "exec in and nmap" threat: the tenant sees only its VPC interface, a route
to its VPC CIDR, and the gateway. Scans reveal only co-tenant VPC members
(intended). The gateway answers only on explicitly exposed ports. The management
network has no route, no ARP visibility, and never appears in the pod's conntrack
— it is genuinely invisible, not merely filtered at L3.

## 7. Network identity & security groups (first-class)

- Each port gets a **security identity** derived from workload metadata (labels)
  **scoped to its VPC**, so identities never collide or leak across tenants.
- **`SecurityGroup`** selects ports by metadata and defines ingress/egress in
  terms of *other security groups*, FQDNs, or external CIDRs — never internal IP
  ranges.
- Enforcement is in eBPF at both ends; the Geneve identity TLV lets the
  destination enforce on identity directly.
- This subsumes what we use Cilium for today. **Cilium compatibility is not a
  goal**; the identity model is native and tenant-scoped. (k8s `NetworkPolicy`
  is still honored for the system/default network for ecosystem compatibility.)

## 8. One CNI, system workloads included

A pod's posture is declarative:

- **Default/system network** (no VPC binding): the pod lives directly on the
  system fabric with flat reachability — exactly what controllers, CoreDNS,
  ingress, CSI, and operators need. The K8s contract holds in full for them.
- **Tenant network** (bound to a VPC): the isolated-overlay + bridge model above.

Because system pods are first-class on the fabric, a controller talks to the API
via the normal `kubernetes` Service, and can open a connection to a tenant
workload via its `status.podIP` through the bridge. No tenant VPC required for
the controller itself.

### The address-agreement problem (managed stateful services)

The bridge provides *connectivity*, not *address agreement* — and for clustered
workloads that distinction bites. Consider the etcd-operator (system pod) driving
etcd members (tenant pods):

- A member sees itself as its **VPC IP**: that is what it binds, advertises as
  its peer/client URL, writes into the membership list, and uses to reach peers.
- The operator knows the member only as its **`status.podIP`** (fabric).
- A health GET to `status.podIP:2379` survives the bridge fine. But the moment an
  address rides in the *payload* — `MemberList` returning peer URLs, `MemberAdd`
  taking one, the initial-cluster string the operator composes, a leader
  redirect, client endpoint auto-sync — the two sides are in different address
  spaces. The operator learns VPC IPs that are overlapping and unroutable from
  the fabric; or it writes a fabric IP into cluster state that the *members*
  cannot use to reach each other.

This is general to operators of peer-to-peer/stateful systems (Patroni, Cassandra,
Kafka advertised listeners, RabbitMQ, Redis Cluster, ClickHouse Keeper, MinIO),
so it is a first-class pattern, not an etcd corner case.

**Decision: name-based addressing is the default posture, and a packaging
requirement for every Cozystack managed service that can support it.** Cozystack
owns the managed-service catalog, so "address members by stable DNS name, never by
literal IP" is enforceable, not aspirational. The escape hatch below is reserved
for the minority of systems that gossip *resolved IPs* in their wire protocol
regardless of config — **Redis Cluster** (cluster bus) and **Cassandra/ScyllaDB**
(`system.peers`, gossip) — where names cannot help. Each managed service gets a
one-time audit of a single question: *does it ever report a resolved IP across the
operator↔member boundary?* If no → default path; if yes → escape hatch.

The default path imposes two hard requirements on the design:

- **Stable per-port names tied to the `PortBinding`**, surviving pod recreation
  and migration. The VPC IP is stable, but the system-view `status.podIP` changes
  on migration, so the **system-view A record is re-pointed as part of the
  migration cutover** — DNS is control-plane reconciliation, not a static zone.
- **TLS SANs keyed on the stable name**, not the IP (saner than IP SANs anyway).

Two layers of remedy:

1. **Default — split-horizon DNS with stable per-port names.** Every port gets a
   stable name (`<member>.<vpc>.cozyplane`) that resolves to the **VPC IP in the
   VPC view** and to the **`status.podIP` in the system view** (we already run
   both DNS views — §10). Workloads and operators address members **by name,
   never by literal IP**: member↔member resolves to VPC IPs (peer traffic stays
   in-VPC), operator→member resolves to fabric IPs (through the bridge). For etcd,
   additionally pin the operator's client to the fabric endpoints and disable
   endpoint auto-sync. Covers name-friendly systems with no operator changes.
2. **Escape hatch — the operator joins the VPC** (native multi-attach, §9) when
   names aren't enough (IP-literal gossip, deep membership surgery). Because
   tenant CIDRs overlap, one cluster-wide operator cannot sit in all VPCs at
   once, so this means a **per-tenant operator shard** attached to that single
   VPC (recommended — also the right blast-radius story) or VRF-style
   per-attachment routing tables inside one operator (heavier). Operator and
   members then share one address space and addresses-in-payload just work.

## 9. Replacing Multus

The CNI natively understands **multiple attachments per pod**:

- A pod may attach to the system network, to one VPC, or to several (e.g. a
  tenant router/NFV workload bridging two VPCs, or a workload needing a separate
  storage network).
- Attachments are declared via annotation/CRD (`NetworkAttachment`), realized as
  additional interfaces by the single CNI — no meta-CNI, no `net-attach-def`
  chaining. Multus goes away.

## 10. Controlled doors: Services, DNS, metadata, egress

The VPC gateway address is the single, policy-controlled door between a tenant
and anything outside its VPC:

- **DNS**: `gateway:53` → a per-tenant CoreDNS view (tenant resolves its own
  service names; cannot enumerate the cluster).
- **Cluster API / Services**: not exposed to tenants by default; opt-in DNAT of
  specific Services onto the gateway when a managed workload genuinely needs it.
- **Metadata**: `169.254.169.254` served at the gateway (cloud-init, instance
  identity), per-tenant.
- **Egress to internet / external networks**: via `GatewayPolicy` to gateway
  nodes (SNAT, NAT64, floating IPs).
- **Service LB for tenant pods** (ClusterIP/LB scoped to the VPC) handled in
  eBPF within the VPC scope.

## 11. Open questions, answered

- **Jumbo frames — lean in.** Run the **underlay at 9000 MTU** so Geneve
  overhead (~50 B) doesn't force tenant fragmentation; expose clean tenant MTUs
  (1500, or 8950 for jumbo-aware tenants). MTU is per-VPC and advertised via DHCP
  or the gateway.
- **IPv6 — dual-stack capable from day one.** The model is L3-agnostic; VPCs may
  be v4, v6, or dual-stack with overlapping v4 and global v6. Underlay can be v6.
  NAT64 at gateway nodes for v6-only tenants reaching v4 internet.
- **Encapsulation — yes, Geneve.** Chosen specifically for the identity-carrying
  option TLV and VNI-per-VPC. Native routing reserved for the system fabric.
- **Kernel vs userspace — kernel datapath, userspace control** (see §4).
  Userspace forwarding only on optional gateway nodes.

## 12. Components & API surface

Components:

- `cozyplane-cni` — thin CNI binary kubelet invokes; forwards ADD/DEL to the
  node agent over a socket.
- `cozyplane-agent` — per-node DaemonSet; eBPF map programming, local IPAM,
  bridge/NAT, encap/decap, policy realization.
- `cozyplane-controller` — cluster controller; central IP/identity/MAC
  allocation, `PortBinding` coordination (incl. migration cutover), policy
  compilation, fabric↔VPC mapping distribution.
- `cozyplane-gateway` (optional) — dedicated nodes for VPC↔external, NAT64,
  encryption termination; may use a userspace datapath.

CRDs (sketch):

- `VPC` / `Subnet` — tenant network(s): CIDRs, dual-stack, MTU, routing.
- `PortBinding` — pinned `{VPC, IP, MAC}` ↔ workload identity; migration-stable.
- `SecurityGroup` — metadata-selected ports; rules over identities/FQDNs/CIDRs.
- `NetworkAttachment` — binds pods to networks (Multus replacement).
- `GatewayPolicy` / `ServiceExposure` — what crosses the VPC gateway (DNS, API,
  metadata, egress).
- `VPCPeering` — explicit cross-VPC connectivity.

## 13. Coexistence & migration from kube-ovn + Cilium

- cozyplane can run system pods on a flat network that mirrors today's pod CIDR,
  so the control plane is unaffected during cutover.
- Per-namespace/per-VPC opt-in: move tenants onto cozyplane VPCs incrementally
  while legacy stays on kube-ovn until drained.
- Cilium policy is replaced by `SecurityGroup`; k8s `NetworkPolicy` remains
  honored on the default network to avoid breaking system manifests.

### Phased roadmap

1. **Fabric + system pods**: single flat eBPF network, Services, DNS — pass CNI
   conformance and the K8s contract. (No tenancy yet.)
2. **The bridge**: per-pod dual addressing, kubelet-probe masquerade, hide the
   fabric from a pod. Validate probes/operators against an isolated pod.
3. **VPC overlay**: Geneve, overlapping CIDRs, intra-VPC connectivity, gateway
   (DNS/metadata).
4. **Identity & policy**: security identities, `SecurityGroup`, identity in
   Geneve.
5. **Stable identity & migration**: `PortBinding`, live-migration cutover with
   KubeVirt.
6. **Multi-attach (kill Multus), peering, gateway nodes, encryption, NAT64.**

## 14. Risks / decisions still open

- **`status.podIP` semantics for tenant pods**: confirm nothing in the stack
  assumes the pod can *originate* from `status.podIP` (it can't — that address is
  node-side only). Audit operators that reverse-connect.
- **Conntrack scale** for the per-pod bridge across many probes/connections.
- **Geneve identity TLV** interop and offload support on target NICs.
- **Gateway HA** and per-VPC egress IP management.
- **Migration cutover atomicity** under partial map-propagation failure.
