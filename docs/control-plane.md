# cozyplane — control plane & implementation

How the operator comes alive. Companion to `design.md` (architecture). Group:
`sdn.cozystack.io`, version `v1alpha1`, served by the **Cozystack aggregated API
server**, not CRDs.

## 1. Why the aggregated apiserver changes the design

We own the REST handlers and the backing store, so we are not bound by CRD
ergonomics. Concretely we exploit:

- **Atomic, server-side IPAM.** IP/MAC/identity allocation happens *inside the
  storage transaction* of a `Port` CREATE. No CR-spinning, no optimistic-retry
  races, no allocator CRD. The allocation index lives server-side and is never
  exposed as a racy object.
- **Custom verbs / subresources** with their own RBAC: `Port/bind`,
  `Port/migrate`, `Port/status`, `VPC/peering`. The node agent gets RBAC to
  `bind` and write `status`, but not to mutate `spec`.
- **Inline validation & defaulting** in the handler — no admission webhooks.
  Overlap checks, MAC uniqueness, CIDR/dual-stack sanity, SG selector
  resolvability, VNI uniqueness — all fail closed at write time.
- **Projected (computed) resources** that aren't stored: `Port/effectivePolicy`
  (compiled SG ruleset for a port), `Subnet/allocations` (live free/used map),
  `VPC/topology`. Computed on read for debugging/observability.
- **Node-scoped watches.** Agents watch with a `spec.nodeName`/`status.nodeName`
  field selector; we implement efficient server-side filtering so each agent only
  streams the slice it must program.
- **Per-resource storage strategy.** Declarative config (VPC/Subnet/SG) is
  durable and GitOps-friendly; high-churn allocation state can use a separate
  keyspace tuned for write rate.

## 2. Object model

Two tiers: **declarative** (authored by tenants/operators, desired state) and
**realized** (control-plane owned, the live state).

### Declarative

- **`VPC`** — `{ cidrs[v4,v6], mtu, routingMode, encryption }`. Server allocates a
  unique **VNI** on create (validation rejects exhaustion/collision).
- **`Subnet`** — `{ vpcRef, cidr, gateway, allocRanges[], dns }`. Validation
  rejects overlap within the VPC and CIDR outside the VPC.
- **`SecurityGroup`** — `{ selector (labels, VPC-scoped), ingress[], egress[] }`;
  rules reference other SGs / FQDNs / external CIDRs — never internal IPs.
- **`NetworkAttachment`** — binds a workload class to `{ vpcRef, subnetRef,
  securityGroups[] }`. The Multus replacement; referenced from a pod by
  annotation. A pod may reference several.
- **`VPCPeering`**, **`GatewayPolicy`** — cross-VPC and the controlled doors
  (DNS/metadata/API/egress) from `design.md` §10.

### Realized

- **`Port`** — the central runtime object: one network interface.
  - `spec`: `{ vpcRef, subnetRef, requestedIP?, requestedMAC?, securityGroups[],
    owner (pod or VM NIC), persistent }`.
  - `status`: `{ ip[], mac, identity, dnsName, binding{ node, podUID, fabricIP,
    state }, programmed }`.
  - **Lifecycle by persistence:**
    - *Ephemeral* (ordinary pod): created at CNI ADD, `ownerRef` → pod, garbage
      collected with the pod.
    - *Persistent* (VM NIC): pre-created by a controller watching
      `VirtualMachine`s, named after the VM+NIC, holds the **pinned** MAC/IP.
      Each virt-launcher pod's CNI ADD *binds* to it rather than creating one —
      this is how MAC/IP survive pod churn and live migration.

A persistent `Port` *is* the "PortBinding" concept from `design.md` — one kind,
two lifecycles, rather than two kinds.

### Port subresources

- **CREATE** (no subresource): allocates IP(s)/MAC/identity/dnsName atomically and
  returns them. This *is* IPAM.
- **`/bind`** — agent claims realization on a node: sets `status.binding` with the
  node and the allocated **fabric IP**. Enforces a single *active* binding, except
  during migration where source (draining) and target (active) coexist briefly.
- **`/status`** — agent reports datapath programming progress/health.
- **`/migrate`** — initiate cutover: stage a target binding, return a token, let
  the migration controller drive the flip (see §5).
- **`/effectivePolicy`** (projected) — compiled rules for debugging.

## 3. The ADD path — first sign of life

What happens when a tenant pod is scheduled to node N:

1. kubelet → `cozyplane-cni` (thin binary) with ADD, netns, and `CNI_ARGS`
   (`K8S_POD_{NAME,NAMESPACE,UID}`).
2. CNI binary → node agent over a unix socket, forwarding pod identity.
3. Agent reads the pod + its `NetworkAttachment`/annotations → resolves
   `{ VPC, Subnet, SecurityGroups }`.
4. Agent obtains the Port:
   - ordinary pod → **CREATE** a `Port` (server allocates IP/MAC/identity/name);
   - VM → look up the persistent Port and **`/bind`** it.
   Either way the agent ends with `{ vpcIP, mac, identity, dnsName, fabricIP }`.
5. Agent programs the datapath:
   - veth into the netns; configure **VPC IP + MAC**, default route to the subnet
     gateway, per-VPC MTU;
   - eBPF maps: the bridge (`fabricIP ↔ vpcIP`, source-masquerade to gateway),
     the port identity, and the overlay location (this `vpcIP/mac` lives on N);
   - publish DNS records in **both views** (VPC view → vpcIP, system view →
     fabricIP).
6. Agent `/bind`s (or updates `status`) marking the Port programmed.
7. CNI returns its result to kubelet.

### The decision this path forces (and the #1 risk)

The CNI result reports the **fabric IP** as the pod's IP — so `status.podIP`,
Endpoints, and Services are cluster-unique and probe-able — **while the pod's
interface inside the netns carries the VPC IP**. This divergence is deliberate
and is exactly what hides the fabric (`kubectl get pod -o wide` shows the fabric
IP; `ip addr` inside the pod shows the VPC IP).

The risk: some runtimes assume the reported sandbox IP is actually configured on
the pod interface. **We must validate that containerd/CRI-O accept a reported pod
IP that is not present in the netns.** Mitigation if a runtime balks: the agent
already owns interface configuration, so we can fall back to configuring a
loopback-scoped or otherwise non-routable shadow of the fabric IP inside the
netns to satisfy the check without making the fabric reachable — but that
re-introduces a fabric address into the pod and must be a last resort. Treat the
clean path (fabric IP reported, absent from netns) as the design target and
prove it on the target runtime first.

## 4. Distribution: agents watch, controller compiles

- **Agents** (per-node DaemonSet) watch `Port`/`SecurityGroup`/`VPC`/`Subnet`
  filtered to their node, and translate the slice into eBPF map state. They are
  the only writers of `Port/{bind,status}`.
- **Controllers** (in the apiserver process or alongside) own the compile-down:
  - *VPC controller* — VNI lifecycle, gateway state, routing.
  - *SecurityGroup controller* — compile SGs + Ports → per-identity policy, fold
    identities into the numbering carried by Geneve.
  - *Port/IPAM* — mostly server-side at CREATE; the controller handles GC, DNS
    reconciliation, and identity assignment.
  - *Migration controller* — drives `/migrate` cutovers (§5).
  - *VM-Port controller* — watches `VirtualMachine`s, pre-creates persistent Ports.

Because allocation is transactional in the apiserver, controllers stay
level-triggered reconcilers over already-consistent state — they never arbitrate
allocation races.

## 5. Migration cutover as one transaction

Live migration must flip three things together or an operator can dial a stale
address mid-move:

1. the overlay **location map** (which node hosts `vpcIP/mac`),
2. the **bridge** `fabricIP ↔ vpcIP` mapping (target pod has a new fabricIP),
3. the **system-view DNS** A record for the port's stable name (→ new fabricIP).

`/migrate` stages the target binding; the migration controller programs the
target node's datapath, waits for readiness, then performs an atomic flip of
location + bridge + DNS, then tears down the source. The VPC IP/MAC never change,
so the VM and its in-VPC peers see nothing. (See `design.md` §5, §8 — the DNS
step is on the cutover critical path precisely because of name-based addressing.)

## 6. First milestone to build

Smallest slice that is observably alive, in order:

1. **Apiserver skeleton**: `VPC`, `Subnet`, `Port` kinds; Port CREATE does atomic
   IPAM; validation for overlaps/uniqueness. No datapath yet — prove allocation
   and watches with `kubectl`.
2. **Agent + CNI ADD/DEL** on the **system fabric only** (no overlay): pod gets a
   veth and a fabric IP, passes CNI conformance and kubelet probes. Validate the
   fabric-IP-reporting decision (§3) here.
3. **The bridge**: dual addressing + probe masquerade for a single pod; confirm
   the fabric is invisible from inside.
4. **VPC overlay** (Geneve), intra-VPC connectivity, gateway DNS — first real
   tenant network.

Everything after (identity/SG, persistent Ports + migration, multi-attach,
gateways) layers on this spine.
