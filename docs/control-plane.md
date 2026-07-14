# cozyplane — control plane & implementation

How the operator comes alive. Companion to `design.md` (architecture). Group:
`sdn.cozystack.io`, version `v1alpha1`, served by the **cozyplane aggregated API
server** — with a CRD serving of the same group as the **bootstrap surface**.

## 0. Two groups, two owners — and no takeover

**Rewritten 2026-07-12** ([api-groups.md](api-groups.md) is the design). The old
model — one group bootstrapped as CRDs and then *taken over* by the aggregated
apiserver — is gone, along with all of its machinery. It could not work: a CRD
keeps publishing its OpenAPI paths after an APIService takes the group over, the
two specs collide on duplicated paths, the group's schema stops serving, and
`kubectl apply` fails for every object in the group while core types keep
working.

The split is by concern, not by serving mechanism:

- **`local.sdn.cozystack.io`** — CRDs, shipped with the CNI. Underlay IPAM
  (`FabricIP`). Its dependency floor is the kube API and nothing else, because
  everything above it — cert-manager, etcd, cozyplane's own apiserver — runs as
  default-network pods and therefore needs this layer first.
- **`sdn.cozystack.io`** — the aggregated apiserver, only, never CRDs. `VPC`,
  `VPCBinding`, `VPCPeering`, `VPCGateway`, `Port`, `SecurityGroup`,
  `HostFirewall`, `ServiceVIP`, `FloatingIP`, `ExternalPool`.

Disjoint kinds, so disjoint paths, so the collision cannot occur. What this
deleted: APIService adoption, the `automanaged`-label fight with the CRD
autoregistration controller, the CRD-delete grant, and the ordering constraint
between the two charts. The server still registers its own APIService at
startup — but that is now a plain create, because nothing else creates one.

The old text follows for the record.

## 0b. (Historical) Two serving modes, one group — and the takeover

The group has two servers, packaged as two charts, because of a deploy-time
truth: **the CNI must install before cert-manager, and the aggregated apiserver
needs cert-manager** (serving cert, etcd PKI).

- **CRD mode** (`chart/cozyplane`, `crds.enabled`, the default): the group is
  served by CRDs from the moment the CNI lands. No cert-manager, no etcd.
  Tenancy works immediately; validation is CEL-grade, no subresources.
- **Aggregated mode** (`chart/cozyplane-apiserver`): the real apiserver with its
  dedicated etcd. In Cozystack it is a separate component that `dependsOn`
  cert-manager. Installing it creates the explicit APIService for
  `v1alpha1.sdn.cozystack.io`, which **atomically takes over** the group's
  serving from the CRDs' implicit APIService, and every request from that moment
  hits the aggregated server. **The server then deletes the bootstrap CRDs.**

The takeover is storage-disjoint: objects in the CRD store (kube etcd) are not
visible through the aggregated server (its own etcd). On a fresh cluster that is
a non-event — the CRD store is empty when the apiserver lands (tenants come
later). On a cluster with live CRD-stored objects, export → install → re-apply
(see the cozyplane-apiserver chart README).

Three mechanics of the takeover, all learned the empirical way:

- **The bootstrap CRDs must be REMOVED, not merely shadowed** (corrected
  2026-07-12 — an earlier version of this doc claimed they could "stay
  installed, shadowed and inert"). They are shadowed for *routing* only: a CRD
  goes on publishing its OpenAPI paths after the APIService takes serving over,
  so the kube-apiserver tries to merge two specs describing the same paths and
  gives up —

  ```
  Error in OpenAPI handler: failed to build merge specs: unable to merge:
  duplicated path /apis/sdn.cozystack.io/v1alpha1/namespaces/{namespace}/vpcs/{name}
  ```

  The group's schema then never serves, and every `kubectl apply` of one of our
  objects fails client-side with *"failed to download openapi"* — while core
  types keep working perfectly, which is exactly why this hid for so long. The
  apiserver deletes the CRDs itself once its APIService lands
  (`--remove-bootstrap-crds`, on by default), which is safe precisely because
  the takeover is storage-disjoint (below). The CNI chart must also stop
  shipping them (`crds.enabled: false`) wherever the apiserver is installed, or
  the next `helm upgrade` puts them back.

- **The APIService cannot be a chart manifest.** The kube-apiserver
  auto-registers an APIService for every served CRD group, so in the takeover
  scenario the object always pre-exists — and Helm refuses to adopt an object
  it does not own. The aggregated server therefore registers (or takes over)
  its own APIService at startup (`--ensure-apiservice-service`), stripping the
  `kube-aggregator.kubernetes.io/automanaged` label so the CRD autoregistration
  controller stops reconciling it back to local serving.
- **Established watches do not follow the takeover.** A client that opened its
  watch streams against the CRD serving keeps them — the kube-apiserver closes
  idle watch connections only after 30–60 minutes — so it watches the shadowed
  store and never sees aggregated-store objects. After the takeover (and after
  the import, on a migrating cluster), **restart the cozyplane controller and
  agents**; import-first ordering matters, so agent startup pruning sees a
  populated store and no-ops instead of tearing down live datapath state.

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

> **Built vs sketched.** This section predates the implementation and still carries
> shapes that were never built. **`Subnet`, `NetworkAttachment` and `GatewayPolicy`
> do not exist** — a VPC carries its CIDRs directly, a pod attaches by annotation +
> `VPCBinding`, and the VPC's door is the shipped **`VPCGateway`**. Treat the
> unbuilt three as vocabulary from `design.md` §10, not as API.

### Declarative

- **`VPC`** — `{ cidrs[v4,v6], mtu }`. Server allocates a unique **VNI** on create
  (validation rejects exhaustion/collision). (`routingMode` and `encryption` were
  sketched here and never built.) `spec.egress` is **gone** — the boundary is a
  `VPCGateway`, because a bool on an object the tenant owns lets a tenant grant
  itself internet.
- **`Subnet`** *(not built)* — `{ vpcRef, cidr, gateway, allocRanges[], dns }`.
- **`SecurityGroup`** — `{ selector (labels, VPC-scoped), ingress[], egress[] }`;
  rules reference other SGs / FQDNs / external CIDRs — never internal IPs.
- **`NetworkAttachment`** — binds a workload class to `{ vpcRef, subnetRef,
  securityGroups[] }`. The Multus replacement; referenced from a pod by
  annotation. A pod may reference several.
- **`VPCPeering`**, **`GatewayPolicy`** — cross-VPC and the controlled doors
  (DNS/metadata/API/egress) from `design.md` §10.
- **`VPCGateway`** — `{ vpcRef, poolRef?, nat.enabled, ingress.loadBalancer }`. A
  VPC's **one** north-south boundary, and the object that replaced
  `VPC.spec.egress.natGateway` — a bool on an object the tenant owned, so a tenant
  could grant *itself* internet. Creating one requires the **`attach`** verb on the
  referenced `ExternalPool` (the `export`/`peer` escalation-gate pattern): the
  operator grants the pool, the tenant opens its own door onto it. `status.natAddress`
  carries the address the VPC wears on the way out. A VPC has exactly one boundary
  (the oldest gateway wins). See [north-south.md](north-south.md).
- **`ExternalPool`** (cluster-scoped) — `{ cidrs[] }`. An admin-defined range of
  externally-routable addresses; the MetalLB IPAddressPool analog, minus the
  announcement — **cozyplane attracts nothing**, so there is no `advertisement`
  field to configure. `status` tracks allocation counts.
- **`HostFirewall`** (cluster-scoped, operator-only) — `{ nodeSelector,
  ingress[] (cidr/except → proto/port) }`. Ingress policy for the nodes
  themselves — the node-scoped sibling of NetworkPolicy (net-0 pods) and
  SecurityGroup (VPC ports). [host-firewall.md](host-firewall.md).
- **`FloatingIP`** — `{ vpcRef (local), target (tenant IP), poolRef?, address? }`.
  Binds one pool address 1:1 to a workload in a VPC, source-preserving (the
  ingress door in `design.md` §10). `status` carries the assigned `address` +
  `phase`. The address is reserved permanently, but the binding is `Ready` (and
  the address advertised + programmed) only while its `target` is a **live Port**
  — a running pod to advertise from and deliver to; no live target ⇒ reserved but
  silent. It needs no egress gateway (the NAT is in the eBPF bridge, not the
  gateway).

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

## 6. Tenancy & authorization (VPC sharing)

How a pod is *authorized* to attach to a VPC. The hard constraint: at CNI/attach
time the only trustworthy fact about the requester is the **pod's namespace**
(kubelet hands it to us via `CNI_ARGS`; the annotation is forgeable). The
identity of whoever created the workload is three hops upstream and gone. So
every authorization decision must be made earlier, where an authenticated
identity still exists, and **materialized into an object the datapath can read by
namespace.**

### Scopes (these refine §2)

- **`VPC` is namespaced** — it lives in the owner tenant's namespace. The
  namespace *is* the authorization anchor (see below), which is what lets us drop
  any `use`-verb SAR for same-domain attach.
- **`Port` stays cluster-scoped**, named by the globally-unique **VNI**:
  `v<vni>.<ip-dashed>`. Cluster scope keeps the atomic name-based IPAM claim in a
  single global keyspace; tenants never address Ports by name (they read them
  through a projected subresource, §6 *Observability*).
- **`VPCBinding` is namespaced** — it lives in the **consumer (target)**
  namespace and references the owner VPC via `spec.vpcRef {namespace, name}`.

### Attachment (data plane, no identity)

- Pod annotation: `sdn.cozystack.io/vpc: [<owner-ns>/]<vpc>`. No slash → the
  pod's own namespace.
- Attach is **always default-deny** unless a `VPCBinding` in the pod's namespace
  authorizes `(podNamespace, vpcRef)` — **including the same-namespace case**. A
  VPC's namespace expresses *ownership*; a `VPCBinding` expresses *use*. Even the
  owner attaching its own pods creates a binding in its namespace (the `export`
  SAR passes trivially since it owns the VPC). This keeps one uniform code path —
  the agent reads only the trustworthy namespace + binding existence, no
  same-namespace special-casing and no identity required here.

### Authorization (control plane, has identity) — the two-check create gate

A `VPCBinding` is created by the **VPC owner**, reaching into the consumer
namespace. Create is gated by a conjunction, both checks landing on the same
principal:

1. **Standard RBAC** — caller has `create vpcbindings` in the target namespace
   (normal authz chain, before the strategy).
2. **Custom SAR** — in the create strategy, a `LocalSubjectAccessReview` in the
   *VPC's* namespace: `verb=export, resource=vpcs, resourceName=<vpc>`.

Check 2 is load-bearing, not hardening: a tenant trivially holds `create
vpcbindings` in its own namespace, so without the `export` SAR a subtenant could
point a binding at *anyone's* VPC and attach — a self-service escalation. The
`export` verb is the only thing standing in that gap. Because both permissions
must be held by one principal, **the binding never crosses a trust boundary** —
it is one party exercising authority it already holds on both ends.

### Nested tenancy

This falls out of Cozystack's tenant RBAC hierarchy with no special-casing: a
parent tenant admin natively holds `export` on their VPC *and* `create
vpcbindings` in subtenant namespaces, so they can bind their VPC into a
subtenant. A subtenant holds neither upward.

### Binding vs peering (the AWS line)

`VPCBinding` is the **intra-domain** primitive (one principal with authority on
both ends). Genuine **cross-tenant** connectivity — two separately-owned VPCs,
each side independently consenting — is **`VPCPeering`** (built), not a binding.
Mirrors AWS: RAM/VPC sharing stays within accounts you control; cross-account is
peering. Collapsing the two is how you accidentally build a sharing escape hatch.

A peering is **two symmetric halves**: each owner creates a `VPCPeering` in its
own namespace (`spec.vpcRef` = its VPC, name-only; `spec.peerRef` = the remote
VPC), and the peering is live only while both halves exist and reference each
other.

- **Consent is reciprocity.** No verb is checked on the *remote* VPC and there
  is no imperative accept step — an unmatched half just sits `Pending`, which
  *is* the visible, declarative peering request. The AWS request/accept
  handshake, without the workflow.
- **Revocation is unilateral**: either owner deletes their half. There is no
  finalizer and nothing to reap — no Ports were created; agents just remove the
  datapath pair, and in-flight cross-VPC traffic starts dropping at watch
  latency.
- **The agents key the datapath on the halves' specs directly** (mutual match +
  both VNIs), not on status — a stale `Ready` can't hold a revoked peering open.
  The controller's status (`Pending`/`Ready`, `PeerMatched`/`VPCReady`/
  `PeerVPCReady` conditions, `peerVNI`) is observability only.
- **Specs are immutable** (enforced by the aggregated apiserver's update
  strategy, and by a CEL transition rule in CRD mode): the refs pin the identity
  the reciprocal half consented to; re-pointing means replacing the object,
  which re-runs the handshake.
- **Non-transitive by construction**: the datapath allows exact `(net, net)`
  pairs, so a↔b plus b↔c never grants a↔c.
- **Intra-domain peering is subsumed**: a parent tenant with authority over both
  namespaces simply creates both halves; no second code path.
- Peered traffic is routed **natively** (no NAT), so the two CIDRs must not
  overlap — enforced by the agent (it won't program a peering whose VPCs'
  CIDRs overlap) and surfaced as the `CIDRsDisjoint` condition. Overlapping
  VPCs otherwise coexist fine (net-scoped delivery); they just can't peer.

Creating a half requires `create vpcpeerings` in the owner namespace **and the
`peer` virtual verb on the local VPC** (`spec.vpcRef`), mirroring `export`
([#1](https://github.com/lllamnyp/cozyplane/issues/1)): verbs on a VPC express
what a principal may do with it — `export` grants use, `peer` connects it
outward. This enables delegating peering management in a namespace without
authority over every VPC in it. Enforcement is dual-mode, like `export`: the
aggregated apiserver checks the verb in the create strategy (admission never
sees aggregated resources — which is also why both verbs are now
strategy-enforced there; a VAP alone covers only CRD mode), and CRD mode uses
the VAP twin. No verb is checked on the *remote* VPC — consent stays the
reciprocal half.

### Revocation

The owner deletes the `VPCBinding` (they hold delete in the target namespace).
A reap finalizer (`sdn.cozystack.io/reap-ports`) holds the binding until the
`VPCBindingReconciler` deletes the `Port`s for `(namespace, vpc)` — *unless*
another still-live binding in that namespace authorizes the same VPC, in which
case the pods stay (reaping waits for the last grant to go).

Deleting a Port drives the sever:

- **Other nodes** drop the reaped pod's remote `/32` (their agents' Port-delete
  handler), removing cross-node reachability.
- **The pod's own node** severs the *live* local datapath without disturbing the
  running pod: the agent reassigns the pod's `ports`-map entry to a reserved
  `QuarantineNet` id — never programmed into `networks` and never part of a
  peering pair — so `from_pod`/`to_pod` drop its traffic both ways via the
  existing isolation check; it removes the `locals` entry and tears down the
  fabric↔vpc bridge. The pod keeps running, disconnected (NetworkPolicy-like).

The agent distinguishes revocation from ordinary pod deletion (where CNI `DEL`
already cleaned up) by checking the owning pod still exists, isn't terminating,
and matches the Port's recorded pod UID — so a stale delete for a name-reused pod
can't cut off an unrelated one.

Revocation is **replayable across agent outages** via a sever finalizer
(`sdn.cozystack.io/sever`, set by the CNI at claim time): a reaped Port stays
*terminating* until the agent on its node severs (or confirms there is nothing
to sever) and releases the finalizer. An agent that was down finds the
still-terminating Port in its informer's initial sync and acts then. A Port
whose node no longer exists is released by the controller's Port GC — the
workload died with its node.

One known limitation of this iteration: **re-granting** (recreating the binding)
does not restore a severed pod — it must be recreated.

### Observability — the `/ports` subresource was DROPPED

A `/ports` virtual subresource on `vpcs`/`vpcbindings` was proposed here, so a
tenant could "list the ports of my VPC" without a cluster-scoped read.

**Dropped on reflection, and not for a technical reason.** Ask what a tenant *does*
with that list: it discovers its peers **by address** — and tenet 4 says identity,
not addresses. Membership is by label, name resolution is by the split-horizon DNS,
and policy selects on metadata. A tenant that enumerates its VPC's addresses is
doing the one thing the design refuses to make load-bearing, and the list would be a
surface we defend forever.

What a tenant genuinely could not do was learn **its own** address — `status.podIP`
is the *fabric* IP, and the real identity lived only on the cluster-scoped `Port`.
That is answered without any new surface: the CNI stamps the pod it already owns with
`sdn.cozystack.io/vpc-ip` and `sdn.cozystack.io/vpc-mac`. See
[multitenancy.md](multitenancy.md) (R1, R3).

### Tenancy: the persona, and the ceiling

- **Tenant RBAC.** `cozyplane-tenant-edit` / `cozyplane-tenant-view` aggregate into
  the built-in admin/edit/view ClusterRoles and list **only namespaced kinds**. That
  is load-bearing, not tidiness: a RoleBinding cannot grant access to a
  cluster-scoped resource, so `list ports` is unreachable from a tenant role **by
  construction**. One `list ports` would hand over every other tenant's pod names,
  VPC addresses, MACs and node placement.
- **Quota.** The aggregated server enforces plain `ResourceQuota` —
  `count/vpcs.sdn.cozystack.io` and friends — through the Kubernetes quota
  **`Evaluator`** interface, because the kube-apiserver's quota admission cannot see
  an aggregated API's kinds. No new kind, no new vocabulary. `Port` and `ServiceVIP`
  are deliberately unbounded: a tenant creates neither, and `count/pods` /
  `count/services` already bind them.

### Aggregated apiserver — the only mode

The `sdn.cozystack.io` group is served **exclusively** by the aggregated API server
(a dedicated etcd, a cert-manager serving cert, an `APIService`). It is *not* served
as CRDs, and there is no `apiserver.enabled` switch: the group and the CRD-served
group are disjoint by construction (`local.sdn.cozystack.io` holds the CRDs — see
[api-groups.md](api-groups.md)).

That disjointness is why the escalation verbs live where they do. **Admission
webhooks and `ValidatingAdmissionPolicy` never see aggregated resources**, so
`export`, `peer` and `attach` are enforced in the registry **strategies**, not in a
VAP. A VAP targeting `sdn.cozystack.io` cannot fire and would be a silent no-op.

The registries live in `pkg/registry/sdn/{vpc,port,vpcbinding,vpcgateway,…}`; VPC
carries a `/status` subresource so the controller's `Status().Update()` works
unchanged; the Port name is the atomic IP claim (etcd name-uniqueness).

## 7. First milestone to build

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
