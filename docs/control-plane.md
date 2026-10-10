# cozyplane — control plane & implementation

How the operator comes alive. Companion to `design.md` (architecture). Group:
`sdn.cozystack.io`, version `v1alpha1`, served by the **cozyplane aggregated API
server** — with a CRD serving of the same group as the **bootstrap surface**.

## Metadata validation resource budget

The aggregated API must reject malformed metadata collections before the generic
Kubernetes store assembles its complete error list. Repeated invalid labels,
annotations, finalizers, owner references or managed-field entries can otherwise
amplify a small rejected request into substantial temporary allocations and CPU
work. Validate entries with Kubernetes' own rules, stop at the first invalid
entry, and return one bounded `Invalid` cause without echoing the input. Check
Kubernetes' existing byte limits before splitting or matching long keys, label
values, finalizers or field-manager names. Keep
collection-wide constraints (annotation bytes, a single controlling owner, and
conflicting deletion finalizers), existing storage hooks and valid metadata.
The same guard must cover create, update and the shared `/status` stores.
This bounds diagnostics; it does not make request decoding use constant memory.

Request-option validation needs the same protection before the generic resource
handlers. For create, update and patch, check the decoded `fieldManager` against
Kubernetes' 128-byte and printable-character rules before calling the SDK's
validator, which otherwise emits one error per invalid character. Return one
bounded `Invalid` cause without reading the request body or echoing the value.
Place this filter inside the existing generic handler chain so authentication,
authorization, request accounting and auditing retain their normal order.

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
  `HostFirewall`, `ServiceVIP`, `FloatingIP`.

Disjoint kinds, so disjoint paths, so the collision cannot occur. What this
deleted: APIService adoption, the `automanaged`-label fight with the CRD
autoregistration controller, the CRD-delete grant, and the ordering constraint
between the two charts. The server still registers its own APIService at
startup — but that is now a plain create, because nothing else creates one.

**It keeps registering it.** A one-shot at boot is not enough: the object is
ownerless by design, and anything that reconciles the cluster — Helm, a GitOps
agent, an operator — can delete or rewrite an object it believes it owns. That
is not hypothetical. On an in-place switch to the cozyplane networking variant
this server started first and took the APIService over, and the previous owner's
Helm release was upgraded minutes later with the APIService no longer in its
manifest, so Helm deleted it. The aggregated group vanished, every agent's
informers and the sdn controllers lost their kinds, and nothing recreated it —
recovery was a manual restart of this pod.

So registration is reconciled (`ReconcileAPIService`, 30s resync) for as long as
the server is serving the group, and a *recreation* is logged loudly rather than
at debug level: it means something outside this server deleted its own group's
registration, which is worth an operator's attention even though it self-heals.
The first pass stays blocking, so a server that genuinely cannot register still
fails at startup instead of serving a group nothing routes to.

The other half of that incident belongs to whoever owns the departing release:
on a variant switch the APIService should be handed over (keep rendering it, or
mark it `helm.sh/resource-policy: keep`) rather than deleted. This server's
reconcile bounds the damage to one resync interval; it does not make the delete
correct.

## 0a. Bootstrap ordering — the controller runs degraded, never crashlooping

Deleting the takeover deleted the ordering constraint *between the two charts*,
not the ordering itself. It survives as a plain fact of every fresh install:

> **The CNI installs first, and `sdn.cozystack.io` is served last.**

cozyplane is the cluster's CNI, so it must be up before anything else can be
scheduled. Its aggregated apiserver needs cert-manager (serving cert, etcd PKI),
an `EtcdCluster` and a `StorageClass` — all ordinary default-network pods, all of
which therefore need the CNI first. So there is always a window, minutes long on a
real cluster, in which `cozyplane-controller` is running and the group it mostly
watches does not exist. This is not a packaging mistake to order away; it is the
contract the controller is built against.

**The contract.** `cozyplane-controller` is one process that runs in two states.
It never exits because an API group is missing.

| | Degraded (group absent) | Full (group served) |
|---|---|---|
| FabricIP GC (`local.sdn.cozystack.io`) | running | running |
| health / readiness | Ready | Ready |
| VPC, VPCBinding, VPCPeering, VPCGateway, PortGC, PersistentPort, PortMembership, SecurityGroup, ServiceVIP, FloatingIP, Gateway | **not registered** | running |

The degraded set is everything that needs only the kube API and the CRD-served
group — today the FabricIP GC, which reclaims an underlay address whose pod is
gone. That work is *most* needed during bootstrap (pods are churning while the
platform installs), so taking it down with the missing group was the real cost of
the old behaviour.

**Why the old behaviour was a crashloop, not a wait.** controller-runtime treats
an unresolvable kind as fatal: `source.Kind` retries `no matches for kind "VPC" in
version "sdn.cozystack.io/v1alpha1"` until the per-source `CacheSyncTimeout`
fires, `Controller.Start` returns that error, and the manager exits. Every
controller in the process dies with it, kubelet restarts the pod, and the cycle
repeats for the length of the window.

**The gate.** `internal/apigate` holds a manager `Runnable` that polls discovery
for `sdn.cozystack.io/v1alpha1` (default every 15s) and calls the sdn
controllers' registration the first time it answers, adding them to the
*already-running* manager — controller-runtime accepts `Add` after `Start` and
starts the runnable on the spot. On a cluster where the group is served from the
start the first probe succeeds and nothing is deferred at all. The probe asks for
the group's **resource list**, not merely its presence in `/apis`: an APIService
whose backend is not up still advertises its group, and informers against it would
hang exactly as an absent group does. Registration happens once, and a failure
*inside* it is a wiring bug — still fatal, exactly as a `SetupWithManager` failure
was before.

**When the group goes away again** (the apiserver is uninstalled under a running
controller), the process does not exit. The gated controllers stay registered —
their relists fail and client-go retries, which is not fatal — and the gate keeps
polling so the state is visible.

**Observability.** The state is stated in the log at startup and on every
transition (`gated API group is not served yet; running DEGRADED…` /
`gated controllers started; no longer degraded`), and exported as
`cozyplane_controller_api_group_served` and
`cozyplane_controller_api_group_controllers_started`, both labelled by group. The
two can legitimately disagree — `served=0, started=1` is "the apiserver was
removed under running controllers", which is exactly the state worth alerting on.
Health and readiness stay plain pings on purpose: a degraded controller is doing
all the work currently possible, and flapping the pod NotReady for the whole
window would hide that rather than report it. (The shipped manifests pass
`--metrics-bind-address=0`, so the log is the signal until metrics are turned on.)

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
- **`VPCGateway`** — `{ vpcRef, loadBalancerClass?, nat.enabled, ingress.loadBalancer }`.
  A VPC's **one** north-south boundary, and the object that replaced
  `VPC.spec.egress.natGateway` — a bool on an object the tenant owned, so a tenant
  could grant *itself* internet. Its NAT identity comes from owned delegated
  `Service type: LoadBalancer` objects, one per address family
  ([external-addresses.md](external-addresses.md) §5) — who may mint an address is
  Service RBAC + the allocator's scoping, not a cozyplane verb. `status.natAddress`
  / `natAddress6` carry the addresses the VPC wears on the way out. A VPC has
  exactly one boundary (the oldest gateway wins). See [north-south.md](north-south.md).
  (`ExternalPool`, the old admin-defined CIDR list both this and FloatingIP drew
  from, is **deleted** — external-addresses.md §9.)
- **`HostFirewall`** (cluster-scoped, operator-only) — `{ nodeSelector,
  ingress[] (cidr/except → proto/port) }`. Ingress policy for the nodes
  themselves — the node-scoped sibling of NetworkPolicy (net-0 pods) and
  SecurityGroup (VPC ports). [host-firewall.md](host-firewall.md).
- **`FloatingIP`** — `{ vpcRef (local), target (tenant IP), loadBalancerClass? }`.
  Binds one externally-routable address 1:1 to a workload in a VPC,
  source-preserving (the ingress door in `design.md` §10). The address comes from
  an owned delegated `Service type: LoadBalancer` — the LB implementation
  allocates + attracts, cozyplane consumes `status.loadBalancer.ingress`
  ([external-addresses.md](external-addresses.md)). `status` carries the assigned
  `address` + `phase`; the binding is `Ready` (and the address advertised via the
  synthesized EndpointSlice + programmed) only while its `target` is a **live
  Port** — no live target ⇒ address held but dark. It needs no egress gateway
  (the NAT is in the eBPF bridge, not the gateway).

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

Boundary informer callbacks only enqueue a coalesced notification (capacity
one). A single worker reads current informer state, programs the maps, then
reports acknowledgements with a bounded request context. An API stall must
not retain an unbounded queue of object notifications. The five-second repair
tick remains, so real map drift and agent replacement are still detected.
Stable VPC status is not sent again; changed agent acknowledgements remain
observable and must not be filtered by a generation-only predicate.
Stable boundary map entries are compared with their current values before
writing. These BPF writes are kernel memory operations, not etcd disk writes.

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

Revocation drains every still-present veth proven to belong to the reaped Port,
including lingering sandboxes of terminated or already deleted Pods. The exact
Port UID in the live alias fences replacement owners; the alias is rechecked
under the shared writer lock. This proven-owner path does not depend on an
unused live Pod read. Legacy endpoints require sandbox or protected launcher
ownership proof before adoption. A Pod name or shared VPC address alone cannot
authorize revocation.

Revocation is **replayable across agent outages** via a sever finalizer
(`sdn.cozystack.io/sever`, set by the CNI at claim time): a reaped Port stays
*terminating* until the agent on its node severs (or confirms there is nothing
to sever) and releases the finalizer. An agent that was down finds the
still-terminating Port in its informer's initial sync and acts then. A Port
whose node no longer exists is released by the controller's Port GC — the
workload died with its node.

Before releasing that barrier on a cache-missing Node, Port GC confirms the
Node's absence with the live API reader. An initial or delayed informer view
cannot acknowledge severing on behalf of an existing node agent. Abandoned-Port
GC and binding revocation delete each observed Port with both UID and resource
version preconditions. Replacement or in-place rebinding between the read and
delete returns a conflict and retries from a new snapshot; a binding keeps its
reap finalizer while any deletion remains unresolved. Persistent VM Ports retain
their existing lifecycle exemption from abandoned-pod GC.

The binding reaper lists remaining grants and matching Ports through the live
API reader, not the informer snapshot. A newly granted binding must preserve
authorized endpoints even if its event has not arrived; a revoked grant or a
new Port missing from the cache must not escape the durable reap barrier. Both
lists consume all continuations before deletion, using 128-object pages and a
65,536-object/512-page limit. Failed or incomplete scans keep the finalizer and
delete nothing. Only name, UID and resource version of the candidate Ports are
retained after each page, keeping large spec/annotation payloads out of the
deletion work list. Conditional deletion still catches replacement/rebinding
after that snapshot; these live reads are not a distributed transaction with
concurrent grant creation.

A binding's `spec.vpcRef` is immutable. Retargeting a live grant would otherwise
lose the original VPC's durable Port-reaping target and let a consumer owning
the new VPC authorize removal of the old grant's finalizer. Running agents also
reconcile missing grants, but that is not a substitute for replayable revocation
while an agent is unavailable. To change VPC targets, delete the old binding,
let its reap barrier finish, then create the new grant. The aggregated strategy
and CRD admission policy reject retargeting even for an actor authorized on both
VPCs. Owner-authorized forwarding/CIDR changes and ordinary metadata updates
retain their existing behavior.

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
### Controller allocation serialization

VNI allocation additionally reserves a durable monotonically increasing counter
in `kube-system/cozyplane-vni-allocator` (Lease). Unlike the leader-election
Lease, this counter records historical allocations and must survive workload
deletion, restarts and backups. No VNI is recycled; the valid tenant range is
100 through `2^22-1`, below the Geneve forwarding/gateway flag bits.

The controller manager requires leader election, including a single-replica
Deployment: a rolling update also overlaps processes. All instances use the
same coordination Lease, `kube-system/sdn-controller.cozystack.io`. Disabling
election is rejected at startup. Live reads and serial reconciles allocate VNI
and group IDs only inside this leader; they are not distributed allocation locks
on their own. The controller ServiceAccount has a namespaced Lease role.
APIService reconciliation explicitly writes insecureSkipTLSVerify=false when
TLS verification is enabled. Moving from a self-signed development registration
to the production CA-injection configuration must revoke the old TLS bypass;
omitting the field from a merge patch would preserve it.

Peering CIDR overlap checks parse each candidate once. They sort and collapse
one list into disjoint prefixes, then search that list for each prefix in the
other VPC. There is no pairwise reparsing of both lists: transient memory is
linear and lookup work grows with sorting and binary searches. IPv4, IPv6,
host bits, mapped IPv4 spellings and ignored unparsable entries retain the
existing overlap definition; this changes no two-sided peering authorization.

The peering status controller uses cache indexes for the complete directed
VPC pair and for both current VPC references. Reciprocal resolution/events
copy only candidates for the reverse pair; a VPC event copies only halves
referencing that namespace/name. Indexes track reference updates and removal,
without accumulating historical keys. The Matches predicate still checks both
references and deletion timestamps; an index hit alone is not consent.

VNI live-scan safeguard (SEC198): bootstrap high-water scans and duplicate
ownership checks use 128-object pages, at most 65,536 objects per collection.
Bootstrap shares a 30-second deadline across VPC, Port and ServiceVIP scans;
the complete Lease reservation/retry operation has the same bounded lifetime.
Duplicate checks also have a 30-second budget. Counter reservation must
independently observe a successful Lease write before returning a VNI (SEC199).
A retry helper returning nil after an interrupted attempt is not success; both
parent cancellation and per-request deadline errors must propagate. Earlier parent cancellation or
deadlines always win. The high-water includes orphaned Port/ServiceVIP claims
and all VPCs, including terminating objects; failed, oversized or incomplete
scans publish no partial allocation or duplicate verdict. Pagination bounds
transient client payloads, not total stored objects or a universal memory quota.

VPC status reconciliation still checks live duplicate VNI ownership, but sends
a status update only when it changes VNI or phase. Repeated metadata/status
notifications on an already Ready VPC do not send identical writes. Allocation
and duplicate repair still publish their new VNI before returning.

VPC CIDR admission bounds spec.cidrs to 1,024 prefixes and 64 bytes per prefix, validates IP CIDR syntax on create or CIDR changes, and returns bounded index-only diagnostics. CIDRs remain optional and tenant ranges may overlap. Unchanged legacy CIDRs permit metadata/finalizer and unrelated updates so invalid objects can still be repaired or deleted. Runtime CNI and agent checks protect against legacy objects already stored. This ceiling does not guarantee aggregate datapath capacity or replace ResourceQuota.

### Persistent NIC creation transaction

Within a VNI, persistent Port creation checks the current namespace/VM/VPC/NIC identity in a paged etcd snapshot before writing. The transaction compares the modification revision of every Port key in that VNI with the snapshot revision, alongside the existing Port/ServiceVIP address guards. A concurrent creation or identity-affecting update invalidates the snapshot; eight retries and a 65,536-claim/128-per-page scan ceiling bound the work. The allocation client caps each gRPC response at 16 MiB, and each scan stops before decoding more than 64 MiB of stored data; exceeding either limit fails ADD without a partial allocation. This includes legacy claims without adding an index, lease or historical reservation. Empty-collection compares admit the first claim. A matching claim returns AlreadyExists with the actual holding Port name, so ADD can fetch it, verify the instance UID and pinned IP/MAC, and bind or stage it. NIC identity fields are immutable through normal and status updates; pinned VM MAC changes are refused. Unrelated status changes within a busy VNI may cause a bounded retry or an ADD failure for kubelet to retry; they cannot permit a second identity.

VPCGateway reference safeguard (SEC200): the local VPC reference must be a
nonempty DNS subdomain name of at most 253 bytes, on both create and update.
Legacy invalid references are omitted from VPC indexes and notification queues
before hashing or retention. Status reconciliation treats them as unresolved
without looking up the invalid target or allocating a boundary for it; the
existing unresolved-VPC cleanup and status contract applies. A valid retarget
still notifies both old and new VPCs. Diagnostics do not echo invalid values.
This bounds reference bytes per request, not valid update frequency or all
controller-cache memory. Namespace-selector indexes require separate review.

VPCGateway selector-reference safeguard (SEC201): appliance and route namespaces
are optional (empty means the gateway namespace); nonempty values must be DNS
labels of at most 63 bytes. Admission create/update stops on the first invalid
reference with a bounded diagnostic, and rejects more than 4096 route declarations
or prefix candidates, matching the existing route-resolution ceiling. The
namespace index does not retain invalid keys or expand oversized legacy route
arrays. Legacy invalid next-hop namespaces do not reach Pod lookups: valid
route prefixes remain published with no next hop (blackholes); an invalid
appliance namespace resolves no appliance. Correct references recover normally.
No new workers or historical state are introduced.

Gateway healing lookup safeguard (SEC202): list the system gateway Pods first,
then confirm a live Ready Pod belongs to the current VPC gateway Deployment
through its ReplicaSet UID before consulting Ports. Use the existing spec pod
namespace/name index plus VPC labels, then retain the existing gateway flag,
Pod UID and VPC identity checks. No Ready owned Pod means no Port list. A missing
index or failed lookup is an error, never a broad scan or a reason to delete a
Pod. Destructive healing still requires UID/resourceVersion preconditions.
Register the shared Port pod index in VPCGateway setup before Gateway and VPN
setup; no duplicate indexes, historical state or new workers.

Actual-cache test transports must honor request cancellation and return API
list metadata, never reuse the cache reader s continue-not-supported marker as
an upstream continuation. Restart fixtures clear that marker and supply the
current snapshot/resourceVersion. This prevents a simulated pager from retaining
repeated pages after a test is cancelled; it is not a tenant exploit finding.

Peering reference safeguard (SEC219): both VPC names must be nonempty DNS subdomain names of at most 253 bytes, and the remote namespace a nonempty DNS label of at most 63 bytes. Reject unusable references before delegated authorization, without echoing their contents. Controller and DNS indexes omit malformed legacy halves before joining or retaining keys; reconciliation and agent replay resolve no target or grant for these halves. Unchanged legacy specs still permit metadata cleanup and deletion. Valid references retain exact spelling, namespace separation and reciprocal consent. This bounds added reference work and index keys; informer objects and aggregate object counts still require operator resource limits.

Binding reference safeguard (SEC220): creation validates the VPC name and optional namespace against the same Kubernetes name bounds before export authorization. Immutable-target rejection never echoes a submitted reference. Legacy invalid targets do not reach NAD name/config construction or local grant-map hashing. The empty namespace remains the same-namespace default; unchanged legacy metadata cleanup and owner-authorized withdrawal/finalizer release keep their existing paths. These guards do not grant attachment, change pinned NIC identity or remove revocation barriers.

Authorization diagnostics also omit oversized legacy reference text without altering the attributes sent to the authorizer. This preserves owner-authorized cleanup while keeping a denied withdrawal response bounded; malformed legacy reference bytes must not be repeated in the APIStatus message and cause.

### Multiple workload interfaces

`NetworkAttachment` was never built and is deliberately dropped. Pod attachments
are a JSON-list annotation; the VPC owner authorizes forwarding through
`VPCBinding`, with its existing `export` check. See [multi-attach.md](multi-attach.md).
KubeVirt additional guest NICs use the Multus adapter and a generated
NetworkAttachmentDefinition per binding. This does not add an attachment grant;
the delegate CNI verifies current binding consent. See
[kubevirt-multi-nic.md](kubevirt-multi-nic.md).
