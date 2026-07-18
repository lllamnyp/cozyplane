# Two API groups: `local.sdn.cozystack.io` and `sdn.cozystack.io`

Status: **BUILT 2026-07-12** (increments 1-3). `FabricIP` replaces host-local, the pool is flat, and the tenant kinds are aggregated-only.
Supersedes the single-group "bootstrap CRDs then take the group over" model in
[control-plane.md](control-plane.md) §0.

## Why two groups

The forcing bug is that **one group cannot be served by two mechanisms**. A CRD
does not stop existing when an APIService takes its group over: it is shadowed
for *routing*, but it keeps publishing its OpenAPI paths, so the kube-apiserver
tries to merge two specs describing the same paths and gives up —

```
Error in OpenAPI handler: failed to build merge specs: unable to merge:
duplicated path /apis/sdn.cozystack.io/v1alpha1/namespaces/{namespace}/vpcs/{name}
```

— the group's schema never serves, and every `kubectl apply` of a cozyplane
object dies client-side with *"failed to download openapi"* while core types
keep working. (Latent since the chart split; found 2026-07-12.)

The deeper reason is that cozyplane has **two layers with different dependency
floors**, and the object model has been pretending they are one:

- **The local layer** — a pod gets an underlay address and a working default
  network. It must come up with nothing but a CNI: no cert-manager, no etcd, no
  extension apiserver. Everything else in the cluster — including cozyplane's
  *own* apiserver and its etcd — is a default-network pod, so this layer sits
  strictly beneath them.
- **The extension layer** — VPCs, Ports, peerings, security groups, host
  firewalls, service VIPs, floating IPs: server-side allocation, custom
  validation, cross-kind claims, subresources.

| Group | Served by | Holds | Dependency floor |
|-------|-----------|-------|------------------|
| **`local.sdn.cozystack.io`** | CustomResourceDefinitions, shipped with the CNI chart | `FabricIP` (and see `NodeFabric` below) | the kube API, nothing else |
| **`sdn.cozystack.io`** | the aggregated apiserver, only — never CRDs | `VPC`, `VPCBinding`, `VPCPeering`, `VPCGateway`, `Port`, `SecurityGroup`, `HostFirewall`, `ServiceVIP`, `FloatingIP` | apiserver + storage |

Disjoint kinds ⇒ disjoint paths ⇒ the merge collision **cannot occur**, and
nothing is duplicated between the groups. The takeover machinery — APIService
adoption, stripping the `automanaged` label, deleting CRDs, the cluster-wide
CRD-delete grant — is deleted, not fixed.

### Why `local.`, and not `fabric.`

The obvious name for a group holding fabric IPAM is `fabric.cozystack.io`. It is
the wrong name, because it presumes what the group is *for*.

The extension server's registry may not stay on etcd. A **CRD-storage shim** —
the aggregated server persisting its objects as ordinary CRs through the kube
API instead of running its own etcd — is under consideration, and it would drop
the etcd dependency entirely while keeping the rich API surface (validation,
allocation, subresources) that CRDs cannot give us. Those stored CRs need a
group, and it cannot be `sdn.cozystack.io` (that is the collision, again). It
would be this group.

So `local.sdn.cozystack.io` is not "the scaffold". It is **everything of ours
that CRDs serve**: today the local layer, and possibly tomorrow the storage
substrate beneath the extension API. The name keeps that door open; `fabric.`
would have shut it.

## `FabricIP` — decided, and it fixes a live bug

Today the local layer has no API at all: the CNI shells out to the `host-local`
IPAM plugin, which keeps a file store per node under `/var/lib/cni/networks/`.

That store is **on disk and released only by CNI DEL**. A pod that goes away
while kubelet or containerd is down never gets a DEL, so its address stays
reserved across the reboot — forever. Enough of those and the node's range
fills with ghosts; the symptom is new pods stuck in `ContainerCreating` with
*"no IP addresses available in range set"*, while the corpses that caused it sit
in `Completed`/`Error`/`ContainerStatusUnknown`. There is no GC, no visibility,
and no way to tell a live reservation from a leaked one.

The VPC side of the house already solved this: the controller reaps a `Port`
whose claiming pod is gone. The fabric side simply never had an object to reap.

**`FabricIP`** (cluster-scoped, `local.sdn.cozystack.io`):

- `metadata.name` **is the address** (v4 dotted or v6, dashes for `:`), so the
  claim is atomic by name uniqueness — the same trick `Port` already uses for
  VPC IPs. No lock file, no per-node store, no double-allocation.
- `spec`: the node, the claiming pod (namespace / name / **UID**), the family.
- The controller GCs an object whose pod is gone (pod UID, not name — the
  stale-DEL-vs-reused-name lesson from `Port` applies unchanged), so a leaked
  address is visible (`kubectl get fabricips`) and reclaimable.
- The CNI stops shelling out to `host-local` for the default network and claims
  through the API — which it already talks to on every ADD anyway, to read the
  pod.

## The pool is FLAT — no per-node podCIDR carve-out

`FabricIP` allocates from **one cluster-wide pool**, not from a slice of it
handed to each node. This is a consequence of the claim being atomic
cluster-wide (name uniqueness in the API), and it is worth stating explicitly
because the Flannel-style carve-out is so idiomatic that its absence looks like
an oversight.

**The datapath already works this way everywhere else.** `remotes` is a 128-bit
LPM keyed address → node:

- VPC networks feed it **one entry per pod** (`hostCIDR(port.Spec.IP)`), from a
  pool with no node carve-out at all. Flat, already.
- The default network feeds it the node's `spec.podCIDR` — one aggregated entry
  per node.

The carve-out on net 0 is not a design decision; it is what `host-local`
requires, because a file-based allocator can only be safe within a range it owns
exclusively on that node. Replace it with a cluster-wide atomic claim and the
reason evaporates.

**The one real argument for per-node ranges is route aggregation** — if pods are
reachable by *native routing*, one route per node scales and one route per pod
does not (and BGP/cloud route tables want the aggregate). cozyplane does not
route natively: it Geneve-encapsulates and demuxes by map lookup, so aggregation
buys nothing. If a native-routing mode is ever wanted, that is the decision that
brings node ranges back — nothing else.

What flat buys:

- **No per-node exhaustion.** A /24 per node caps a node at 254 pods no matter
  how empty the cluster is; the mask is chosen up front and the fragmentation is
  permanent.
- **A pod's underlay address can survive a node move.** Live migration preserves
  a VM's VPC IP and MAC today, but its fabric IP comes from the node's slice, so
  it necessarily churns at cutover. From a flat pool it need not.
- `nodeCIDRFor` and every dependence on `Node.spec.podCIDR` disappear
  (kube-controller-manager may keep allocating it; nothing of ours reads it).

What it costs, and what must change before flipping:

- **Churn.** Every pod create/delete becomes a `remotes` write on *every* node,
  where today only node joins move it. This is Cilium's endpoint-propagation
  cost, and the agent already does exactly this for VPC `Port`s — but net-0 pod
  density is far higher, so the watch/update path must be event-scoped (the
  `svc_vips` workqueue shape), not a full rebuild per event.
- **`remotes` is sized `max_entries = 4096`.** Aggregated that is 4096 *nodes*;
  per-pod it is 4096 *pods*. It must grow (65k+) before the default network goes
  flat, or a busy cluster silently fails to program remotes.
- Rules that name "the pod range" (a `HostFirewall` admitting the pod CIDR, an
  `ipBlock`) take the **cluster** CIDR instead of a node's slice — simpler, but
  it is a semantic change in anything that hardcodes `Node.spec.podCIDR`.

## `Port.spec.fabricIP` — normalized away (BUILT)

`Port` currently conflates two things: the *tenant identity* of a VPC NIC (VPC
IP, pinned MAC, the persistence that survives live migration) and the pod's
*underlay* address (`spec.fabricIP`). Denormalizing the address into `Port`
invites exactly the bug class we should refuse to build: a fabric address that
churns while the `Port` holding a copy of it is never updated, and a datapath
programmed from the stale copy.

So: **`Port` drops `spec.fabricIP` entirely.** It does not gain a `fabricRef`
either — a reference whose value *is* the address (the `FabricIP` name) would
re-create the same stale-copy problem under a different field name.

The address lives in exactly one place — the `FabricIP` object — and both
objects point at the **pod**. Everything that used to read the copy now joins on
the pod UID:

- the **agent** (severing a revoked Port) resolves the address from the FabricIP
  store;
- the **CNI** tears the bridge down from the pod's own claims at DEL (read
  before releasing — releasing is what destroys them);
- the **responder** identifies a querying VPC pod from the underlay source of
  its DNS packet: address → `FabricIP` → pod → `Port`. Two lookups instead of
  one, and no denormalized address to go stale;
- the **datapath's restart rebuild** never read the Port at all — it re-derives
  from the veth alias records — so it needed no change.

**The sharpest instance of the bug this kills:** the persistent-Port controller
used to *copy the fabric IP into the Port on every live-migration cutover*
(`port.Spec.FabricIP = active.Status.PodIP`), because the launcher's address
churns while the VPC IP and MAC do not. That whole sync is deleted. A cutover
now re-points the Port at the new launcher and nothing else; the launcher's own
`FabricIP` holds the address.

## `NodeFabric` — what it would be, and why it waits

I put it in the first draft's table without ever saying what it was. It would
be a cluster-scoped object, one per node, holding the node's fabric parameters:
its pod CIDRs, its addresses (including the multi-NIC default-route address
that today rides in the `cozyplane.io/node-addresses` annotation), the MTU, the
Geneve port. Today that state is smeared across three places — the `Node`
object's `spec.podCIDRs`, an annotation we patch onto `Node`, and
`/run/cozyplane/agent.json`, a file the CNI reads off the local disk.

**Deferred, not adopted.** It is a tidying, not a fix: the annotation works, the
agent already publishes it, and every consumer already reads it. Adding a kind
that mostly restates `Node` earns its keep only when we need something `Node`
cannot carry — per-node datapath config that the *CNI* must read without a file,
say. Revisit then; the group can grow.

## What this costs

- **The kind e2e must exercise the extension API through the aggregated server**
  rather than through CRDs. If the CRD-storage shim lands, that is nearly free
  (no etcd to stand up); if it does not, the apiserver's single-pod etcd
  fallback (roadmap §1) covers it. Either way the e2e starts testing what
  actually ships.
- **A migration** for existing installs: tenant objects on a CRD-mode cluster
  live in CRD storage, and fabric addresses live in host-local files.
  `--remove-bootstrap-crds` (built 2026-07-12) cleans the old single-group CRDs
  off a pre-split cluster; the agent can adopt existing fabric addresses into
  `FabricIP` objects on first start, since it already rebuilds local state from
  the veth alias records.
- **`Port` is an API break.** Taken now, while the API has one real consumer.

## Build order

1. `local.sdn.cozystack.io` + `FabricIP`: types, CRD, controller GC, CNI claims
   through it, agent watches it. Default network only — no `Port` change yet, so
   nothing regresses. Ship it still allocating from the node's slice, so the
   claim path is proven before the pool changes shape.
2. **Go flat**: allocate from the cluster pool, feed `remotes` per pod at net 0,
   grow the map, event-scope the updates, drop `nodeCIDRFor`. This is the step
   that removes per-node exhaustion and lets an underlay address survive a node
   move.
3. Move the tenant kinds to aggregated-only: drop their CRDs from
   `chart/cozyplane`, delete the takeover machinery, make the clients resolve
   the extension group by discovery.
4. **BUILT.** `Port.spec.fabricIP` removed; every reader joins `Port` and
   `FabricIP` on the pod. VPC pods stop carrying an underlay address in a tenant
   object, and the migration-cutover copy is deleted.
5. (Open) the CRD-storage shim for the extension registry. Its motivation was
   dropping the etcd dependency — but with storage classes in place the built-in
   etcd now defaults to a **PVC**, so that dependency is durable rather than
   painful. The shim is no longer forced; revisit if etcd's operational cost
   bites again. (The group naming still leaves the door open: CRs the shim
   persisted would live in `local.sdn.cozystack.io`.)
