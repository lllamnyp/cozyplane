# Two API groups, split by concern: the fabric plane and the tenant plane

Status: **design, awaiting review.** Supersedes the single-group "bootstrap CRDs
then take the group over" model in [control-plane.md](control-plane.md) §0.

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

But the *interesting* reason for two groups is not that bug. It is that
cozyplane already has **two layers with different dependency floors**, and has
been pretending they are one:

- **The fabric plane** — a pod gets an underlay address and a working default
  network. This must come up with nothing but a CNI. No cert-manager, no etcd,
  no extension apiserver. Everything else in the cluster — including
  cozyplane's *own* apiserver and its etcd — is a default-network pod, so this
  layer is strictly beneath them.
- **The tenant plane** — VPCs, Ports, peerings, security groups, host
  firewalls, service VIPs, floating IPs. Rich API surface: server-side
  allocation, custom validation, cross-kind claims, subresources. It can demand
  the full stack, because nothing depends on it to boot.

Splitting the group along that seam is the structural fix. The two groups hold
**disjoint kinds**, so their paths are disjoint, so the merge collision cannot
occur — and unlike a scaffold-twin design there is nothing duplicated, nothing
generated twice, and nothing to keep in sync.

## The model

| Group | Served by | Holds | Dependency floor |
|-------|-----------|-------|------------------|
| **`fabric.cozystack.io`** | CustomResourceDefinitions, shipped with the CNI chart | the underlay: fabric IP claims, node fabric state | the kube API and nothing else |
| **`sdn.cozystack.io`** | the aggregated apiserver, only — never CRDs | `VPC`, `VPCBinding`, `VPCPeering`, `Port`, `SecurityGroup`, `HostFirewall`, `ServiceVIP`, `FloatingIP`, `ExternalPool` | apiserver + etcd + certs |

`config/crd/` contains only `fabric.cozystack.io` definitions. The tenant group
has no CRD anywhere, ever. The takeover machinery — APIService adoption,
stripping the `automanaged` label, deleting CRDs, the cluster-wide CRD-delete
grant — is **deleted, not fixed**.

## What lives in the fabric group

Today the fabric plane has no API at all: the CNI shells out to the `host-local`
IPAM plugin, which keeps a file store per node. That works, but it is the one
piece of allocation state in the system that is invisible, un-GC-able, and
leaks on an unclean DEL — the classic host-local failure. And a VPC pod's
fabric address is recorded in `Port.spec.fabricIP`, which means the *underlay*
address of a pod is owned by a *tenant-plane* object that requires the whole
aggregated stack to exist.

Proposed:

- **`FabricIP`** (cluster-scoped) — one object per allocated underlay address,
  `metadata.name` *being* the address. The claim is atomic by name uniqueness,
  exactly the trick `Port` already uses for VPC IPs, and it replaces the
  host-local file store. Spec: the node, the pod reference, the family. The
  controller/agent GC an object whose pod is gone, so a leaked address is
  visible (`kubectl get fabricips`) and reclaimable instead of silently wedging
  a node's range.
- **`NodeFabric`** (cluster-scoped, one per node) — the node's pod CIDRs, its
  addresses (today a `cozyplane.io/node-addresses` annotation on `Node`), MTU,
  Geneve port. This is state the agent already publishes by other means; giving
  it a kind makes the fabric plane self-describing rather than smeared across
  annotations and `/run/cozyplane/agent.json`.

**`Port` then stops conflating two things.** It keeps what it is actually for —
the tenant identity of a VPC NIC: the VPC IP, the pinned MAC, the persistence
that survives live migration — and *references* the `FabricIP` rather than
owning the address. A VPC pod needs both objects, which is honest: it is a
tenant workload, so it depends on the tenant plane by definition.

## Consequences that make this worth doing

- **The default network has no dependency on cozyplane's own API server.** It
  never really did; now the object model says so. A cluster whose aggregated
  apiserver is broken keeps scheduling and networking system pods — including
  the ones that would fix the apiserver.
- **Fabric IPAM becomes visible and reclaimable.** Losing the host-local file
  store removes a whole class of "the node ran out of IPs and nobody knows why".
- **The two charts stop being ordered.** `chart/cozyplane` (CNI + the fabric
  CRDs) and `chart/cozyplane-apiserver` (the tenant plane) are independent
  installs with no takeover between them and no `crds.enabled` foot-gun.
- **CRD mode disappears as a *mode*.** It was never a mode; it was the fabric
  layer wearing the tenant layer's clothes. There is no "CRD-served VPC"
  anymore — if you want VPCs, you install the apiserver.

## What it costs

- **The kind e2e must run the aggregated apiserver** to exercise VPCs, security
  groups, and the rest, where today it gets them from CRDs. The apiserver
  already has a single-pod etcd fallback (roadmap §1), and it can self-sign its
  serving cert, so this is bring-up work, not a new dependency on cert-manager.
  Cost is real; it is also the thing that makes the e2e test what actually
  ships.
- **A migration for existing clusters** (the dev cluster, and anything installed
  before this): fabric addresses currently live in host-local files and in
  `Port.spec.fabricIP`; tenant objects currently live in CRD storage on
  CRD-mode clusters. The `--remove-bootstrap-crds` flag built on 2026-07-12
  becomes the tool for the second half — it cleans the old single-group CRDs off
  a pre-split cluster — and the agent can adopt existing fabric addresses into
  `FabricIP` objects on first start (it already rebuilds local state from veth
  alias records, so the inputs are there).
- **`Port` changes shape** (it gives up `spec.fabricIP` for a reference). That is
  an API break, taken now while the API has one real consumer.

## Open questions (for review)

1. **Group name.** `fabric.cozystack.io` says what it is. Alternatives:
   `underlay.cozystack.io`, `node.cozystack.io`. Naming it for the *concern*
   (not for "local" or "CRD") is what keeps this from reading as a scaffold.
2. **Does `NodeFabric` earn its place in v1**, or does the fabric group start
   with `FabricIP` alone and leave node state in annotations until it hurts?
   Smaller first step; the group can grow.
3. **Does `FabricIP` replace host-local now, or later?** The group split and the
   OpenAPI fix do not *require* it — the fabric group could start empty-ish and
   the collision is already solved by moving the tenant kinds to
   aggregated-only. But an empty fabric group is a strange thing to ship, and
   the host-local leak is a real bug we would be walking past.
4. **`Port.spec.fabricIP` → reference, or keep it denormalized** for the agent's
   convenience (it currently reads one object to program the bridge)? A
   reference is cleaner; denormalizing is one fewer join in the datapath's hot
   reconcile path.
