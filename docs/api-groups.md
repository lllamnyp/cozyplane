# Two API groups: one CRD-local, one aggregated

Status: **design, awaiting review.** Supersedes the single-group "bootstrap
CRDs then take the group over" model in [control-plane.md](control-plane.md) §0.

## The forcing bug

A CRD does not stop existing when an APIService takes its group over. It is
shadowed for *routing* — every request goes to the aggregated server — but it
keeps publishing its OpenAPI paths. The kube-apiserver then tries to merge two
specs that describe the same paths, and gives up:

```
Error in OpenAPI handler: failed to build merge specs: unable to merge:
duplicated path /apis/sdn.cozystack.io/v1alpha1/namespaces/{namespace}/vpcs/{name}
```

The group's schema never serves. Every `kubectl apply` of a cozyplane object
dies client-side with *"failed to download openapi"*, while every core type
keeps working — which is exactly why this went unnoticed from the chart split
until 2026-07-12.

The single-group model can only *police* this: whoever installs second must
delete what the other installed. That is a race with Helm (a `helm upgrade` of
the CNI chart re-creates the CRDs the apiserver deleted), it needs the
apiserver to hold cluster-wide CRD **delete** rights, and it is one forgotten
`crds.enabled: true` away from a broken cluster API. **The collision is
structural, so the fix should be structural: never let two servers own the same
group.**

## The model

Two groups, same kinds, same schemas, different owners:

| Group | Served by | For |
|-------|-----------|-----|
| **`sdn.cozystack.io`** | the aggregated apiserver, only | the real API: tenants, operators, all new surface, custom validation, subresources, server-side allocation |
| **`crd.sdn.cozystack.io`** | CustomResourceDefinitions, only | the scaffold: installs with no apiserver (dev clusters, the kind e2e, a CNI-only deployment), and the bootstrap window before an aggregated server exists |

Neither group is ever served by the other mechanism. `config/crd/` only ever
contains `*.crd.sdn.cozystack.io` definitions; the aggregated group has no CRDs
at all, anywhere, ever. Both may therefore be installed at once — their paths
are disjoint, so OpenAPI merges cleanly — and the takeover machinery
(APIService adoption, stripping the `automanaged` label, deleting CRDs) is
**deleted, not fixed**.

The names say what they are: the unqualified group is the product; the
`crd.`-prefixed one is visibly the scaffold, so nobody ships a tenant-facing
manifest against it by accident.

## Which group does a client talk to?

All the clients are ours (CNI plugin, agent, controller). They resolve the
group **once at startup, by discovery**: if `sdn.cozystack.io` is served (an
APIService for it exists and is Available), use it; otherwise fall back to
`crd.sdn.cozystack.io`; if neither is served, the default network still works
(the agent's VPC watches are already best-effort) and VPC attachment fails
closed.

That keeps mode selection out of flags and out of the charts — a cluster's mode
is a fact about what is installed, and the clients read it.

## Codegen: one source of truth, two groups

The types are written once, in `api/sdn/v1alpha1` (group `sdn.cozystack.io`).
The CRD twin `api/sdncrd/v1alpha1` is **generated** from it — the same files
with the package and `+groupName` marker rewritten — by a `make generate` step,
never hand-edited. `controller-gen` then emits the CRD YAML from the twin, so
`config/crd/` is the CRD group by construction. CI's build-drift check catches
any divergence, exactly as it does for deepcopy and the eBPF object.

Each group gets its own generated clientset/informers/listers (codegen is
per-group). The clients talk to a small interface — `pkg/sdnapi` — with two
backing implementations, so the resolver is the only place that knows which
group is live.

**Alternative considered:** serve the CRD group through the dynamic client and
unstructured objects, avoiding a second clientset entirely. Rejected for now:
the agent's watch paths are typed informers, and unstructured conversion at
every event trades a build-time cost for a runtime one, in the datapath's
control loop.

## Migration

Objects do not move between groups by themselves, and they never did — the
current takeover is already storage-disjoint (the CRD store and the aggregated
etcd are different stores; the documented path is export → install → re-apply).
Two groups make that honest rather than magical:

```sh
kubectl get vpcs.crd.sdn.cozystack.io -A -o yaml \
  | sed 's#crd\.sdn\.cozystack\.io#sdn.cozystack.io#' \
  | kubectl apply -f -
```

The `--remove-bootstrap-crds` flag built on 2026-07-12 keeps exactly one job:
cleaning the **old single-group CRDs** off a cluster that predates this split
(dev clusters, and anything installed before it). It is the migration tool, not
part of the steady state.

## What this costs

- **A tenant-facing `apiVersion` depends on the install mode.** A manifest for a
  CRD-only cluster says `crd.sdn.cozystack.io/v1alpha1`. This is a real wart. It
  is mitigated by the naming (the scaffold is visibly the scaffold) and by the
  fact that anything real runs aggregated. Docs and examples target the
  aggregated group; the e2e, which runs CRD mode, derives the group at runtime.
- **Two clientsets** in the binary. Mechanical, generated, drift-checked.
- **The e2e and demo scripts must not hardcode the group.** They resolve it the
  same way the clients do (one `kubectl api-resources` lookup at the top).

## What it buys

- The OpenAPI collision cannot happen — not "is prevented", cannot happen.
- No takeover code: no APIService adoption, no `automanaged` label fight, no
  cluster-wide CRD-delete grant to the apiserver, no Helm race over who owns the
  CRDs, no ordering constraint between the two charts.
- A CRD-only install and an aggregated install are now genuinely independent
  products, which is what they always were in practice.

## Open questions (for review)

1. **Group name for the scaffold.** `crd.sdn.cozystack.io` (proposed) vs
   `local.sdn.cozystack.io` vs `bootstrap.sdn.cozystack.io`. The first says
   *how it is served*, which is the thing that actually distinguishes it.
2. **Does the scaffold need the whole kind set?** It could carry only what a
   CNI-only install can use (`VPC`, `Port`, `VPCBinding`, `SecurityGroup`) and
   omit the kinds that only make sense with server-side allocation
   (`ServiceVIP`, `FloatingIP`, `ExternalPool`, `HostFirewall`). Smaller
   surface, but two divergent kind sets to keep straight. Proposal: keep them
   identical — the generator makes it free, and "the scaffold is the same API,
   served differently" is a simpler sentence than any subset rule.
3. **Do we keep CRD mode at all?** The alternative is to delete it: the
   aggregated server becomes the only way to serve the group, and the kind e2e
   installs it. That removes the wart in (1) entirely, at the cost of making
   every dev cluster deploy cert-manager + etcd. Worth a decision now rather
   than carrying two modes forever.
