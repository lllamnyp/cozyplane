# Multi-tenancy — the rules

Cozyplane's datapath has been multi-tenant since early on: VNI-scoped delivery,
overlapping tenant CIDRs, default-deny across VPCs, identities scoped to the VPC,
a declared north-south boundary with its own egress identity and its own meter.

Its **API** was not — not because isolation leaked (it did not), but because there
was no *tenant* in it: no role a tenant could hold, no surface shaped for one, and
no ceiling on what one could consume. An operator did everything, and a tenant was
a thing the datapath enforced rather than a thing the API knew about.

That gap is closed. **A namespace is the tenant** — cozyplane learns tenancy from
no platform, and the namespace is the whole anchor.

This document is the rules. Each one is stated as a rule, justified, and kept — or
justified badly and dropped. A rule with no justification is a future attack
surface someone will have to defend.

| | rule | state |
|---|---|---|
| **R1** | A tenant can learn the network identity of its own workloads | **built** — the CNI stamps the pod |
| **R2** | A tenant can enumerate nothing it does not own | **built** — structurally; namespaced roles only |
| **R3** | ~~A tenant can list the ports of its VPC~~ | **dropped** — address-thinking (tenet 4) |
| **R4** | A tenant opens its own door; it does not mint what is behind it | already true (`attach`) |
| **R5** | A tenant cannot exhaust what it does not own | **built** — stock `ResourceQuota` |
| **R6** | Consent is mutual, and never inferred | already true (`export` / `peer`) |
| **R7** | Everything a tenant sends across a boundary is attributable to it | already true (north-south metering) |
| **R8** | ~~A tenant's namespaces are one tenant~~ | **dissolved** — a namespace *is* the tenant |
| **R9** | Operators are not tenants | already true |

Only one thing in this document is outstanding, and it is deliberately unbuilt: how
a tenant reads the pinned address of a **stopped VM** (§ "The mechanism for R1").

---

## The rules

### R1. A tenant can learn the network identity of its own workloads.

**Keep — built** (Option C below; `test/tenant-e2e.sh`). This was the one thing a
tenant genuinely could not do.

`status.podIP` is the **fabric IP** — the underlay handle, the address kubelet
probes and the platform routes. It is *not* the address anything inside the VPC
uses, and it is not the address the tenant's own guest sees on its interface. The
tenant's actual identity — its VPC address, and for a VM its pinned MAC — appears
in exactly one place in the API: the cluster-scoped `Port`. Which the tenant
cannot read (R2).

So a tenant literally could not answer "what is my VM's address?" from the API.
That is not a tenancy nicety; a VM guest's provisioning, a tenant's own inventory,
and the entire live-migration promise (*this identity survives a node move*) are
all about an address the tenant could not see. The e2e says it better than prose:

```
status.podIP (the FABRIC ip): 10.244.176.237
annotated VPC ip / mac:       10.90.0.2 / 22:bc:74:2a:51:a3
the Port's truth:             10.90.0.2
```

Kubernetes was showing the tenant a different address, on a different network.

### R2. A tenant can enumerate nothing it does not own.

**Keep — built** (`cozyplane-tenant-edit` / `-view`). This is the rule the whole
model rests on.

`Port` and `ServiceVIP` are **cluster-scoped**, and that is load-bearing: the IPAM
claim is atomic *because* the name `v<vni>.<ip>` is globally unique. It is an
implementation detail of allocation — and it must never become a tenant-visible
surface. A single `list ports` grant would hand any tenant every other tenant's
pod names, VPC addresses, MACs and node placement. The datapath's isolation would
still hold perfectly, and it would not matter: we would have leaked the fleet's
topology through the front door.

Corollary: **no tenant role may ever include a cluster-scoped read.** If a tenant
needs to see something, it is projected into a namespace or it is not shown.

It holds **structurally**, not by vigilance: the tenant roles name only *namespaced*
kinds, and a RoleBinding cannot grant access to a cluster-scoped resource. So `list
ports` is unreachable from a tenant role by construction — not by our remembering to
leave it out. Building this removed a loaded gun: the sample `cozyplane-vpc-owner`
role granted `get/list/watch` on **ports**. Inert under a RoleBinding, but it
documented the intent, and one `ClusterRoleBinding` would have handed every tenant
every other tenant's pod names, addresses, MACs and node placement.

### R3. ~~A tenant can list the ports of its VPC.~~

**Dropped**, and the reasoning is worth keeping because it will be proposed again.

It sounds obviously right, and `control-plane.md` even sketched a `/ports`
subresource for it. But ask what a tenant *does* with that list: discovers its
peers by address. **Design tenet 4 says identity, not addresses** — membership is
by label, name resolution is by the split-horizon DNS, and policy selects on
metadata, never on IP ranges. A tenant that enumerates its VPC's addresses is
doing the thing the design explicitly refuses to make load-bearing, and every such
list becomes a surface we defend forever.

Everything a tenant would reach for the list *for*, it already has, and better:

| the tenant wants… | it already has |
|---|---|
| "what is my address?" | R1 — on its own workload |
| "how do I reach service X?" | the split-horizon resolver (VPC-scoped DNS) |
| "who may talk to whom?" | SecurityGroups, selecting on labels |
| "who is in my VPC?" | its own pods — it created them |

An **operator** debugging a tenant is a different persona with different rules
(R9), and can read the cluster-scoped objects directly.

### R4. A tenant opens its own door; it does not mint what is behind it.

**Keep** — already true, and worth stating so it stays true.

A tenant creates its own `VPCGateway` (its VPC's boundary). But the `ExternalPool`
it draws from is a scarce, cluster-scoped, billable resource, and drawing from one
requires the **`attach`** verb — an operator's grant. Same shape as `VPCBinding`'s
`export` and `VPCPeering`'s `peer`: the tenant acts, the operator grants, and the
escalation is refused at the aggregated apiserver, which admission webhooks never
see.

The general form: **a tenant may always act inside its own namespace; anything that
consumes a shared resource, or reaches into another namespace, is a grant.**

### R5. A tenant cannot exhaust what it does not own.

**Keep — built** (stock `ResourceQuota`; see the sequence below). It is the rule
that decides whether tenancy is real.

Nothing bounded a tenant's consumption of VPCs (and therefore VNIs), addresses out
of a pool it was granted, ServiceVIPs, or Ports. Kubernetes `ResourceQuota` does
not cover aggregated-API kinds, so we got nothing for free. And `attach` is a
**binary** grant: hold it, and you may drain the pool.

Isolation without a ceiling is not tenancy — it is tenancy until the first tenant
that wants everything. A quota is what makes "your VPC" mean something other than
"the VPCs you got to first."

### R6. Consent is mutual, and never inferred.

**Keep** — already true. A `VPCPeering` needs both halves. A `VPCBinding` is
required even to attach to a VPC in your *own* namespace. Nothing is opened by one
side, and nothing is opened by inference — no "same tenant, so probably fine."

### R7. Everything a tenant sends across a boundary is attributable to it.

**Keep** — done. Every north-south crossing is counted per VPC and per door
(`docs/north-south.md`), and a VPC's egress wears its own address. Tenancy that
cannot be billed is a costume.

### R8. ~~A tenant's namespaces are one tenant.~~

**Dissolved, 2026-07-14 — there was no question.** A **namespace *is* the tenant**,
full stop. That is not cozyplane's simplification of someone else's model; it is
the model. A Cozystack tenant is a namespace.

So "two namespaces of the same tenant" is not a thing that exists, and the premise
of the rule was wrong. Cross-namespace **is** cross-tenant, and the `export` grant
is not friction — it is the correct answer, applied uniformly, with no exception
carved for a relationship that has no referent.

The rule is recorded here only because the fix it proposed would have been a real
mistake: teaching cozyplane a platform-specific notion of tenancy (a `Tenant` kind,
a namespace-tree label) to serve a case that does not arise. **Cozyplane does not
learn tenancy from anything. The namespace is the anchor, and that is the whole
model.** No platform specifics.

### R9. Operators are not tenants.

**Keep.** `HostFirewall`, `ExternalPool`, and quotas are operator-only, and no
tenant role includes them. An operator may read cluster-scoped objects (that is
what R2 protects *from tenants*, not from the platform). The two personas get two
role sets, and no rule quietly serves both.

---

## The mechanism for R1

R1 was the only rule that needed a new mechanism, and it was worth doing carefully,
because there were three plausible shapes and two of them are traps. **Option C
shipped.**

### Option A — a namespaced sentinel owned by the Port

The controller creates a namespaced object in the tenant's namespace, owner-ref'd
to the cluster-scoped `Port`, mirroring `{vpc, ip, mac, pod}`. The tenant lists it
in its own namespace, so R2 holds by construction, and plain RBAC, plain informers
and plain `kubectl` all work.

**Rejected — it is the stale-copy bug, rebuilt.** We removed `Port.spec.fabricIP`
for exactly this reason: *"a reference whose value IS the address re-creates the
stale-copy bug."* A sentinel that copies the address is that bug with a namespace
on it. Two objects, two writers, one truth, and a live-migration cutover that
re-points one of them. We have the scar; do not re-open it.

### Option B — a projected read (a virtual `/ports` view)

The aggregated apiserver computes the tenant's view at read time from the single
source of truth. No copy, so no drift.

**Keep in reserve.** It is correct, and it is the right answer *if* we ever need a
durable, queryable, watchable tenant view. It costs virtual-REST machinery, and it
must not be built to satisfy R3 (which is dropped) — only R1.

### Option C — the workload carries its own identity  ← **BUILT**

The CNI already knows the VPC address and MAC at ADD time — it *allocated* them.
It writes them back onto **the pod**: `sdn.cozystack.io/vpc-ip`,
`sdn.cozystack.io/vpc-mac`.

- **No new kind, no new API surface, no new RBAC.** A tenant reads its own pods
  already; the namespace scoping is the one that already exists and is already
  correct.
- **R2 is unbreakable here** — there is no object that could leak someone else's
  address, because the address lives on the object it belongs to.
- **It cannot go stale in a way that matters.** It is a *cache*, and its lifetime
  is exactly the claim's: the pod dies, the annotation dies with it. The `Port`
  remains the source of truth; nothing reads the annotation back.
- It is also simply where a user looks first.

**The one case it does not cover, and we should say so out loud:** a **persistent
VM Port** outlives its launcher pods — that is the whole point of it. Between
launchers there is no pod to carry the annotation, and "what address does my VM
have?" is precisely a question a tenant asks when the VM is *stopped*.

For that case the durable, tenant-owned object is the **VM** (`VirtualMachine` /
`VMI`), and the pinned identity belongs on it. That couples us to KubeVirt, which
is a real cost and a real decision — so it is the open question, not a default:

> **Open:** does the persistent Port's pinned `{IP, MAC}` get stamped onto the
> KubeVirt object (coupling, but where a user looks), or does it justify Option B
> (a projected read, no coupling, more machinery)? Decide when a VM tenant asks;
> do not build ahead of it.

---

## Sequence — as built

**R1 and R2 were one change**, and that was not an ordering preference — it is a
safety property. You cannot grant a tenant *any* role until R2 holds, because the
only tenant-relevant read that existed beforehand was a cluster-scoped one.

1. **R1 + R2 together — DONE 2026-07-14** (`test/tenant-e2e.sh`, 19/19 on the dev
   cluster). The CNI stamps the pod with the address and MAC it allocated
   (`sdn.cozystack.io/vpc-ip` / `-mac`); the aggregated `cozyplane-tenant-edit` /
   `-view` roles carry only namespaced kinds and aggregate into the built-in
   admin/edit/view. R2 holds structurally: a RoleBinding grants no access to a
   cluster-scoped resource, so `list ports` is unreachable from a tenant role.

   The run says it better than prose can:

   ```
   status.podIP (the FABRIC ip): 10.244.176.237
   annotated VPC ip / mac:       10.90.0.2 / 22:bc:74:2a:51:a3
   the Port's truth:             10.90.0.2
   ```

   The tenant's real address is 10.90.0.2; Kubernetes was showing it a different
   address on a different network. And a **loaded gun** was removed on the way: the
   sample `cozyplane-vpc-owner` role granted `get/list/watch` on **ports** —
   cluster-scoped. Inert under a RoleBinding, but it documented the intent, and one
   ClusterRoleBinding would have handed every tenant every other tenant's pod names,
   addresses, MACs and placement.
2. **R5 — the ceiling — DONE 2026-07-14** (`test/tenant-e2e.sh` 23/23 on the dev
   cluster). And it needed **no new kind**: the object already exists, and it is
   Kubernetes' own. `ResourceQuota`, with the `count/<resource>.<group>` idiom:

   ```yaml
   kind: ResourceQuota
   spec:
     hard:
       count/vpcs.sdn.cozystack.io:        "3"
       count/floatingips.sdn.cozystack.io: "8"
   ```

   What was missing is that the **kube-apiserver's quota admission cannot see an
   aggregated API's kinds** — so cozyplane's own apiserver enforces it, which is
   precisely what the quota **`Evaluator`** interface exists for. One object-count
   evaluator per tenant-created kind, the stock `ResourceQuota` plugin registered
   into this server's admission chain, and a `PluginInitializer` supplying the
   Configuration (no stock initializer can — the evaluators are necessarily ours).

   A tenant's fourth VPC is refused by the same machinery, with the same error, as
   its eleventh ConfigMap. And it is a real quota, not a gate: observed usage is
   written back to `status.used`.

   **Usage is counted by LISTing through the loopback client, not a shared
   informer.** kube-apiserver trades exactness for cheapness there; staleness in a
   quota means over-admission. Creates here are rare — a tenant makes a VPC, not a
   VPC per request — so we buy exactness at a price nobody pays.

   **Deliberately not quota'd:** `Port` (one per pod — pods are *already* the unit
   Kubernetes quotas) and `ServiceVIP` (one per attached Service — `count/services`
   already bounds it). A tenant creates neither; it creates the pod or the Service
   that causes them. A ceiling on those would be a second, weaker spelling of a
   limit that already binds.
3. ~~**R8 — decide.**~~ Dissolved: a namespace *is* the tenant, so cross-namespace
   is cross-tenant and the grant is simply right. No platform specifics; nothing to
   build.

## What is done (do not rebuild)

The datapath (VNI-scoped, overlapping CIDRs, default-deny cross-VPC), the
SecurityGroup identity model, the escalation verbs (`export` / `peer` / `attach`),
the north-south boundary and its per-VPC metering — those satisfy R4, R6 and R7,
and predate this document. R1, R2 and R5 — the persona, the self-view and the
ceiling — are built on top of them, and `test/tenant-e2e.sh` is the check that they
stay true.

**What is left is one open question, and it is not a gap:** the address of a
**stopped VM** (§ "The mechanism for R1"). A persistent Port outlives its launcher
pods by design, so between launchers there is no pod to carry the annotation — and
that is exactly when a tenant asks. The answer is either a stamp on the KubeVirt
object (where a user looks, at the cost of coupling) or Option B's projected read
(no coupling, more machinery). **Decide when a VM tenant asks; do not build ahead
of it.**
