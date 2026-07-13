# Multi-tenancy — the rules

Cozyplane's datapath has been multi-tenant since early on: VNI-scoped delivery,
overlapping tenant CIDRs, default-deny across VPCs, identities scoped to the VPC,
a declared north-south boundary with its own egress identity and its own meter.

Its **API** is not. Not because isolation leaks — it does not — but because there
is no *tenant* in it. There is no role a tenant could hold, no surface shaped for
one, and no ceiling on what one can consume. An operator does everything, and a
tenant is a thing the datapath enforces rather than a thing the API knows about.

This document is the rules. Each one is stated as a rule, justified, and kept — or
justified badly and dropped. A rule with no justification is a future attack
surface someone will have to defend.

---

## The rules

### R1. A tenant can learn the network identity of its own workloads.

**Keep.** This is the one thing a tenant genuinely cannot do today.

`status.podIP` is the **fabric IP** — the underlay handle, the address kubelet
probes and the platform routes. It is *not* the address anything inside the VPC
uses, and it is not the address the tenant's own guest sees on its interface. The
tenant's actual identity — its VPC address, and for a VM its pinned MAC — appears
in exactly one place in the API: the cluster-scoped `Port`. Which the tenant
cannot read (R2).

So today a tenant literally cannot answer "what is my VM's address?" from the API.
That is not a tenancy nicety; a VM guest's provisioning, a tenant's own inventory,
and the entire live-migration promise (*this identity survives a node move*) are
all about an address the tenant cannot see.

### R2. A tenant can enumerate nothing it does not own.

**Keep.** This is the rule the whole model rests on.

`Port` and `ServiceVIP` are **cluster-scoped**, and that is load-bearing: the IPAM
claim is atomic *because* the name `v<vni>.<ip>` is globally unique. It is an
implementation detail of allocation — and it must never become a tenant-visible
surface. A single `list ports` grant would hand any tenant every other tenant's
pod names, VPC addresses, MACs and node placement. The datapath's isolation would
still hold perfectly, and it would not matter: we would have leaked the fleet's
topology through the front door.

Corollary: **no tenant role may ever include a cluster-scoped read.** If a tenant
needs to see something, it is projected into a namespace or it is not shown.

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

**Keep.** Missing today, and it is the rule that decides whether tenancy is real.

Nothing bounds a tenant's consumption of VPCs (and therefore VNIs), addresses out
of a pool it was granted, ServiceVIPs, or Ports. Kubernetes `ResourceQuota` does
not cover aggregated-API kinds, so we get nothing for free. And `attach` today is a
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

### R8. A tenant's namespaces are one tenant.

**Open — needs a decision.** Cozyplane's authorization anchor is "the namespace is
the tenant." Cozystack's tenants own namespace *trees*. Today, sharing a VPC
between two namespaces of the same tenant needs an `export` grant — an operator in
the loop for a purely internal act.

The grant exists to stop *cross-tenant* escalation. Inside one tenant it is
friction with no security value. But "same tenant" is a fact cozyplane does not
currently possess, and inventing one (a `Tenant` kind, a namespace label) is
exactly the sort of thing that gets inferred wrongly. **Decide before building:**
does cozyplane learn tenancy from Cozystack, or stay deliberately ignorant of it
and keep the grant?

### R9. Operators are not tenants.

**Keep.** `HostFirewall`, `ExternalPool`, and quotas are operator-only, and no
tenant role includes them. An operator may read cluster-scoped objects (that is
what R2 protects *from tenants*, not from the platform). The two personas get two
role sets, and no rule quietly serves both.

---

## The mechanism for R1

R1 is the only rule that needs a new mechanism, and it is worth doing carefully,
because there are three plausible shapes and two of them are traps.

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

### Option C — the workload carries its own identity  ← recommended

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

## Sequence

**Phase 1 and Phase 2 are one change**, and this is not an ordering preference —
it is a safety property. You cannot grant a tenant *any* role until R2 holds,
because the only tenant-relevant read that exists today is a cluster-scoped one.

1. **R1 + R2 together.** Stamp the workload with its own identity (Option C). Then
   define the tenant role: create/read/update/delete `VPC`, `VPCBinding`,
   `VPCGateway`, `SecurityGroup`, `FloatingIP`, `VPCPeering` **in its own
   namespace**, and *no cluster-scoped read at all*. The testable property is
   sharp: **a tenant, holding the full tenant role, can discover nothing about any
   other tenant.** That is one e2e.
2. **R5 — the ceiling.** A quota, enforced in the aggregated registry's create
   path — the same place `export`/`peer`/`attach` are already enforced, because it
   is the same kind of question ("may you?") asked of a different resource. Bound
   VPCs, pool addresses per namespace, ServiceVIPs, Ports. Roll the per-VPC
   counters up per tenant while we are there: R7 already produces the numbers.
3. **R8 — decide.** Cozystack composition. A decision, not a build.

## What is already done (do not rebuild)

The datapath (VNI-scoped, overlapping CIDRs, default-deny cross-VPC), the
SecurityGroup identity model, the escalation verbs (`export` / `peer` / `attach`),
the north-south boundary and its per-VPC metering. R4, R6 and R7 are satisfied
today. The gap is R1, R2 and R5 — a persona, a projection, and a ceiling.
