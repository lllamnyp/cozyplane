# cozyplane backend for tenant site connectivity (routed mode without kube-ovn)

- **Title:** `cozyplane backend for tenant site connectivity (routed mode without kube-ovn)`
- **Author(s):** `@lfinmauritius`
- **Date:** `2026-08-25`
- **Status:** Draft

## Overview

The accepted proposal **`tenant-site-connectivity`** lets a tenant connect its
workloads to an external site through gateway VMs, in two modes: `site-gateway`
(NAT, CNI-agnostic) and `site-router` (routed L3, **kube-ovn-specific**). The
routed mode depends on kube-ovn internals: the `ovn.kubernetes.io/routes`
namespace annotation inherited onto pods by the kube-ovn webhook, and
disabling OVN `port_security` on the gateway VM's logical port because
"kube-ovn cannot express a CIDR in its allowed-address-pair path: it accepts
host IPs only".

A cluster running the **cozyplane** networking variant has no kube-ovn, so the
routed mode has no backend. This proposal provides that backend natively on
cozyplane — and does it **more safely**, because cozyplane can express exactly
the thing kube-ovn cannot: a **CIDR-scoped forwarding grant**, with no
`port_security` disable and no loss of anti-spoofing. The tenant-facing surface
of `site-router` is preserved; only the dataplane behind it changes.

## Scope and related proposals

- **Depends on / extends `tenant-site-connectivity`** (Accepted). This is not a
  new user feature; it is the cozyplane implementation of that proposal's
  routed mode. The `site-gateway` (NAT) mode already works on cozyplane
  unchanged (it is CNI-agnostic, SNAT keeps egress on the gateway's pod IP).
- Builds on cozyplane's north-south model (VPCGateway, FloatingIP, EIP), its
  multi-attach/forwarding work (`VPCBinding.allowForwarding`, `Port.forwarding`,
  `VPCGateway.spec.appliance`), and its metering (`vpc_counters`, per-door).
- Closes cozyplane issue #6 (authorized-forwarder role + per-VPC route table).

## Decisions

_None yet. Recorded under `decisions/NNNN-*.md` during implementation._

## Context

`tenant-site-connectivity`'s routed mode needs three things from the CNI:
1. a **return route** for the remote CIDRs, so VPC pods reach the remote site;
2. permission for the gateway VM to **forward traffic whose source is not its
   own** (a remote-site address) into the VPC;
3. that permission **scoped to the remote CIDRs**, not blanket.

kube-ovn provides (1) via a namespace route annotation + webhook, and (2) by
**disabling `port_security`** on the gateway port — but cannot do (3), so it
relies on a privileged mediation controller and accepts a blanket
anti-spoof relaxation on that port.

cozyplane already has, from its multi-attach work, the exact primitives:
- **`VPCGateway.spec.appliance`** — a tenant workload (the gateway VM) becomes
  the VPC's "door"; off-VPC traffic is delivered to it with the original
  destination intact, so it can route rather than only NAT.
- **`VPCBinding.allowForwarding`** — an export-gated grant letting a designated
  Port emit a foreign source, marked in the datapath as `PORT_F_FORWARD` and
  re-judged at the destination as a north-south source (so SecurityGroups still
  apply). This is (2), done as a scoped grant instead of a blanket disable.
- A **`forwardingCIDRs`** field bounds that grant to declared prefixes — this is
  (3), the thing kube-ovn cannot express.

Missing today: a **per-VPC route table** ((1) above) so the tenant can say
"these remote CIDRs go to the gateway appliance, everything else behaves as
before". That is the new work here.

## The problem

On a cozyplane cluster, a tenant cannot stand up `site-router` (routed
site-to-site): there is no kube-ovn to carry the return route or relax port
security. Even where a relaxation exists (kube-ovn), it is blanket
(host-IP-only allowed-address-pair, `port_security` off), which is weaker than
cozyplane's model allows.

## Goals

- Make **`site-router`** work on the cozyplane variant with the **same
  user-facing spec** (`tunnel`, `peer`, `remoteCIDRs`, `staticRoutes`), so a
  tenant sees one feature regardless of CNI.
- A **per-VPC route table** directing declared remote CIDRs at the gateway
  appliance's Port, resolved by identity (survives reschedule/migration).
- A **CIDR-scoped forwarding grant** (no `port_security` disable, anti-spoof
  stays on for everything outside the declared CIDRs).
- **WireGuard and IPsec** tunnel backends (matching `tenant-site-connectivity`).
- **Hub topology** (one appliance serving several VPCs) from the same
  primitives.
- Per-door **metering** of tunnel traffic, consistent with cozyplane's
  north-south accounting.

## Non-goals

- Node-to-node transit encryption (that is Kilo; different layer).
- Dynamic routing (BGP) **into** cozyplane's fabric — remote prefixes are
  declared and static (cozyplane "announces nothing"; the platform, e.g.
  MetalLB, owns any BGP announcement of the tunnel endpoint address).
- A shared multi-tenant IKE endpoint (IKE's fixed 500/4500 means one responder
  per address; deployments short on addresses use WireGuard).
- Roadwarrior / per-device client VPN (a later increment).
- Any cryptography in eBPF.

## Design

### The appliance is the VPC's door (built)

`site-router`'s gateway VM is selected as the VPC's door via
`VPCGateway.spec.appliance.podSelector`. The controller moves the
`gateways[vni]` role onto the VM's Port; off-VPC traffic is delivered there with
the original destination intact. cozyplane spawns no fallback gateway pod while
an appliance is declared.

### The scoped forwarding grant (built, extended)

The gateway VM's `VPCBinding` carries `allowForwarding: true` plus
`forwardingCIDRs: [<remoteCIDRs>]`. The datapath admits a foreign source on the
gateway's Port **only** if it falls within the declared prefixes; everything
else stays subject to the normal anti-spoof/RPF check. This replaces
kube-ovn's blanket `port_security` disable with a prefix-scoped grant — safer,
and authored by the VPC owner (export-gated), not by a privileged CNI-mediation
controller relaxing a port.

### The per-VPC route table (new)

`VPCGateway.spec.routes` names prefixes and the workload they resolve through:

```yaml
kind: VPCGateway
spec:
  vpcRef: {name: vpc1}
  nat: {enabled: true}
  routes:
  - cidrs: ["10.20.0.0/16"]          # == site-router's remoteCIDRs
    via: {podSelector: {matchLabels: {app.kubernetes.io/name: site-router}}}
```

A new datapath LPM map `vpc_routes` ( `{scope_net, prefix} -> {gw_ip, node_ip}` )
is consulted in `from_pod` **before** the NAT decision, so remote-CIDR traffic
reaches the tunnel instead of being SNAT'd toward the internet. A miss changes
nothing (existing behaviour is the fallback at every step). Resolution reuses
the appliance machinery (oldest live matching Port, tie-broken by name), so the
route follows a rescheduled/migrated gateway.

Guests learn no routes: they keep one default route to their VPC's (virtual)
gateway address; the route table is enforced in eBPF at the veth. Changing a
route is a map update — no DHCP renew, no gratuitous ARP.

### The tunnel endpoint

The gateway VM's public endpoint is a cozyplane `FloatingIP` targeting its VPC
IP — the existing stateless bijection (inbound IKE/WG arrives with the client's
real source; the VM's own initiations leave wearing the floating address). The
platform's allocator (MetalLB L2 or BGP, or a CCM) attracts the address exactly
as it does for the `kubeovn-cilium` variant; cozyplane consumes it. For IPsec,
whose peer pins the endpoint, the address should be reserved via the existing
`addressClaimName`.

### Tunnels (WireGuard, IPsec)

Kernel WireGuard or kernel xfrm inside the gateway VM's namespace, configured
by the `site-router` app image — the same image and tunnel config
`tenant-site-connectivity` already defines. cozyplane adds **no cryptography**;
it provides identity, delivery, routing, policy, and metering around the
tunnel.

### Hub topology

An appliance multi-attaches with a leg in each served VPC; each spoke consents
independently (its owner grants `allowForwarding` on its binding, its
`VPCGateway` routes the remote prefixes at its leg). Constraint: prefixes routed
through one hub must be disjoint (the same rule peering imposes).

## User-facing changes

- **`site-router` app spec is unchanged** for the tenant — `tunnel{type,peer}`,
  `remoteCIDRs`, `staticRoutes`. On the cozyplane variant it renders the
  cozyplane objects above (VPCGateway routes + appliance, VPCBinding
  forwarding grant, FloatingIP) instead of kube-ovn annotations.
- The catalog/app definition gains a cozyplane-variant backend; the dashboard
  surface is identical.
- No new tenant RBAC verbs beyond the existing export-gated `VPCBinding`.

## Upgrade and rollback compatibility

Additive: `VPCGateway.spec.routes` and `VPCBinding.forwardingCIDRs` are new
optional fields; absent, behaviour is exactly today's. `vpc_routes` is a new map
created through the existing reconcile path — no migration. Deleting a
`site-router` instance removes the routes and the grant, restoring the VPC's
prior egress. The `site-gateway` (NAT) mode is unaffected.

## Security

- **Scoped grant, not a relaxation.** The forwarding grant is bounded to the
  declared remote CIDRs; anti-spoof stays on for everything else. No
  `port_security` disable, no blanket allowed-address-pair.
- **Authored by the VPC owner** (export-gated `VPCBinding`), not by a privileged
  controller relaxing a port — one fewer privileged mediator than kube-ovn's
  routed mode.
- **Policy still applies**: decrypted remote traffic is judged at the
  destination by SecurityGroups as a north-south source (`from: {cidr:
  <remote>}`), so a tunnel does not bypass tenant policy.
- **Route authorship vs forwarding right** are separate: the tenant may point
  its own VPC's routes anywhere inside its own network; the right to forward a
  foreign source stays with the VPC owner's grant. A route to a Port without the
  grant is inert (reported in a condition), never silently widened.
- Tunnel secrets (PSK/keys) live in Secrets, never in specs.

## Failure and edge cases

- **Appliance rescheduled/migrated**: the route and door re-resolve to the new
  Port; in-flight tunnel state re-establishes (WG rehandshake, IKE DPD).
- **Route to an ungranted Port**: inert, condition set, no traffic widened.
- **Overlapping CIDRs**: supported between VPCs that do not share a hub; a
  single hub's served prefixes must be disjoint (documented, refused with a
  condition otherwise).
- **Endpoint address churn** (IPsec): mitigated by reserving the address
  (`addressClaimName`); WireGuard tolerates a re-resolve as a rehandshake.
- **MTU**: tunnel overhead stacks with Geneve; `VPC.spec.mtu` is advertised and
  documented, sharing the inbound-MTU/MSS-clamp work with floating-IP DSR.

## Testing

- **Unit**: route-table resolution (oldest-Port, tie-break), grant scoping
  (foreign source in/out of the declared CIDRs), condition reporting.
- **Datapath**: `vpc_routes` LPM precedence over NAT; kind 6.8 verifier as the
  gate.
- **e2e**: a `site-router` instance on a cozyplane kind cluster tunnelling to an
  off-cluster peer (a netns/container outside the kind network) — VPC pods reach
  the remote CIDR and back, traffic outside the CIDRs still egresses via NAT,
  policy applies at both ends. WireGuard in CI; IPsec strongSwan-to-strongSwan
  in CI, commercial-firewall interop as a manual matrix.
- Reuse `tenant-site-connectivity`'s own acceptance scenarios where possible, to
  prove the two backends are behaviourally equivalent to the tenant.

## Rollout

1. **Route table**: `VPCGateway.spec.routes`, the `vpc_routes` LPM,
   `forwardingCIDRs` scoping. (The appliance + forwarding grant already exist.)
2. **`site-router` cozyplane backend**: render the cozyplane objects from the
   app's existing spec; WireGuard first.
3. **IPsec** backend + interop matrix.
4. Later: roadwarrior (own proposal).

## Open questions

- Should the route table live on `VPCGateway` (proposed) or a dedicated kind?
  `VPCGateway` keeps the VPC's boundary posture in one object.
- Whether to also offer a cozyplane-managed appliance (controller-orchestrated
  tunnel) vs only the customer-operated `site-router` VM — the latter is the
  `tenant-site-connectivity` model and the smaller first step.
- Naming/ownership of any new `sdn.cozystack.io` kind vs reusing the app-level
  `site-router` surface entirely.
- HA (active-passive appliance) — fits the oldest-wins selection; later.

## Alternatives considered

- **Port cozyplane to consume kube-ovn's route annotation model**: rejected —
  cozyplane has no kube-ovn; and its native primitives are strictly safer
  (CIDR-scoped grant vs `port_security` off).
- **Blanket anti-spoof disable on the gateway Port** (mirroring kube-ovn):
  rejected — cozyplane can scope the grant to the remote CIDRs, so a blanket
  relaxation is unnecessary and violates tenet 8 (tenant traffic never wears an
  unearned identity).
- **A cozyplane-only VPN kind unrelated to `tenant-site-connectivity`**:
  rejected — it would fork an accepted design and give tenants a different
  surface per CNI. This proposal keeps one user-facing feature with two
  dataplane backends.
- **Dynamic routing (BGP) into the fabric for remote prefixes**: rejected —
  cozyplane announces nothing; remote prefixes are declared and static.
