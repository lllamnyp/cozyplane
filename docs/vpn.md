# Site-to-site VPN — design proposal (issue #6)

**Status: implemented in increments — §10 distinguishes code-complete/local
validation from tests that still require an external firewall, BGP peer or a
KubeVirt migration environment.**

This document proposes VPN termination for VPCs: site-to-site tunnels (WireGuard,
then IPsec/IKEv2) between a tenant's remote network and their VPC, and — as a later
increment — roadwarrior access for individual clients. It builds directly on the
multi-attach / forwarding / appliance work (`docs/multi-attach.md`,
`docs/north-south.md` §6b) and closes the two halves of
[#6](../../issues/6): the *authorized-forwarder role* (already built — see §2) and
the *per-VPC route table* (designed here, §3).

Reading order: `docs/design.md` for the tenets, `docs/north-south.md` for the
boundary model, `docs/multi-attach.md` for the forwarding-leg mechanics this
proposal stands on.

## 0. The problem

A tenant has a network that is not this cluster — an office behind a firewall, a
lab, another cloud — and wants private, addressed connectivity between it and
their VPC. Today the sanctioned crossings are LoadBalancer ingress, the EIP
bijection, and NAT egress. None of them carries a *network*: a remote site needs
its prefixes routable into the VPC and the VPC's prefixes routable back, through
an encrypted tunnel, without either side being NAT'd out of recognition.

The state of the art elsewhere is poor. kube-ovn's answer requires disabling port
security on the VPN endpoint VM — trading the platform's anti-spoofing away to
make the tunnel work (#6 describes this). Cilium has no tenant-facing VPN at all;
what Cilium and kube-ovn each call "IPsec" is node-to-node transit encryption,
a different layer entirely, and a non-goal here (§4).

`docs/design.md` §4 already reserved the spot this feature occupies:

> The one place a userspace datapath may earn its keep is dedicated gateway nodes
> (VPC↔internet, heavy SNAT/NAT64, IPsec/WireGuard termination) — an optional,
> isolated role, not the common case.

Tunnel termination is stateful kernel work (xfrm SAs, WireGuard peers) and lives
in an appliance's netns. cozyplane's job is everything around it: identity,
delivery, routing, policy, metering. This proposal adds **no cryptography to the
datapath** and no IKE anywhere near eBPF.

## 1. Tenets, applied

The north-south tenets carry over verbatim; this is what they mean for a tunnel:

1. **A tunnel is a door.** Encrypted traffic enters and leaves through an
   addressable endpoint; decrypted traffic crosses the VPC boundary through a
   Port. Both crossings are counted (§6). If a path cannot be counted, it is not
   a sanctioned path.
2. **cozyplane does no cryptography.** The tunnel is kernel WireGuard or kernel
   xfrm inside the appliance pod's netns, configured over netlink/VICI from
   userspace Go. No new eBPF is needed for the tunnels themselves — the only new
   datapath surface is the route table (§3.1), which is routing, not crypto.
3. **The CNI does not announce.** The tunnel endpoint's external address is a
   `FloatingIP` (or a delegated LoadBalancer Service) — allocated and attracted
   by the platform, consumed by cozyplane, exactly like every other external
   address (`docs/external-addresses.md`).
4. **Nothing crosses by default.** A working tunnel requires three explicit,
   separately-authored grants: the VPC's `VPCGateway` routes traffic at the
   appliance (§3.1); the VPC owner grants the appliance's binding
   `allowForwarding` (export-gated, already built); and the destination's
   SecurityGroups still judge every decrypted packet as a north-south source
   (already enforced — a forwarding leg does not escape policy).
5. **Identity, not addresses.** A route resolves to a Port identity, not to an
   IP-on-a-node. The appliance can be rescheduled, replaced, or live-migrated and
   the control plane re-resolves it — the same selection machinery
   `VPCGateway.spec.appliance` already uses.

## 2. What is already built — the customer-operated appliance (option 2 of #6)

The `feat/kubevirt-multi-nic` line of work delivers, today, everything a
*customer-operated* VPN endpoint needs except routing:

- **Multi-attach** — one pod or VM with legs in several VPCs, including real
  per-VPC NICs on KubeVirt VMs via the Multus delegate and per-`VPCBinding`
  generated NADs (`docs/multi-attach.md`, `docs/kubevirt-multi-nic.md`).
- **`VPCBinding.allowForwarding`** — the VPC owner's export-gated grant letting a
  designated leg emit packets whose source it does not own. The datapath marks
  the Port `PORT_F_FORWARD` (deliberately *not* `PORT_F_GATEWAY`), stamps
  forwarded packets `FWD_MARK`/`TUN_F_FORWARD`, and re-gates them at the
  destination as a **north-south source** via the same admission the fabric
  bridge and floating IPs use — `from: {cidr: <remote-site>}` SecurityGroup rules
  apply to decrypted tunnel traffic. This is the kube-ovn contrast in one line:
  where they disable port security, we scope the grant and keep policy on.
- **`VPCGateway.spec.appliance`** — a tenant workload can be its VPC's door:
  the controller moves the `gateways[vni]` role onto the selected workload's
  Port, self-heals across pod replacement, and stands down cozyplane's own
  fallback gateway pod. Off-VPC traffic is delivered to it **with the original
  destination intact**, so it can route, not merely NAT.
- Dev-cluster validated for the generic router case: an appliance with a leg in
  each of two VPCs, declared the door of both — ICMP at 0% loss, TCP gated by
  the source VPC's egress rule *and* the destination VPC's ingress rule.

When this proposal was written, a tenant could already run strongSwan or
WireGuard in a VM and declare it their VPC's door, but two gaps made that an
incomplete answer. Both are now implemented in the increments in section 10:

1. **The door is all-or-nothing.** `gateways[vni]` is a single entry: declaring
   the VPN appliance the door sends *all* off-VPC traffic through it, displacing
   the distributed NAT egress the tenant probably still wants for internet
   traffic. Worse, when `nat.enabled` holds a NAT identity, egress SNAT happens
   at the *source pod's own veth* before any gateway delivery — traffic for the
   remote site would be NAT'd toward the internet instead of reaching the
   tunnel. There is no way today to say "these prefixes go to the appliance,
   everything else behaves as before." That is the route table (§3.1).
2. **Nobody operated the tunnel for you.** Option 1 of #6 — cozyplane
   orchestrating the appliance and its tunnel config — was still unbuilt
   (§3.2).

The original debts on the built half are recorded in increment 0 and are now
closed: automated appliance/forwarding e2e coverage, correct north-south
`door="appliance"` metering, and corrected forwarding documentation.

## 3. Design implemented

### 3.1 The per-VPC route table

**API.** Routes live on the `VPCGateway` — the one object that already declares
the VPC's boundary posture (NAT, LB admission, appliance). A route names
prefixes and the workload they resolve through:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCGateway
spec:
  vpcRef: {name: vpc1}
  nat: {enabled: true}
  routes:
  - cidrs: ["10.20.0.0/16", "10.30.0.0/24"]
    via:
      podSelector:
        matchLabels: {app.kubernetes.io/name: vpn-endpoint}
      # namespace: defaults to the gateway's own
```

Resolution reuses the appliance machinery verbatim: list matching pods, list this
VPC's Ports, intersect, pick the oldest live candidate tie-broken by name — the
same total order `EffectiveGateway` and `reconcileAppliance` use, so every
controller replica agrees. The result is a Port identity written to status; the
workload can move and the route follows.

Authorship split, stated plainly: routes are authored by whoever edits the
`VPCGateway` (the tenant — pointing your own VPC's traffic somewhere inside your
own network is yours to decide). The right of the *target* to forward foreign
sources stays with the VPC owner's export-gated `allowForwarding` grant. A route
at a Port whose binding lacks the grant delivers traffic the appliance cannot
legitimately answer — the route is inert, reported in a condition, and nothing
is silently widened.

**Datapath.** One new LPM map:

```
vpc_routes : LPM { u32 scope_net; struct addr128 prefix } → { gw_ip, node_ip }
```

— the same value shape as `gateways[vni]`, delivered the same way. Lookup order
in `cozyplane_from_pod` for an off-VPC destination becomes:

```
floating_egress → vpc_routes (LPM, longest prefix) → vpc_nat_snat → gateways[vni] → drop
```

The route lookup **must precede** the NAT decision — that is the entire point
(§2, problem 1). A miss changes nothing: existing behavior is the fallback at
every step. `cozyplane_from_overlay`'s VPC branch needs the mirror-image probe
where it consults `gateways` today.

Two datapath cautions, both known territory: `from_pod` sits at ~496 of 512
combined stack bytes and hosts no BPF-to-BPF callee — the lookup must be
inline-and-lean or earn a tail-call slot; and kind's 6.8 verifier remains the
gate, whatever the dev cluster's 6.12 accepts. New eBPF carries
`SPDX-License-Identifier: GPL-2.0` in `bpf/`, and the compiled object is
committed and `go:embed`'d, per the standing convention.

**Guests never learn routes.** A guest — VM or pod — keeps exactly one default
route toward its VPC's gateway address, and that address is a datapath
artifact, not a machine: nothing holds it, so nothing about it ever changes.
The route table is enforced in eBPF at the veth, where every off-VPC packet
already passes; adding, moving, or removing a route is a map update on the
nodes, and the next packet takes the new path. No DHCP renew, no route push,
no gratuitous ARP, no next-hop a guest could even observe. This is the tenet
"the K8s contract is plumbing, not a user surface" doing its job: the VPN
appliance is invisible to the workloads it serves.

**Scoped anti-spoof (tightening the grant).** `allowForwarding` today lifts the
source-RPF check wholesale — the doc comment is honest that the leg can then
impersonate *any* member of the VPC. Routes give us the material to narrow it:

```yaml
kind: VPCBinding
spec:
  vpcRef: {namespace: tenant-a, name: vpc1}
  allowForwarding: true
  forwardingCIDRs: ["10.20.0.0/16"]   # empty = any (today's semantics)
```

backed by a per-port LPM allowlist: a foreign source on a granted leg is admitted
only if it falls within the declared prefixes. `#6` asked for exactly this
("authorized forwarders for a declared remote-cidr"). The field is additive and
optional; since `allowForwarding` has never shipped in a release, tightening the
default later remains on the table.

### 3.2 Managed tunnels (option 1 of #6)

Two new namespaced kinds in `sdn.cozystack.io`, served by the aggregated API
server like their siblings, listed in the tenant RBAC aggregates:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway                      # naming: see open questions, §9
metadata: {namespace: tenant-a, name: site-vpn}
spec:
  vpcRef: {name: vpc1}
  additionalVPCRefs: [{name: vpc2}]   # optional — hub, §3.3
  wireguard: {listenPort: 51820}      # exactly one of wireguard | ipsec
  externalAddress:
    loadBalancerClass: ""             # cluster default
    addressClaimName: ""              # optional reservation, pass-through as ever
status:
  address: 198.51.100.7
  phase: Ready
  conditions: [ApplianceReady, AddressAssigned, RoutesProgrammed]
```

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {namespace: tenant-a, name: office-paris}
spec:
  gatewayRef: {name: site-vpn}
  remoteCIDRs: ["10.20.0.0/16"]
  wireguard:
    peerPublicKey: "…"
    peerEndpoint: "203.0.113.10:51820"     # optional — a roaming peer may initiate
    presharedKeySecretRef: {name: office-paris-psk}
    persistentKeepalive: 25
status:
  phase: Established
  lastHandshake: "2026-08-24T10:11:12Z"
  observedAt: "2026-08-24T10:11:13Z"
  conditions: [Established, RoutesProgrammed]
```

The IPsec variant swaps the tunnel block:

```yaml
  ipsec:
    peerAddress: 203.0.113.10
    startAction: Start                 # peer side uses None to avoid duplicate SAs
    auth:
      psk: {secretRef: {name: site-a-psk}}         # certificate and EAP auth are also supported
    ike:
      proposals: ["aes256gcm16-prfsha384-ecp384"]  # sane defaults when omitted
      dpdDelay: 30s
    # traffic selectors derive from the VPC's CIDRs × remoteCIDRs; an explicit
    # override field can come later if interop demands it
```

**What the controller does.** A new `VPNGatewayReconciler` alongside the existing
twelve, owning:

- an appliance **Deployment** in the VPC's namespace (`Recreate`, one replica in
  v1 — §9 for HA): the appliance image plus a small shim binary. The pod holds
  `NET_ADMIN` in *its own netns only* — WireGuard device or xfrm state never
  touches the host.
- one **`VPCBinding`** per served VPC (§3.3), each with `allowForwarding` and
  `forwardingCIDRs` set to the union of the connections' `remoteCIDRs`. Creating a
  `VPNGateway` in the VPC owner's namespace *is* the owner's grant; the
  controller merely writes it down.
- a **`FloatingIP`** targeting the appliance's VPC IP — the tunnel endpoint.
  This is the existing stateless bijection: inbound IKE/WG datagrams arrive with
  the client's real source; the appliance's own initiations leave wearing the
  floating address (`floating_egress` runs before the isolation block). Nothing
  new in the datapath; the platform's allocator (MetalLB, a CCM) attracts the
  address as ever.
- **routes**: `status.routes` carries one entry per connection × served VPC
  (§3.3). Within each served VPC the effective route set is the merge of the
  `VPCGateway`'s explicit `spec.routes` and the `remoteCIDRs` of every Ready
  `VPNConnection`. Longest prefix wins; an exact-prefix conflict between the two
  sources is refused with a condition, never resolved silently.
- **status**: the controller reads the selected appliance's secret-free `/status`
  endpoint every 15 seconds (every second for an HA gateway). `Established`
  requires both programmed routes and
  a live WireGuard handshake/IPsec CHILD-SA; `Down` distinguishes a materialized
  route with no tunnel, and `observedAt` makes staleness visible. The same source
  feeds the metrics endpoint (§6).

**The endpoint address.** The tunnel endpoint is the one address in this design
a *remote* system pins in its configuration — a firewall names its IKE peer by
address, and a changed endpoint is a dead tunnel plus a change request at the
customer's site. So the address must outlive everything on our side: the
appliance pod, the `FloatingIP` object, the `VPNGateway` itself. The existing
levers cover this, and the split of responsibilities is deliberate:

- `externalAddress.loadBalancerClass` picks the allocator (MetalLB, a CCM) and
  thereby the pool — cozyplane consumes the address, it never allocates one.
- `externalAddress.addressClaimName` names an `IPAddressClaim` reservation: the
  address is held by the claim, not by anything the controller creates, and
  survives deletion and recreation of the whole gateway. There is deliberately
  no literal `address:` field — asking for a specific address *is* what a claim
  expresses, and keeping allocation (and its conflicts) in the allocator is the
  external-addresses rule applied, not an omission.
- `status.address` (with the `AddressAssigned` condition) is what the tenant
  reads out to configure the remote peer.

For WireGuard a re-resolved endpoint merely delays the next handshake; for IPsec
it is an outage. The practical guidance is therefore: **an IPsec gateway should
always name a claim.** One constraint, stated: the endpoint cannot share the
VPC's NAT address — the NAT identity is per-node sharded (`nat_owner` demuxes
replies by port range) while a floating address is a whole-address bijection;
one address cannot serve both masters. Distinct addresses, checked and refused
with a condition, never resolved silently.

**Inside the appliance.** WireGuard first: a kernel `wg` device configured via
`wgctrl` by the shim, peers projected from the `VPNConnection`s, keys mounted
from Secrets. IPsec next: strongSwan's charon driven over **VICI** by the same
shim — connections loaded/unloaded on reconcile, no config-file reload dance.
strongSwan stays where it belongs, in the appliance image; the controller never
links it. If the shim's dependency tree grows past trivial, it becomes its own Go
module on the `kpr/` precedent; `wgctrl` and `govici` alone do not justify that.

Failure behavior on a plain reschedule is boring: the appliance is replaced, the
appliance machinery re-resolves the Port, WireGuard peers reconnect statelessly,
IKE re-establishes via DPD. A single-appliance v1 accepts a tunnel interruption
on reschedule; §3.5 is how to remove it.

### 3.3 Hub topology — several VPCs, one appliance

The managed path (§3.2) is now the primary mechanism. `VPNGateway.spec.vpcRef`
stays the PRIMARY served VPC — FloatingIP endpoint, appliance default route,
tunnel MTU budget — and optional `spec.additionalVPCRefs []LocalVPCRef` (same
namespace, up to 9) names further VPCs the same appliance serves:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {namespace: tenant-a, name: site-vpn}
spec:
  vpcRef: {name: vpc1}                 # PRIMARY — endpoint, default route, MTU budget
  additionalVPCRefs: [{name: vpc2}, {name: vpc3}]
  wireguard: {listenPort: 51820}
```

Granularity is per-gateway, not per-connection: every connection's
`remoteCIDRs` route into every served VPC, and every served VPC reaches every
connection's remote sites. The appliance multi-attaches, one leg per served VPC
(`sdn.cozystack.io/networks`, entry 0 = primary; 10 legs total is the CNI's
`maxAttachments`). The controller writes one `VPCBinding` per served VPC
(primary `<gw>-vpn`, additional `<gw>-vpn-<vpc>`, same scoped grant, pruned by
label when a VPC leaves the list); `status.routes` gets one entry per
connection × served VPC, pointing at the *same selected appliance pod's* leg in
that VPC — the tunnel itself lives only on the primary leg, and the agent
already scopes a route by the VNI its next-hop Port encodes, so no datapath
change. Nothing is transitive — no route from one served VPC to another is ever
installed — and each leg stays anti-spoof-bounded by its own binding's
`forwardingCIDRs`. Forbidden with `ha.mode: LiveMigration` (one-NIC KubeVirt
VM; Multus multi-NIC is out of scope); active-active's BGP `AdvertiseCIDRs`
become the union of every served VPC's CIDRs.

Disjointness is enforced, not just stated: served VPCs' CIDRs must be pairwise
disjoint or the controller holds the gateway `Pending` (`VPCCIDRsOverlap`), and
a `remoteCIDR` overlapping any served VPC's CIDR is refused by the same
route-CIDR deny-set behind `RemoteCIDRsAccepted` (reason "served VPC").
Overlapping CIDRs remain fully supported between VPCs that don't share a hub —
the rule is peering's, for the same reason: routed traffic is delivered
natively, and a router cannot serve two owners of one prefix.

A tenant-operated hub still falls out of the same primitives, unmanaged: a
hand-attached appliance with a leg in each VPC, each spoke's owner granting
`allowForwarding` on its own binding and routing the remote prefixes at its own
leg's Port. Nothing transitive there either, and the same disjointness rule
applies.

### 3.4 Roadwarrior

Individual IKEv2 clients reuse `VPNConnection`; no second lease controller or
shadow identity API is introduced. An IPsec gateway declares non-overlapping,
named address pools and an optional cert-manager-compatible TLS Secret:

```yaml
spec:
  ipsec:
    credentialSecretRef: gateway-ike-tls # tls.crt, tls.key, optional ca.crt
    trustedCASecretRef: client-ca        # ca.crt; needed for client certificates
    localIdentity: vpn.example.invalid
    addressPools:
    - name: clients-v4
      cidr: 10.250.0.0/24
      dns: [10.0.0.53]
```

Each client is one revocable `VPNConnection`. Its IPsec authentication is
exactly one of PSK, a certificate identity, or EAP credentials. EAP and client
certificate connections select one gateway pool and are responder-only:

```yaml
spec:
  gatewayRef: {name: site-vpn}
  ipsec:
    addressPool: clients-v4
    auth:
      eap:
        identity: device-001
        secretRef: device-001-eap # data.password
```

The controller reads referenced Secrets, projects credentials only into the
appliance's config Secret, and adds the selected pool CIDR to the scoped
forwarding grant and VPC route table. The appliance loads certificates, keys,
EAP secrets and pools directly over VICI. strongSwan owns online/offline leases;
the live status reports assigned virtual IPs. Deleting the connection removes
the credential and connection on the next immutable-config rollout, which is
the revocation boundary. Secret contents never enter API status or metrics.

### 3.5 High availability — a three-tier stack, not one switch

The one piece of a tunnel that does not move by identity is its **crypto state**:
IPsec anti-replay sequence numbers, WireGuard session keys — they live in one
node's kernel. cozyplane already makes everything *around* that seamless: a
**reserved** `FloatingIP` (the tunnel endpoint) moves to the surviving node by
identity, so the remote peer keeps dialling the same address and never
reconfigures; the route re-resolves to the new Port. So the residual failover
cost is the crypto re-establishment alone — and "zero-drop" is really a question
of how far you pay to remove *that*. Three tiers, chosen per deployment:

1. **Planned maintenance → live migration (true zero-drop, already built).** When
   the appliance is a KubeVirt VM (the `tenant-site-connectivity` form factor),
   draining a gateway node live-migrates it with its kernel state intact —
   including the xfrm SA or the WireGuard keys. cozyplane's persistent Port gives
   the sub-second cutover. Zero-drop, both crypto backends, no remote
   cooperation. Does not help on a crash (the source is gone).

2. **Crash, cheap near-zero → WireGuard warm standby.** A standby appliance on a
   second gateway node holds the **same WireGuard private key**. On the active's
   death, health-checked failover flips the FloatingIP + route; WireGuard's
   native roaming means the standby re-handshakes from the moved address in
   ~1 RTT and the remote updates the endpoint. Sub-second, single active tunnel,
   no remote ECMP. **WireGuard-specific** — IPsec has no clean single-tunnel
   equivalent (strongSwan's HA plugin assumes a shared L2 segment, a netfilter
   CLUSTERIP target, and periodic sequence-number sync whose gap still drops
   packets as replays; a poor fit for cozyplane's no-netfilter overlay, and
   rejected).

3. **Crash, true zero-drop → dual active tunnels + BGP/BFD.** Two appliances on
   two gateway nodes, each with its own tunnel and FloatingIP, both up; the
   remote peer runs ECMP / route-based failover with BGP + BFD (FRR inside the
   appliance's netns — cozyplane's fabric still announces nothing). A node death
   is a BFD withdrawal; the surviving tunnel already carries the traffic — **no
   packet lost**. This is the standard enterprise redundant-VPN pattern, works
   with **IPsec and WireGuard**, and is why `site-router` already carries a
   `bgp.enabled` field. Costs: 2× crypto, and the remote gear must support
   multi-tunnel (most enterprise firewalls do).

The honest bottom line: **there is no clean single-tunnel zero-drop on a crash**
— the SA state is in one kernel, and replicating it without a gap is what
strongSwan HA tries and does imperfectly. True zero-drop on a crash is tier 3
(dual tunnel), which is crypto-agnostic; tier 2 (WireGuard standby) buys
sub-second for far less; tier 1 (live migration) covers planned maintenance for
free. cozyplane's contribution is that it removes **every** failover cost except
the irreducible crypto one, and tier 3 removes even that.

Appliance form factor follows from the tier: a **VM** unlocks tier 1
(live migration) and is the accepted `tenant-site-connectivity` shape; a **pod**
restarts faster on a crash but cannot live-migrate. Both do tiers 2 and 3.

## 4. Non-goals

- **Transit encryption.** Node-to-node encryption of the overlay (what Cilium
  and kube-ovn call IPsec, what Kilo does with WireGuard) is a different layer.
  Not this feature, not this document.
- **Dynamic routing to remote sites.** No BGP, no route exchange over the tunnel.
  `docs/north-south.md` §6 already ruled: a CNI has no business holding routing
  sessions. Remote prefixes are declared, static, in `remoteCIDRs`.
- **A shared multi-tenant IKE endpoint.** One appliance, one VPC, one external
  address. IKE's fixed UDP 500/4500 means one IPsec responder per address —
  documented, not engineered around. Deployments short on addresses use
  WireGuard, whose per-VPC `listenPort` is freely chosen.
- **Crypto in eBPF.** Ever.

## 5. Security model, summarized

Secrets (PSKs, private keys) live in Secrets, mounted into the appliance, never
in resource specs. Decrypted traffic is judged by the destination's
SecurityGroups as a north-south source — already enforced, already tested at the
datapath level. The forwarding grant is export-gated and, with §3.1, scoped to
declared prefixes. Cluster-scoped kinds stay invisible to tenants; both new
kinds are namespaced and slot into the existing `cozyplane-tenant-{edit,view}`
aggregates. The appliance is a tenant workload in the tenant's namespace:
its traffic wears the tenant's identity, never the platform's (tenet 8).

### 5.1 Adversarial review — findings and disposition

An attacker-posture audit of the whole feature (control plane + datapath +
appliance binaries) ran once the increments were built. The inter-tenant
escalation vectors are **structurally closed** by the API typing (`LocalVPCRef`,
`LocalVPNGatewayRef` resolve only in the gateway's own namespace) and
namespace-scoped RBAC, independent of admission checks. What it surfaced, and
what was done:

- **Fixed — route-CIDR deny-set** (was: a tenant could declare a cluster-internal
  CIDR as a tunnel remote and redirect the VPC's own service/pod traffic into the
  tunnel). The controller now refuses a `remoteCIDRs` entry overlapping
  loopback/link-local/CGNAT/multicast (always) or the operator's
  `--internal-cidrs` (pod/service/node), before it reaches the grant, the route
  table, or the peer config, and surfaces a `RemoteCIDRsAccepted=False` condition.
  Verified on kind: `10.96.0.0/16` refused, no binding, no route.
- **Fixed — quota is now enforcing, not cosmetic** (was: a burst of concurrent
  creates could each pass the cap on a stale cache, and a gateway later marked
  `QuotaExceeded` kept its running tunnel/grant/IP). The count now reads live
  (`GetAPIReader`), and an over-quota gateway is torn down — Deployment,
  VPCBinding, FloatingIP deleted — so it grants and serves nothing. Verified.
- **Fixed — the IPsec appliance detects charon's death** (was: `exec.CommandContext`
  binds the child to the context, not the reverse, so a charon that crashed on its
  own left a live pod with a dead tunnel). The process now waits on charon and
  exits non-zero if it dies, so the kubelet restarts the pair.
- **Capability-bounded mode is available, compatibility mode remains the
  default.** `--vpn-hardened-appliance` (chart
  `vpn.hardenedAppliance`) moves forwarding to pod-level sysctls, drops all
  capabilities, and adds only `NET_ADMIN`+`NET_RAW`+`NET_BIND_SERVICE` with
  privilege escalation disabled. Enable it only after the kubelet admits the two
  forwarding sysctls; clusters that do not retain the privileged compatibility
  path and should isolate it on the dedicated gateway node-pool.
- **Tunnel MTU derives from `VPC.spec.mtu`.** The controller subtracts a
  conservative worst-case outer overhead (80 bytes for WireGuard, 128 for
  ESP-in-UDP) and configures the WireGuard/xfrm interface accordingly. This
  gives the kernel a correct PMTU boundary on paths stacking Geneve and VPN
  encapsulation. The datapath also clamps oversized MSS options on bare TCP SYNs
  before VPN, FloatingIP, Geneve and DSR encapsulation; PMTU remains the fallback
  for non-TCP traffic.
- **Owed — controller holds cluster-wide `secrets` + `vpcs/export`**: the managed
  model has the controller create the keypair/config Secrets and the forwarding
  grant on the tenant's behalf, so it is a trusted cluster component (like the
  existing broad grants it already holds). Scoping the Secret access to the
  gateway namespaces is a hardening follow-up.
- **Owed — `--internal-cidrs` must include the node network** for the deny-set to
  cover it (the built-in reserved set does not know node subnets), and
  **per-node `vpc_routes` exhaustion** (cap 4096, no per-tenant map quota) falls
  back to the NAT path silently — fail-closed for cross-tenant isolation, but a
  route that should tunnel could egress cleartext under saturation; a saturation
  metric + a drop-on-expected-route mode are owed (increment 6 guardrail).

## 6. Metering and observability

Two layers, cleanly split:

- **Datapath**: a fourth door. `NSDoorNames` gains `"appliance"`
  (`NSGateway, NSEIP, NSLB, NSAppliance`), and crossings through a forwarding
  leg are counted against it — keyed on the Port's role, not the packet flag,
  exactly as `docs/multi-attach.md` §5 prescribes. This closes the documented
  "forwarding traffic reads as `door="gateway"`" gap for every appliance, VPN or
  not.
- **Tunnel**: both shims expose Prometheus metrics on `:9410/metrics`, with one
  series per `VPNConnection`. WireGuard reads peer state through `wgctrl`; IPsec
  streams live IKE/CHILD-SA state through VICI and aggregates all active/rekeyed
  SAs belonging to the connection. The common byte metrics are
  `cozyplane_vpn_connection_{rx,tx}_bytes_total{connection}`; IPsec adds
  `backend="ipsec"` to its series and also
  exports packet totals and `cozyplane_vpn_connection_up`; both backends expose
  `cozyplane_vpn_connection_last_handshake_timestamp_seconds`. Kubernetes pod
  discovery adds the namespace, pod and gateway labels at scrape time. The
  controller publishes the scrape annotations and named `vpn-metrics` port for
  both backends. When the VictoriaMetrics Operator CRD is available, the chart
  installs a cross-namespace `VMPodScrape` selecting only
  `app=cozyplane-vpn-gateway`. The datapath never learns what a "connection" is.

## 7. MTU

TCP SYNs entering a VPN route or Geneve north-south path have an advertised MSS
above the conservative encapsulation-safe ceiling reduced in eBPF. The bounded
TCP-option walk leaves absent/smaller MSS values, SYN+ACK, UDP and ICMP intact;
PMTU signalling remains the fallback for every other packet.

Tunnel overhead (WireGuard 60 bytes, ESP with NAT-T encapsulation ~73) stacks
with Geneve's 50 wherever the decrypted path crosses nodes. `VPC.spec.mtu`
already exists and is advertised to guests. The shared MSS implementation is
applied once at the encapsulating boundary for VPN routes, FloatingIPs,
north-south Geneve and DSR. Its bounded option parser and every tc entry point
are loaded through the kernel verifier in CI.

### 7.1 Kernel prerequisites (and the Cozystack/Talos ask)

Both appliance backends terminate crypto in the kernel, so each has a
compile-time kernel dependency. These are node-image properties, not things a
workload can set at runtime:

| Backend | Requires | Validated Talos v1.13.6 image (kernel 6.18.38) |
|---------|----------|-----------------------------------------------|
| WireGuard | `CONFIG_WIREGUARD` | **present** (`=y`) |
| IPsec (route-based) | `CONFIG_XFRM_INTERFACE` | **present** (`=y`) |

`CONFIG_XFRM_INTERFACE` is mainline since Linux 4.19 and is the portable way to
do route-based IPsec — chosen precisely so the backend is not tied to one distro.
The option is compile-time, not a machine-config knob. If a Talos image builds
it as a module (`=m`), that module must also be included in the boot artifact and
loaded. The validated cluster image builds it in (`=y`). The appliance still
fails closed and loud when the runtime capability is unavailable (§10.3). No
policy-based fallback is shipped because it would pull ESP policy into the
datapath, which the route-based design exists to avoid.

## 8. Testing

- **Increment 0**: `test/vpc-e2e.sh` exercises `spec.appliance` and
  `allowForwarding` with the two-VPC router path.
- **Route table**: e2e with both doors live — internet egress via NAT identity,
  a routed prefix via the appliance, and the boundary cases (route to an
  ungranted Port is inert; longest-prefix override; route removal restores NAT).
- **WireGuard**: a live two-gateway tunnel is exercised with application traffic
  across distinct VPCs; an independently managed off-cluster peer remains a CI
  follow-up.
- **IPsec**: a live strongSwan-to-strongSwan IKEv2/ESP/NAT-T pair is exercised
  across distinct VPCs with application traffic and per-connection metrics.
  Interop with commercial firewalls remains a documented manual matrix, not CI.
- **Reusable CI harness**: `test/vpn-e2e.sh` creates a throw-away namespace,
  generates its WireGuard PSK or IPsec PSK at runtime, and drives a managed
  gateway pair through application traffic. `BACKEND=wireguard|ipsec` and
  `KCTX` make the same suite run after `test/e2e.sh` on kind and against the
  dedicated laboratory context. `MODE=materialize` validates kind's control
  plane and route realization without inventing external endpoint allocation;
  `MODE=live` requires the laboratory FloatingIP allocator and verifies the
  handshake and traffic. The separate self-hosted job owns Talos and any
  physical-lab validation.
- Unit tests follow the house pattern: one `_test.go` per reconciler,
  fake-client, small builders. No manifest-grepping drift guards.

## 9. Open questions

1. **Naming.** `VPNGateway` is one letter from `VPCGateway` — readable on the
   page, dangerous at 2 a.m. Alternatives: `TunnelGateway`/`Tunnel`, or hanging
   connections off `VPNGateway` only and dropping the second kind. Bikeshed
   flagged, not resolved here.
2. **Route target shape.** `via.podSelector` (symmetric with `spec.appliance`)
   vs. an explicit `portRef`. Selector proposed; it survives rescheduling
   without an intermediary.
3. **HA default.** All three tiers in §3.5 are selectable; the default stays a
   single pod. Operators choose warm standby, KubeVirt live migration, or
   active-active BGP/BFD explicitly because their infrastructure and remote-peer
   contracts differ.
4. **Appliance image.** A new `cozyplane-vpn-appliance` image (strongSwan +
   shim) is a real maintenance surface — version pinning, CVE cadence. Who owns
   it, and does WireGuard-only v1 ship without strongSwan at all?
5. **Certificate authority ownership.** Certificate/EAP authentication and
   address pools consume namespace Secrets (including cert-manager TLS Secrets).
   Cozyplane intentionally does not operate a per-VPC CA.

## 10. Increments

0. **[DONE] Close the debts on the built half**: `door="appliance"` metering
   (`NS_APPLIANCE`); fixed the stale `Port.spec.forwarding` /
   `cmd/cni/main.go` `PORT_F_GATEWAY` comments.
1. **[DONE] Route table + scoped grant** — the #6 core, customer-operated VPN
   served end to end:
   - `VPCGateway.spec.routes[].{cidrs, via.podSelector}` + `status.routes` +
     the `RoutesResolved` condition; the controller resolves each route to a
     Port by the appliance's oldest-wins rule (`reconcileRoutes`), the agent
     programs the `vpc_routes` LPM map (`watchRoutes`, `SyncRoutes`).
   - the datapath `vpc_routes` probe in `from_pod` (before NAT) and the
     `from_overlay` mirror, delivering by identity and metering on the
     appliance door.
   - `VPCBinding.spec.forwardingCIDRs` + `PORT_F_FWD_SCOPED` + the per-veth
     `fwd_cidrs` allowlist, scoping the anti-spoof lift to declared prefixes
     (a blanket grant still wins the union); the CNI programs it
     (`requireVPCBinding`, `configureHostVeth`, `ClearFwdCidrs`).
   - Verified on kind (functional + attacker review): routing (dst preserved,
     not NAT'd), scope enforcement (in-CIDR delivered; out-of-CIDR, VPC-member,
     node, service, pod sources all dropped), the export gate blocking a
     non-owner from widening the grant, routes VNI-scoped, door metering,
     verifier-clean load, fail-closed map exhaustion. **Known limitations owed
     before/at merge** (none re-open the blanket spoof #6 closed; all bounded to
     the tenant's own namespace): (a) *grant granularity* — `forwardingCIDRs`
     scopes to prefixes but `VPCBinding` has no pod selector, so like
     `allowForwarding` today the grant covers every pod bound to the VPC in the
     namespace, not only the appliance (a binding-model question for the
     maintainer); (b) *route CIDR deny-set* — `reconcileRoutes` does not yet
     reject a cluster-internal CIDR (pod/service/node/link-local); the datapath
     only steers a VPC pod's off-VPC egress so node/cross-tenant traffic is
     unaffected, but the deny-set is owed; (c) *per-node map quotas* —
     `vpc_routes`/`fwd_cidrs` are per-node (cap 4096) with no per-tenant quota,
     exhaustion fail-closed (increment 6 guardrail); (d) *`fwd_cidrs` reclaim* —
     cleared at CNI ADD (closing the ifindex-reuse hazard) but not at DEL; a
     slow, bounded, non-security leak a rebuild-scan prune would close.
2. **[DONE] Managed WireGuard** — the tenant declares intent, the controller
   runs the tunnel:
   - `VPNGateway` (`{vpcRef, wireguard.listenPort, externalAddress}`, status
     `{address, publicKey, appliancePort, routes, phase, conditions}`) and
     `VPNConnection` (`{gatewayRef, remoteCIDRs, wireguard.{peerPublicKey,
     peerEndpoint, presharedKeySecretRef, persistentKeepalive}}`), served by the
     aggregated apiserver (not CRDs).
   - `VPNGatewayReconciler` (`internal/controller/sdn/vpngateway_controller.go`)
     materializes, from a gateway + its connections: the WireGuard keypair Secret
     (only the public key surfaced), the peer config Secret the appliance mounts
     (checksum-rolled), the appliance `Deployment` (VPC-attached, running
     `cmd/vpn-gateway`), the scoped `VPCBinding` (`forwardingCIDRs` = union of the
     connections' `remoteCIDRs` — increment 1's grant, reused verbatim), the
     `FloatingIP` endpoint (target = the appliance's tenant IP), and
     `status.routes` (each connection's remote CIDRs → the appliance Port).
   - `cmd/vpn-gateway` terminates kernel WireGuard in the appliance's netns via
     `wgctrl` + `netlink` (create `wg0`, configure peers, route the remote CIDRs
     into the tunnel, enable forwarding) — **no crypto in the datapath**.
   - the agent's `watchRoutes` merges `VPNGateway.status.routes` into the same
     `vpc_routes` table it builds from `VPCGateway.status.routes`.
   - **Authorization**: the `VPCBinding` admission requires the `export` verb on
     the VPC (increment 1's guard). The controller holds it cluster-wide and
     creates the grant on the tenant's behalf, so the tenant's authority is the
     level above — "create a `VPNGateway` in my namespace for a VPC I own"
     (`spec.vpcRef` is local; the controller resolves it only in the gateway's
     own namespace). The forwarding stays scoped to declared `remoteCIDRs` and is
     re-judged north-south by SecurityGroups.
   - Verified on kind: the control plane materializes end to end (keypair/config
     Secrets, scoped binding, appliance pod with `wg0` up, FloatingIP target,
     resolved Port, `status.routes` + `publicKey`), the agent programs
     `vpc_routes`, and a VPC pod's traffic to a connection's remote CIDR is routed
     to the appliance and metered on `door="appliance"` (1:1 packet delta).
     FloatingIP address stays Pending only where no LoadBalancer implementation is
     installed (environmental, not a code gap). **Known limitation owed at merge**:
     `remoteCIDRs` share increment 1's *route CIDR deny-set* debt — a tenant
     declaring a cluster-internal CIDR (pod/service/node) as remote is not yet
     rejected; only the managed appliance (not tenant code) forwards under the
     grant, but the deny-set is owed before this is enabled by default.
   - Validated on the Talos/Cozystack cluster with two managed gateways: the
     WireGuard handshake completed and application traffic crossed from one VPC
     workload to the other. An independently managed off-cluster peer remains a
     portability/interop follow-up.
3. **[DONE] Managed IPsec site-to-site** — the enterprise-interop backend,
   sharing every control-plane mechanism with the WireGuard one:
   - `VPNGateway.spec.ipsec` (`{proposals}`) selects the backend; the connection
     carries `VPNConnection.spec.ipsec` (`{peerAddress, auth.pskSecretRef,
     proposals, dpdDelay, startAction}`). `startAction: Start|None` elects one
     initiator for managed pairs; unset preserves the historical address-based
     behavior. Exactly one of `wireguard`/`ipsec` per gateway.
   - the controller (`backendOf`, `buildIPsecConfig`) renders the same objects as
     the WG path — scoped `VPCBinding`, `FloatingIP`, `status.routes` — but a
     `cozyplane-vpn-gateway-ipsec` appliance and a PSK-bearing config Secret (the
     PSK read from the connection's referenced Secret, never a spec field). No WG
     keypair, no `publicKey` in status.
   - `cmd/vpn-gateway-ipsec` runs charon (strongSwan) and drives it over VICI
     (`govici`): loads the PSK (`load-shared`) and an IKEv2 connection
     (`load-conn`) that is **route-based** — TS `0.0.0.0/0`, selection by a stable
     per-connection `if_id` on an `ipsec<if_id>` xfrm-interface — so **no crypto,
     no netfilter, no SPD in the datapath**. Each remote CIDR routes to that
     interface; decrypted traffic leaves on the VPC leg under the scoped grant.
   - Verified on kind: the control plane materializes (scoped binding
     `forwardingCIDRs`, resolved appliance Port, `status.routes`), the appliance
     runs charon, VICI loads the connection (`swanctl --list-conns` shows IKEv2,
     the peer address, PSK auth, DPD, route-based TS), and a VPC pod's traffic to
     the connection's remote CIDR is routed to the appliance and metered on
     `door="appliance"` (1:1 delta, cross-node).
   - **Kernel prerequisite — `CONFIG_XFRM_INTERFACE`.** The route-based data path
     binds each SA to an `xfrm` interface. This is the deliberate, **portable**
     choice: xfrm-interfaces are mainline since Linux 4.19 and work on any
     standard kernel that enables the option — the design is not tied to one
     distro, which is why it is kept over a platform-specific policy-based hack.
     The appliance **preflights** the capability at startup (`probeXfrmSupport`)
     and **fails loud** — a clear error naming `CONFIG_XFRM_INTERFACE`, exit
     non-zero — rather than bringing IKE up over a tunnel that can carry no
     traffic. So a node without it shows an unmistakable `CrashLoopBackOff` +
     message, never a silent dead tunnel.
	- **Platform validation.** The deployed Talos v1.13.6 image (kernel
	  **6.18.38**) reports `CONFIG_XFRM_INTERFACE=y`, together with `CONFIG_XFRM`,
	  `CONFIG_XFRM_USER`, `CONFIG_INET_ESP`, `CONFIG_INET6_ESP` and
	  `CONFIG_WIREGUARD`. A limited userspace `ip` binary reporting "Unknown device
	  type" is not a valid kernel-capability test; the appliance preflight uses
	  netlink directly and successfully creates the interface. Images that build
	  the option as `=m` must ship and load the matching signed module.
   - Validated end to end on the Talos/Cozystack cluster: two managed peers
     established IKEv2 and CHILD SAs over ESP-in-UDP/NAT-T, and application HTTP
     traffic crossed the xfrm interfaces between distinct VPCs. The route-CIDR
     deny-set is enforced before materialization. Commercial-firewall and
     independently managed off-cluster interop remain manual follow-ups.
4. **[IMPLEMENTED] HA + resource guardrails** (§3.5):
   - **[DONE] Tier-2 warm standby**: `VPNGateway.spec.highAvailability` runs the
     appliance as two same-identity replicas (shared config Secret) anti-affined
     across nodes. A node loss costs one handshake, not a reschedule — the
     controller's oldest-wins Port resolution re-targets the FloatingIP and the
     route to the survivor. Verified on kind: two pods on distinct nodes; killing
     the targeted pod re-resolved `status.appliancePort` to the survivor and the
     route kept metering (1:1 delta) across the failover.
   - **[DONE] Resource guardrails**: mandatory appliance requests/limits
     (defaulted, `--vpn-*` overridable), a dedicated gateway node-pool via
     `--vpn-gateway-node-selector` + `--vpn-gateway-toleration-key`, and a
     per-tenant quota (`--vpn-max-gateways-per-namespace`,
     `--vpn-max-connections-per-gateway`, sensible built-in defaults) rejecting an
     over-quota gateway with a `QuotaExceeded` condition before it materializes.
     Verified: limits present on the appliance; a 2nd connection past the cap was
     rejected in status.
   - **[DONE] Readiness-aware selection**: both appliances expose `/readyz`; the
     Deployment probes it every second and route/FloatingIP resolution considers
     only Ready pods. A process without a WireGuard device or responsive VICI
     session cannot become the selected next hop. HA gateways also poll live
     status every second, bounding process-level detection to the requested
     three-second window; node-loss detection still depends on Kubernetes node
     health and is not claimed as a three-second SLO.
   - **[IMPLEMENTED, INFRA VALIDATION REQUIRED] Tier-1**:
     `ha.mode=LiveMigration` reconciles a KubeVirt `VirtualMachine` with
     `evictionStrategy=LiveMigrate`, bridge pod networking, an RWX state PVC,
     a digest-pinnable containerDisk and controller-owned cloud-init. The image
     builder installs both VPN binaries and a systemd dispatcher. A real drain
     test still requires an RWX StorageClass and a built/published appliance
     image in the target cluster.
   - **[IMPLEMENTED, PEER VALIDATION REQUIRED] Tier-3**:
     `ha.mode=ActiveActive` creates two stable StatefulSet members, distinct
     WireGuard identities (or independent IPsec SAs), two FloatingIPs, two route
     next-hops and an FRR BGP/BFD sidecar. `vpc_routes` performs deterministic
     two-way ECMP. WireGuard connections may supply ordered `peerPublicKeys` and
     `peerEndpoints`; status publishes both local keys and endpoints. Unit,
     build and kernel-verifier checks pass; loss-free failover still requires a
     cooperating external BGP/BFD peer.
5. **[IMPLEMENTED] Roadwarrior**: IPsec certificate and EAP authentication,
   cert-manager-compatible TLS Secrets, named per-VPC address pools, VICI-loaded
   credentials/pools and assigned-address status. Per-device WireGuard remains
   expressible as ordinary `VPNConnection` peers and is intentionally not a
   separate credential authority.
6. **[DONE] Managed hub — one VPNGateway, several VPCs
   (`spec.additionalVPCRefs`)** (§3.3):
   - `VPNGateway.spec.additionalVPCRefs []LocalVPCRef` (same namespace as the
     gateway, max 9) names further VPCs the appliance serves alongside the
     PRIMARY `spec.vpcRef`, gateway-level: every connection's `remoteCIDRs`
     route into every served VPC, and every served VPC reaches every
     connection's remote sites.
   - the appliance pod multi-attaches one leg per served VPC
     (`sdn.cozystack.io/networks`, entry 0 = primary); the controller writes one
     `VPCBinding` per served VPC (`<gw>-vpn` primary, `<gw>-vpn-<vpc>`
     additional, same scoped `allowForwarding`/`forwardingCIDRs`, pruned by
     label on removal) and one `status.routes` entry per connection × served
     VPC, pointed at the primary-selected appliance pod's leg in that VPC — the
     agent's existing VNI-scoped route lookup needed no change.
   - the hub constraint is enforced, not just documented: overlapping
     served-VPC CIDRs hold the gateway `Pending` (`VPCCIDRsOverlap`), and a
     `remoteCIDR` overlapping a served VPC is refused via the route-CIDR
     deny-set (`RemoteCIDRsAccepted`, reason "served VPC").
   - the primary VPC keeps the encapsulation/default-route leg and the tunnel
     MTU budget; active-active's `AdvertiseCIDRs` become the union of every
     served VPC's CIDRs.
   - **Known limitation**: forbidden with `ha.mode: LiveMigration` — the
     KubeVirt VM appliance has a single NIC, and Multus multi-NIC for the
     appliance VM is out of scope.

Docs before code at every step, per the house rule — each increment updates this
document and `docs/roadmap.md` as part of the change, not after.

## Appendix — Cozystack integration

cozyplane already enters Cozystack as a networking variant
(`packages/system/cozyplane*`, cozystack#3149), growing the same
`sdn.cozystack.io` group Cozystack's `SecurityGroup` lives in; the new kinds
follow that precedent and need nothing special from `cozystack-api` — tenants
reach them through cozyplane's own RBAC aggregates.

Catalog exposure follows Cozystack's uniform app convention: a chart pair
`packages/apps/vpn-gateway` + `packages/system/vpn-gateway-rd` (the
`ApplicationDefinition` — dashboard category NaaS, OpenAPI schema generated from
the chart's annotated `values.yaml`), a `PackageSource`
(`cozystack.vpn-gateway-application`) bundling the two, and one
`cozystack.platform.package.default` line in
`packages/core/platform/templates/bundles/naas.yaml`, next to
`vpn-application` and `tcp-balancer-application`. The app chart renders the
`VPNGateway`/`VPNConnection` objects and their Secrets; the dashboard surface
(visible Services/Secrets, tenant RBAC on the exact named resources) comes for
free from the `ApplicationDefinition` + `dashboard-resourcemap` pattern.

Two coexistence notes. Cozystack's existing `vpn` app is Outline/Shadowsocks —
an *outbound proxy*, a different product; both apps stay, and the dashboard copy
must make the distinction. And the `VirtualPrivateCloud` app (kube-ovn-backed
today) is the natural object to grow VPN-facing fields once cozyplane backs it —
out of scope here, noted so the two designs do not drift apart.
