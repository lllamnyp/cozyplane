# Policy layers — who gates what

cozyplane has three policy surfaces. They share enforcement machinery but
deliberately not audiences, and **no flow is ever owned by two of them**.
This doc is the canonical answer to "which layer do I write rules in" and
records the trust model their exemptions rest on.

| Layer | Kind | Written by | Subjects |
|-------|------|-----------|----------|
| [SecurityGroup](security-groups.md) | `sdn.cozystack.io` (namespaced) | the VPC owner (tenant) | VPC ports — traffic on **VPC IPs** |
| [NetworkPolicy](network-policy.md) | upstream `networking.k8s.io/v1` | namespace owners | net-0 pods — traffic on **net-0 pod IPs** |
| [HostFirewall](host-firewall.md) | `sdn.cozystack.io` (cluster-scoped) | the cluster operator only | the **nodes** themselves |

## Trust zones

The layers map onto three trust zones, in descending privilege:

- **Hosts** — the operator's. Nothing a workload does may reprogram them.
- **The default network (net 0)** — *semi-privileged*. Anything attached to
  it (system pods, net-0 VM guests) can address node IPs and other net-0
  pods directly; it is infrastructure land, not tenant land. The
  HostFirewall exists largely because this zone is only *somewhat* trusted.
- **VPCs** — tenant land. A VPC workload cannot address a node or a net-0
  pod at all (the datapath has no sanctioned path for it; gateway and
  floating egress surface as pod-sourced or refuse cluster-internal
  destinations). True tenant isolation is the VPC boundary itself; the
  policy layers refine what crosses it, they don't create it.

## Flow ownership

Ownership is decided by the network a flow rides, not by which objects
select the endpoint — a tenant NetworkPolicy may *select* a VPC pod (both
key on labels), but it never gates that pod's VPC traffic:

| Flow | Owner | Why the others don't fire |
|------|-------|---------------------------|
| to/from a **VPC IP** (east-west, peering, gateway, floating, LB→VPC backend) | SecurityGroup | NP's gate lives in `to_pod`'s net-0 branch (`!dstnet`) — structurally skipped; HF looks only at host-destined traffic |
| to a **net-0 pod IP** — from another net-0 pod, from an LB/NodePort delivery (client source preserved), or raw routed external ingress | NetworkPolicy | SG never sees VNI 0; HF not host-destined |
| **pod → node address** | HostFirewall (at the destination node) | NP's node-destined egress is exempt by design — one owner per contract, no double jeopardy |
| **node-originated** (kubelet probes, apiserver→pod/webhook, node→anything) | *nobody — structurally exempt from all three* (see below) |

Consequences worth spelling out:

- **No SecurityGroup can break kubelet health checks.** A probe rides the
  fabric bridge with no `NS_MARK` and is delivered before any SG code runs;
  NP exempts node sources via `np_nodes`; HF doesn't gate node→pod. This
  holds for any pod, net-0 or VPC (e.g. a tenant etcd's readiness). What a
  restrictive SG *does* gate — by design — is the tenant's own east-west
  (etcd peer traffic on VPC IPs) and their own health-checking *pods*: the
  exemption is deliberately narrow so workloads can't ride it.
- **NP selecting a VPC pod is inert.** All of that pod's net-0 deliveries
  are either node-exempt or sanctioned north-south paths that return before
  the NP block. Intended: SG is a VPC pod's policy surface.
- **Known corner (decision pending):** an NP-egress-isolated net-0 pod
  dialing a VPC pod's *fabric* IP slips between the layers — the `from_pod`
  gate sees the fabric IP has an identity and defers to the destination
  gate, which the sanctioned north-south path never runs. The flow is still
  SG-gated at the destination, but the client's own egress rules don't
  constrain it the way an external CIDR would. Candidate fix: drop VPC pods
  from `np_ident`, making their fabric IPs "external" to NP (`ipBlock`
  territory); alternative: document as intended. Neither done yet.

## The node-origin exemption is plumbing, not policy

All three layers exempt node-originated traffic unconditionally. This is
invariant #7 (the Kubernetes contract is plumbing): probes, apiserver→
webhook, and kubelet↔apiserver must keep working *no matter what anyone
writes*. It is deliberately **not** an explicit default-allow policy
object: a deletable "allow kubelet" rule is one `kubectl delete` — or one
not-yet-synced watch at pod start — away from every isolated pod in the
cluster going NotReady. Plumbing must not be revocable from the policy
surface, any more than the Geneve port should be.

What *is* legitimate policy is everything beyond that contract minimum:
node→pod scrapes, node→internet. Those become expressible when the
HostFirewall's **egress** increment lands (roadmap §6) — the natural home
for gating node-originated traffic, since upstream NetworkPolicy has no
vocabulary for "the kubelet" as a peer, while HostFirewall already has the
node as its subject and the operator as its author.

## The trust model under the exemption — and where it must go

Today every layer recognises node origin by **source address** (`np_nodes`,
`hf_self`, the absence of `NS_MARK`), backstopped by the underlay's
anti-spoofing. That makes the exemption exactly as strong as the guarantee
that nothing can *mint* an exempt address — and the host-firewall e2e
already caught one minting path: the cluster-egress masquerade rewrote v6
pod→node flows to a node source (the `node_remotes` laundering bug,
host-firewall.md). Fixed, but the class remains: any future path that
rewrites sources into the exempt set silently re-opens all three layers.

The hardening direction, recorded here so it survives until it's built:
**path-trust instead of address-trust.** Node origin is provable by the
channel it arrives on, not the address it wears — same-node node-origin
enters host→veth, a channel pods cannot inject into; cross-node node-origin
can ride the overlay with node-controlled provenance (the `node_remotes`
encap, authenticatable the way SG's stage-B Geneve TLV already is). Under
path-trust the laundering class is structurally impossible: masqueraded
traffic arrives on the uplink, not through a node channel, whatever source
it carries. Until then, the exemption should be *visible* even though it is
not revocable — a per-layer `*_node_exempt_total` counter is the cheap
first step.
