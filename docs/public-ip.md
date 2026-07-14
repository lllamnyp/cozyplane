# Public IPs on the default network — superseding cozy-proxy

**Status: DESIGN — not implemented.**

A Cozystack VM on the default network sometimes needs a real public address: all
ports forwarded to it, and its own outbound traffic leaving *as that address*, so
external allow-listing works. Today [cozy-proxy](https://github.com/cozystack/cozy-proxy)
provides this with nftables. When cozyplane lands as the CNI it takes over the
default network, and cozy-proxy has to go — this document is how the capability
survives the transition.

The short version: **cozyplane already has this datapath.** It is the floating-IP
(EIP) machinery, which is net-scoped and simply refuses to run at net 0. The work is
not to build a NAT; it is to let the existing one serve the default network **without
punching a hole in NetworkPolicy**, which is the one thing a naive port would do.

---

## 1. The capability to save

cozy-proxy watches Services carrying the standard delegation label
`service.kubernetes.io/service-proxy-name: cozy-proxy` — the upstream mechanism that
tells the default proxy to keep its hands off — and gives them 1:1 NAT:

| | cozy-proxy |
|---|---|
| **selector** | the `service-proxy-name` label. The label is the *only* selector |
| **ingress, `wholeIP: "true"`** | every TCP/UDP port of the LB address is forwarded to the backend pod |
| **ingress, `wholeIP: "false"` / absent** | only ports in `spec.ports`; the rest dropped |
| **egress, both modes** | the pod's outbound traffic is SNATed to the LB address |
| **ICMP** | dropped in port-filter mode unless `allowICMP: "true"` |
| **state** | stateless: nft `raw`/`mangle` priorities, conntrack bypassed |
| **family** | `table ip` — IPv4 only |

Two Kubernetes limitations are the whole reason it exists: a Service forwards only
the ports you list ([kubernetes#23864](https://github.com/kubernetes/kubernetes/issues/23864)),
and kube-proxy does not SNAT, so the VM's egress wears the node's address instead of
its own.

## 2. Why it cannot simply keep running

- **It is nftables.** Cozyplane's first invariant is that the datapath is pure eBPF:
  no iptables, no fwmark, no policy routing to move, isolate or NAT pod traffic. The
  only netfilter in the tree is conditional on the cluster's kube-proxy having a
  `KUBE-FORWARD` chain — and on a cozyplane cluster there *is* no kube-proxy, so that
  installs nothing. Adding an nft NAT table back would reverse the direction the
  project has been travelling.
- **Two proxies would claim the same Service.** `cozyplane-kpr` does not honour
  `service.kubernetes.io/service-proxy-name` at all today. So the day cozyplane ships
  next to cozy-proxy, kpr programs the Service into `svc_vips`/`lb_ingress` while
  cozy-proxy writes nft rules for the same address. **Honouring that label is a
  correctness fix kpr owes regardless of this feature** (see §6).

So: supersede, not coexist.

## 3. This is the EIP datapath, at net 0

Line up cozy-proxy's semantics against what cozyplane already runs for floating IPs
and they are the same object:

| cozy-proxy | cozyplane, today (net ≠ 0) |
|---|---|
| stateless 1:1 NAT, conntrack bypassed | the `floating` map — a stateless bijection, no conntrack (`float_ct` was deleted) |
| `wholeIP` — all ports | `floating_forward` DNATs *the address*, not a port. Whole-IP is its native mode |
| `egress_snat` — pod egresses as the LB IP | `floating_egress_snat` — the pod egresses as its public address |
| source preservation | the point of the design |
| `allowICMP`, opt-in | ICMP echo **and ICMP errors with embedded-header NAT** — PMTU and traceroute work, unconditionally, in both families |

Three things stop it at net 0, and none of them is the NAT:

1. `FloatingIP.spec.vpcRef` is required, and the controller only binds a target that
   is a `Port` in that VPC.
2. Pool resolution runs through the VPC's `VPCGateway`.
3. `from_pod` guards the egress SNAT with `if (srcnet && !dstnet)`. A default-network
   pod has `srcnet == 0`, so `floating_egress_snat` **never fires** for it.

(3) is the whole datapath change on the egress side. It must be gated on a flag bit in
the pod's `ports` entry — there is already one at bit 31 for the gateway leg — so an
ordinary net-0 pod does not pay a map lookup on the hottest path in the tree.
`from_pod` sits at ~496 bytes of the 512-byte combined-stack limit and hosts **no
BPF-to-BPF callee at all**; that budget is the reason this is a flag test and not a
lookup.

## 4. The constraint that drives the design: NetworkPolicy

**A naive port of the EIP path to net 0 would bypass NetworkPolicy.** This is the
core of the design and the reason it is written down before any code.

In `to_pod`, a `floating` hit is answered early:

```c
struct bridge_ep *fe = float_of(p.dst);
if (fe)
        return floating_forward(skb, ip, fe->net, fe->vpc_ip);   // delivered
```

The net-0 **NetworkPolicy gate (`np_ingress` / `np_egress`) runs much later in the
same function.** So the floating path never reaches it.

For a VPC that is correct: `floating_forward` calls `ns_sg_admit` internally, so the
north-south **SecurityGroup** gate applies. But **NetworkPolicy is the net-0 policy
layer**, and it has no equivalent hook inside `floating_forward`. Programming
`floating[LB_IP] = {net: 0, podIP}` and letting the machinery run would therefore
deliver an external client's packet straight into the pod with no policy evaluated at
all — on the single most internet-exposed workload on the default network.

That would be **a regression against the thing being replaced.** Under cozy-proxy the
DNAT happens in netfilter and the packet is then delivered normally, so the cluster's
NetworkPolicy implementation still sees and enforces it. Cozyplane must be at least as
safe.

### Three ways out

1. **Call the NP gate from inside `floating_forward` when `net == 0`.** Rejected. It
   nests `np_ingress` (a `noinline` callee) inside an `__always_inline` helper — the
   exact shape already recorded as blowing the combined-stack budget (*"sibling callees,
   not nested ones, near the 512B cliff"*). `to_pod` is at ~432 bytes.
2. **Stop early-returning for net-0 in `to_pod`;** fall through to the normal path and
   apply the DNAT after `np_ingress` admits. Correct — NetworkPolicy resolves the
   *destination* pod from `ports[ifindex]` (the veth), not from the packet's
   destination address, and a 1:1 address NAT leaves the L4 ports alone, so the gate
   evaluates correctly on the un-rewritten packet. Cost: restructuring `to_pod` right
   at the verifier cliff.
3. **Do the whole-IP DNAT at `from_uplink` / `lb_ingress` instead.**  ← **chosen**

`lb_ingress` is a **tail-called** program: a fresh stack and a fresh instruction
budget, which is exactly why LoadBalancer ingress lives there. It already DNATs, and
it already runs gates. Rewrite the destination there, and `to_pod` then sees an
**ordinary packet addressed to the pod, with the external client as its source** —
so the net-0 NetworkPolicy gate applies with **no change to `to_pod` at all**, and
`ipBlock` rules mean exactly what an operator expects them to mean.

It also puts a whole-IP Service where the rest of the LoadBalancer traffic already
is, rather than inventing a second ingress path beside it. The cost is a new lookup
shape — a whole-IP row matches *any* port, where LB rows are keyed
`{proto, addr, port}` — which is a small map, not a new subsystem.

**The egress half is unchanged by this choice**: it is still the `from_pod` SNAT of §3,
because that is the only place a pod's identity is knowable.

## 5. The contract

Drop-in. **No new kind, no new API, no migration** — the manifests Cozystack users
already have keep working:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: example-service
  labels:
    service.kubernetes.io/service-proxy-name: cozy-proxy
  annotations:
    networking.cozystack.io/wholeIP: "true"
spec:
  type: LoadBalancer
  allocateLoadBalancerNodePorts: false
  externalTrafficPolicy: Local
  ports: [{port: 65535}]
  selector: {app: nginx}
```

That this needs no new resource is not laziness, it is the better design on the
project's own tenets:

- **The platform attracts the address.** MetalLB (or a CCM) assigns the LB IP;
  cozyplane consumes `status.loadBalancer.ingress` and *delivers*. Tenet 3 — the CNI
  does not announce — is satisfied by construction, and a bespoke kind would only
  tempt someone to re-implement allocation and announcement inside the CNI again.
- **The Service selects its backend by label.** That is identity, not addresses
  (tenet 4) — strictly better than `FloatingIP.spec.target: 10.0.0.5`, which is
  address-thinking tolerated inside a VPC.
- It is a Kubernetes primitive doing a Kubernetes job.

**kpr must claim the label's value explicitly.** Under upstream semantics a
`service-proxy-name` a proxy does not recognise means *skip* — so if kpr merely
"honours" the label, every existing cozy-proxy Service goes **dark** on upgrade. kpr
therefore answers to a configurable set of names, defaulting to `cozy-proxy` (with
`cozyplane` as an alias), and skips Services delegated to any name outside that set.

`wholeIP: "false"` / absent (**the default**) is per-port filtering — the existing LB
path — **plus the egress SNAT**, which cozyplane does *not* do for a net-0 LB backend
today. cozy-proxy SNATs in **both** modes; that is easy to miss and it is half the
feature.

## 6. What improves for free

Not goals in themselves; they fall out of using the eBPF datapath instead of nft.

- **PMTU works by default.** `allowICMP` becomes a no-op accepted for compatibility.
  cozyplane already NATs ICMP echo *and* the embedded headers inside ICMP errors, so
  path-MTU discovery and traceroute work through a public address without an opt-in.
  cozy-proxy drops ICMP by default in port-filter mode, which silently breaks PMTU.
- **A multi-backend Service is refused, not coin-flipped.** cozy-proxy takes
  `Subsets[0].Addresses[0].IP` — first endpoint wins, silently. A 1:1 NAT with two
  ready backends is ambiguous, and cozyplane has already been bitten by exactly this
  shape (two FloatingIPs on one target overwrote each other's egress row and one
  address went quietly dead). Refuse with a status condition; reuse the
  `TargetExclusive` precedent rather than inherit the coin flip.
- **It is metered.** The EIP door already counts crossings; at net 0 they become
  visible in `cozyplane_vpc_ns_*` instead of being invisible nft counters.
- **IPv6.** cozy-proxy's ruleset is `table ip` — v4 only. Cozyplane's floating path is
  dual-family already.
- **kpr honours `service-proxy-name`** — which it must anyway, or it fights any other
  proxy in the cluster.

## 7. What this does NOT change: field authorization

A Service that carries the label gets a public address, and **any principal who can
create a Service in a namespace can set that label.** Ordinary Kubernetes RBAC cannot
gate it: RBAC authorizes *verbs on resources*, not *fields*.

This is **a pre-existing, unclosed gap, not a decision and not something this change
opens.** It is the same gap cozy-proxy has today, and structurally the same one that
`VPC` attachment had: a pod selects its VPC with an *annotation*, which RBAC cannot
gate either. That one was closed not by gating the field but by **requiring a separate,
RBAC-gated object** — the `VPCBinding`, whose creation needs `export` on the VPC.

The equivalent machinery for Services does not exist yet, and inventing it here would
be the wrong place for it: it belongs with the multi-tenancy work, alongside every
other "a field selects a privileged thing" case, so that they are closed **once**
rather than one bespoke gate at a time. Recorded in [multitenancy.md](multitenancy.md)
as outstanding.

Nothing below is widened by this document. A cozyplane cluster ends up exactly as
permissive here as the cozy-proxy cluster it replaces — no more, no less.

## 8. Increments

0. **kpr honours `service.kubernetes.io/service-proxy-name`** — skip Services
   delegated elsewhere, claim the names we answer to. Independently a correctness fix;
   without it kpr and any other proxy fight over the same Service.
1. **Egress identity.** The `ports` flag bit and the `srcnet == 0` relaxation in
   `from_pod`, plus the net-0 `floating_egress` rows. A net-0 pod behind a managed
   Service now leaves the cluster **as its public address**. This is the half that
   Kubernetes cannot do at all, and it is useful on its own.
2. **Whole-IP ingress.** The wildcard-port row consulted in `lb_ingress`, the DNAT
   hoisted to `from_uplink` (§4), NetworkPolicy applying unchanged in `to_pod`.
   `wholeIP: "false"` keeps the existing per-port path.
3. **Refuse the ambiguous cases** — multi-backend whole-IP Services — with conditions,
   and delete cozy-proxy from the cozyplane variant of the platform bundle.

## 9. Non-goals

- **Allocating or announcing the address.** MetalLB/CCM does that. Cozyplane delivers.
- **A new API kind.** §5.
- **Closing the field-authorization gap.** §7 — it belongs to multi-tenancy, and it is
  not made worse here.
- **Reimplementing nftables anywhere.** §2.
