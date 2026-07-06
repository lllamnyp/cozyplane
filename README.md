# cozyplane

A multi-tenant, eBPF-based CNI for [Cozystack](https://cozystack.io), built so
that cloud-style tenancy — not a flat cluster network — is the backbone. It
replaces kube-ovn for VPC networking; ClusterIP/Service load-balancing stays with
kube-proxy or Cilium's kube-proxy replacement, which cozyplane coexists with (a
built-in replacement that imports Cilium's LB components is
[under design](docs/kube-proxy-replacement.md)).

> **Status: functional, pre-production.** The default pod network and the full VPC
> datapath — tenant isolation, overlapping CIDRs, peering, egress, floating public
> IPs, and IPv6/dual-stack — work and are covered by an e2e suite. VM live
> migration with **IP + MAC preservation** is validated on a real cluster with
> KubeVirt (including an IPv6 VM), and the whole thing is packaged for Cozystack.
> Not yet: network policy / security groups, split-horizon DNS, and removing the
> interim netfilter dependency. See [docs/roadmap.md](docs/roadmap.md) for the full
> built-vs-outstanding checklist, [docs/design.md](docs/design.md) for the vision,
> and [docs/internals.md](docs/internals.md) for what exists as-built.

## What works today

- **Default/system pod network** over an eBPF Geneve overlay: cross-node
  pod-to-pod, node↔pod, kubelet probes; coexists with kube-proxy / Cilium-KPR for
  Services. Dual-stack (IPv4 + IPv6).
- **VPCs**: a namespaced `VPC` (its namespace is its owner); a pod attaches by
  annotation, gated default-deny by a `VPCBinding` in the pod's namespace. Same-VPC
  pods reach each other across nodes; a VPC pod can't initiate to anything outside
  its VPC unless explicitly allowed.
- **Overlapping VPC CIDRs**: delivery is net-scoped (VNI-keyed), so distrusting
  tenants may reuse the same address ranges without collision.
- **Tenancy & revocation**: the VPC owner grants use with a `VPCBinding` (creation
  gated by an `export` SAR on the VPC); deleting it reaps the Ports and severs the
  attached pods.
- **Dual-address bridge**: a VPC pod's `status.podIP` is a unique fabric IP (so
  kubelet probes, Services, and the system network can reach it) while its interface
  carries the hidden tenant VPC IP — the pod never sees the node/management network.
- **VPC peering**: symmetric `VPCPeering` halves, native cross-VPC datapath, status
  controller.
- **Egress**: an opt-in per-VPC NAT gateway (`spec.egress.natGateway`) for VPC↔internet.
- **Floating IPs**: `ExternalPool` + `FloatingIP` give a Port a true public address
  (inbound and outbound), advertised and NAT'd entirely in eBPF — no gateway pod.
- **IPv6 / dual-stack**: v6 VPCs ride the overlay (128-bit map keys, v4 stored in
  RFC 6052 NAT64 form); the fabric-IP family is decoupled from the VPC's, so a v6
  VPC runs even on a v4-only cluster.
- **VM live migration**: a persistent `Port` pins `{VPC IP, MAC}` to a VM NIC
  identity; a KubeVirt bridge-bound VM keeps its VPC IP and MAC across a node move
  (sub-second cutover), validated on a real cluster.
- **Split-horizon DNS for VPCs**: the datapath steers a VPC pod's cluster-DNS
  queries to a per-node resolver that answers the *tenant's* view — headless
  Services annotated into the VPC resolve to VPC IPs, other tenants' names are
  unprovable, external names forward upstream, and names follow reachability
  across peerings. ([Services in a VPC](docs/services-in-vpc.md).)
- **Services inside a VPC (ServiceVIPs)**: an annotated ClusterIP Service gets
  a VIP from the VPC's *own* address space, resolved only by the split-horizon
  DNS and load-balanced in eBPF (flow-pinned DNAT to backend VPC IPs, hairpin
  included) — the ClusterIP-equivalent for tenants, peered VPCs included.
- **IPv6 guest autoconfiguration**: the agent answers Router Solicitations
  (M=1) and runs a per-veth DHCPv6 responder handing out the exact pinned
  `/128` — a bridge-bound VM guest learns its address, default route, and DNS
  server with no console access.

See the [roadmap](docs/roadmap.md) and the [open issues](../../issues) for what's
outstanding (network policy, DNS, netfilter-optional operation, and more).

## Documentation

| Doc | What it covers |
|-----|----------------|
| [docs/user-guide.md](docs/user-guide.md) | Install it, create a VPC, attach pods, verify, limitations |
| [docs/internals.md](docs/internals.md) | How it works as-built (datapath, control flow, packet walks) and how the code is structured |
| [docs/design.md](docs/design.md) | The architecture vision (three planes, dual-address bridge, identity) |
| [docs/control-plane.md](docs/control-plane.md) | The aggregated-apiserver control-plane design |
| [docs/live-migration.md](docs/live-migration.md) | VM live migration via persistent Ports (IP + MAC preservation) |
| [docs/roadmap.md](docs/roadmap.md) | Checklist of what's built and what's outstanding, with open-issue index |
| [docs/security-groups.md](docs/security-groups.md) | *Design draft* — intra-VPC network policy (security groups) |
| [docs/vm-provisioning.md](docs/vm-provisioning.md) | *Design draft* — metadata endpoint & guest autoconfiguration |
| [docs/cross-family.md](docs/cross-family.md) | *Design draft* — cross-family (v4↔v6) peering & north-south |
| [docs/services-in-vpc.md](docs/services-in-vpc.md) | *Design draft* — Services inside a VPC (per-VPC VIPs, split-horizon DNS) |
| [docs/kube-proxy-replacement.md](docs/kube-proxy-replacement.md) | *Design draft* — own Services by importing Cilium's LB + socket-LB |

Contributor invariants (never reach for iptables in the datapath, 128-bit/NAT64
address form, etc.) live in [CLAUDE.md](CLAUDE.md).

## Repository layout (one line each)

```
bpf/            eBPF datapath (C, CO-RE) — tc classifier + maps; compiled object is committed and go:embed'd
datapath/       Go: load/pin eBPF, manage Geneve + maps, program bridges/locals/remotes/floating/peers
cmd/cni/        CNI plugin binary (per-pod ADD/DEL; VPC attach, persistent-Port bind)
cmd/agent/      node agent DaemonSet (loads datapath, watches Nodes/VPCs/Ports/…)
cmd/sdn-controller/  controllers: VNI assignment, peering, floating IPs, live-migration cutover/GC
cmd/apiserver/  aggregated API server — serves the sdn.cozystack.io API
cmd/gateway/    per-VPC egress NAT gateway
api/sdn/        API types: VPC, Port, VPCBinding, VPCPeering, ExternalPool, FloatingIP
internal/       apiserver wiring (internal/cmd, internal/setup) + controllers
pkg/apiserver/  aggregated apiserver framework
pkg/registry/   REST storage for the apiserver
pkg/generated/  generated clientset/informers/listers/openapi
config/crd/     generated CRDs (the prototype serving path, alongside the aggregated server)
deploy/         DaemonSet, controller Deployment, RBAC
chart/cozyplane/  Helm chart (Cozystack packaging)
test/           kind cluster config + e2e suite
```

## Quick build

```
make generate   # k8s codegen (deepcopy/conversion/defaults/openapi/clientset)
make build      # builds all binaries into bin/
docker build -t ghcr.io/lllamnyp/cozyplane:dev .   # eBPF object is committed + embedded — no clang needed
```

To change the datapath, edit `bpf/overlay.c` and regenerate the committed object
(needs clang + bpftool); see [CLAUDE.md](CLAUDE.md). Then see the
[user guide](docs/user-guide.md) to run it on kind.
