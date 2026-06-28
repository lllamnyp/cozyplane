# cozyplane

A multi-tenant, eBPF-based CNI for [Cozystack](https://cozystack.io), built so
that cloud-style tenancy — not a flat cluster network — is the backbone. It is
intended to replace kube-ovn for VPCs while leaving Cilium in place as the
kube-proxy replacement / policy engine.

> **Status: early prototype.** The default (flat) pod network and a basic VPC
> overlay with tenant isolation work and are smoke-tested on kind. Many design
> goals (the dual-address probe bridge, overlapping VPC CIDRs, security groups,
> split-horizon DNS, VM live-migration) are **not implemented yet**. See
> [docs/design.md](docs/design.md) for the full vision and
> [docs/internals.md](docs/internals.md) for what actually exists today.

## What works today

- cozyplane as the cluster CNI for the **default/system pod network**, over an
  eBPF Geneve overlay (cross-node pod-to-pod, node↔pod, kubelet probes; coexists
  with kube-proxy / Cilium-KPR for Services).
- **VPCs**: a pod attaches to a named VPC via an annotation, in any namespace,
  and gets an IP from the VPC's CIDR. Pods in the same VPC reach each other
  across nodes; everything else (the default network, the node, other VPCs) is
  blocked.

## Documentation

| Doc | What it covers |
|-----|----------------|
| [docs/user-guide.md](docs/user-guide.md) | Install it, create a VPC, attach pods, verify, limitations |
| [docs/internals.md](docs/internals.md) | How it works as-built (datapath, control flow, packet walks) and how the code is structured |
| [docs/design.md](docs/design.md) | The architecture vision (three planes, dual-address bridge, identity) |
| [docs/control-plane.md](docs/control-plane.md) | The aggregated-apiserver control-plane design |

## Repository layout (one line each)

```
bpf/            eBPF datapath (C, CO-RE) — the tc classifier + maps
datapath/       Go: load/pin eBPF, manage Geneve + maps, attach to veths
cmd/cni/        CNI plugin binary (per pod ADD/DEL)
cmd/agent/      node agent DaemonSet (loads datapath, watches Nodes/VPCs/Ports)
cmd/sdn-controller/  controller (assigns VPC network ids)
cmd/apiserver/  aggregated API server entrypoint (scaffolded; CRDs used for now)
api/sdn/        VPC and Port API types (group sdn.cozystack.io)
internal/       apiserver wiring (internal/cmd, internal/setup) + controllers
pkg/apiserver/  aggregated apiserver framework (from cozyportal scaffolding)
pkg/registry/   REST storage for the apiserver
pkg/generated/  generated clientset/informers/listers/openapi
config/crd/     generated CRDs (how VPC/Port are served today)
deploy/         DaemonSet, controller Deployment, RBAC
test/           kind cluster config for the smoke test
```

## Quick build

```
make generate   # bpf2go + k8s codegen (needs clang + bpftool)
make build      # builds binaries into bin/
docker build -t ghcr.io/lllamnyp/cozyplane:dev .
```

See the [user guide](docs/user-guide.md) to run it on kind.
