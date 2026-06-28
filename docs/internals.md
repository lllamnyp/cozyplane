# cozyplane internals

How cozyplane works **as built today** (the default network + basic VPCs), and
how the code is organized. For the broader architecture this is converging
toward, read [design.md](design.md); where this doc and the design disagree, this
doc describes reality.

## 1. The model in one paragraph

Every pod interface belongs to a **network**, identified by a small integer
*network id*. The default/system network is id `0`. Each `VPC` gets a unique id
(≥100, also used as the Geneve VNI). All inter-node traffic rides a single
per-node Geneve device; the datapath encapsulates a packet only when its
destination is on another node, and drops it when source and destination
networks differ. The default network uses the cluster pod CIDR (unique per node);
VPCs use their own CIDRs (required unique cluster-wide for now). Services are not
cozyplane's job — kube-proxy or Cilium-KPR handles them, unchanged.

## 2. Components

```
            ┌──────────────── control plane ────────────────┐
            │  sdn-controller        VPC/Port API (CRDs)     │
            │  (assigns VPC VNIs)    group sdn.cozystack.io   │
            └───────▲────────────────────▲───────────────────┘
                    │ watch VPCs          │ get VPC / claim Port
        ┌───────────┴──────────┐   ┌──────┴───────────┐
        │ cozyplane-agent (DS) │   │ cozyplane (CNI)  │
        │ per node, hostNet,   │   │ per pod ADD/DEL, │
        │ privileged           │   │ host-side binary │
        └───────────┬──────────┘   └──────┬───────────┘
                    │ load/pin eBPF,       │ veth + IPAM,
                    │ Geneve, maps,        │ writes ports map,
                    │ FORWARD rule         │ attaches program
                    └──────────┬───────────┘
                          eBPF datapath (bpf/overlay.c)
```

- **`cozyplane-agent`** (`cmd/agent`, DaemonSet, `hostNetwork`, privileged). Owns
  the node datapath: loads and pins the eBPF objects, creates the Geneve device,
  sets sysctls and the FORWARD rule, attaches the classifier to the uplink, and
  publishes node state + a kubeconfig for the plugin. It then *watches* the API
  and keeps the maps in sync: `Node` → remote pod CIDRs, `VPC` → the networks
  map, `Port` → remote VPC pod /32s. It depends only on the **core** API for the
  default network, so it can bootstrap before the VPC API exists.
- **`cozyplane` CNI plugin** (`cmd/cni`, invoked by kubelet per pod). Sets up the
  pod's veth, allocates the IP, programs the per-veth network id, and attaches
  the classifier. Two paths: default (host-local IPAM) and VPC (claim a `Port`).
- **`sdn-controller`** (`cmd/sdn-controller`, controller-runtime Deployment).
  Assigns each `VPC` a unique network id (VNI) and marks it `Ready`.
- **API** (`api/sdn`, group `sdn.cozystack.io/v1alpha1`): `VPC` and `Port`.
  Served as **CRDs** today (`config/crd/`); the aggregated API server is
  scaffolded (`pkg/apiserver`, `cmd/apiserver`) and is a drop-in swap because the
  group/version/kind and generated clients are identical.

## 3. The eBPF datapath

One C file, `bpf/overlay.c`, compiled with CO-RE via `bpf2go`. It defines four
maps and one program.

### Maps

| Map | Type | Key → Value | Written by |
|-----|------|-------------|-----------|
| `remotes` | LPM trie | dst IP/CIDR → remote node IP | agent (Nodes + Ports) |
| `networks` | LPM trie | VPC CIDR → network id | agent (VPCs) |
| `ports` | hash | veth ifindex → network id | plugin (per pod) |
| `params` | array | `[0]`=Geneve ifindex, `[1]`=default VNI | agent |

All are pinned under `/sys/fs/bpf/cozyplane/` (`LIBBPF_PIN_BY_NAME`) so the
short-lived plugin and the long-running agent share the same map instances.

### The program: `cozyplane_from_pod`

Attached at **two** hooks via classic tc (clsact, direct-action):

- the **ingress** of every pod's host-side veth (a pod's egress), and
- the **egress** of the node's uplink (host-originated traffic, e.g. the reply
  path of NATed Service traffic or the apiserver reaching a pod).

For each IPv4 packet it:

1. reads the **source net** from `ports[skb->ifindex]` (absent ⇒ `0`; the uplink
   ifindex is never in `ports`, so host-originated traffic is the default net);
2. reads the **destination net** from the `networks` LPM (absent ⇒ `0`);
3. **drops** (`TC_ACT_SHOT`) if the two differ — this is the isolation gate;
4. looks up the destination in `remotes`. Miss ⇒ `TC_ACT_OK` (local pod, or
   off-cluster/node traffic the kernel routes). Hit ⇒ encapsulate:
   - rewrite the inner Ethernet destination to the shared overlay MAC (see
     below), set the Geneve tunnel key (`tunnel_id` = source net id, remote =
     the node IP from `remotes`), and `bpf_redirect` to the Geneve device.

There is deliberately **no receive-side program**. Decapsulation and delivery
are done by the kernel (see the two tricks below), which keeps the datapath
small for the prototype.

### Trick 1 — the shared Geneve MAC (decap delivery)

The Geneve device runs in `collect_metadata` (external) mode and carries L2
frames. A decapsulated frame still has the *sending* node's inner Ethernet
destination MAC, which is foreign on the receiver, so the kernel marks it
`PACKET_OTHERHOST` and refuses to route it. `skb->pkt_type` is read-only in tc,
so instead every node's Geneve device is given the **same fixed MAC**
(`02:cf:cf:cf:cf:cf`, `datapath.OverlayMAC` / `OVERLAY_DMAC`), and the encap path
rewrites the inner destination to it. The decapsulated frame is then addressed to
the receiver's own Geneve device → `PACKET_HOST` → the kernel forwards it to the
local pod via that pod's `/32` route. (This is the Flannel-style trick adapted to
eBPF encap.)

### Trick 2 — FORWARD ACCEPT (conntrack)

Pod egress is encapsulated by a tc `bpf_redirect`, which **bypasses conntrack**.
The decapsulated reply that returns on the Geneve device therefore has no
matching conntrack entry, so kube-proxy's `KUBE-FORWARD ... ctstate INVALID -j
DROP` discards it. The agent inserts `-i cozyplane0 -j ACCEPT` and `-o cozyplane0
-j ACCEPT` at the top of the `FORWARD` chain (via `iptables`, nft backend) so
overlay traffic is accepted before that drop.

### Packet walks

**Default network, cross-node (pod A on N1 → pod B on N2):** A sends → host veth
ingress → `from_pod` (srcnet 0, dstnet 0, allowed) → `remotes` hit (B's node) →
inner MAC rewritten, tunnel key {vni=1, N2}, redirect to Geneve → out the uplink
as Geneve/UDP 6081 → N2 receives, kernel decaps (frame addressed to N2's Geneve
MAC) → routes to B via B's `/32` → B. Reply retraces it.

**Node → remote pod:** host stack routes the packet out the uplink → uplink
egress `from_pod` (srcnet 0 because the uplink isn't in `ports`) → `remotes` hit
→ encapsulate. This is what makes Service return paths and apiserver→pod work.

**Isolation (VPC pod → default pod):** srcnet = the VPC's id, dstnet = 0 → differ
→ `TC_ACT_SHOT`. Same for default→VPC and VPC→other-VPC.

**VPC, cross-node:** identical to the default walk, but srcnet/dstnet are the
VPC's id and the tunnel VNI carries it; delivery still works by `/32` route
because VPC CIDRs are unique cluster-wide today.

### Addressing / byte order (for maintainers)

- `remotes` / `networks` LPM keys are `{prefixlen uint32, addr uint32}` with
  `addr` in **network byte order** (LPM matches MSB-first). In Go the field is
  filled with `binary.LittleEndian.Uint32(ip4)` so its native-endian marshaling
  lands the bytes in network order; the C side uses `ip->daddr` directly. See
  `datapath.lpmKey`.
- `remotes` values are the remote node IP in **host byte order**, because
  `bpf_skb_set_tunnel_key`'s `remote_ipv4` is host-order (the kernel does
  `cpu_to_be32`). Filled with `binary.BigEndian.Uint32(ip4)`.

## 4. Control flow

### Bootstrap order & invariant

**Invariant:** the default-network path depends only on the core API (Node
objects) and node-local config — never on the VPC API or Services. So bootstrap
is: kube-proxy/Cilium (hostNetwork, no CNI) → cozyplane-agent (brings up the flat
network, nodes go Ready) → CoreDNS / controller / workloads → VPC API usable.

### CNI ADD

The plugin (`cmd/cni`) is a thin host-side binary. It reads the pod's
namespace/name from `CNI_ARGS`, then:

- **default path** (`addDefault`): delegate IPAM to the upstream `host-local`
  plugin with the range injected from the node pod CIDR (published by the agent
  in `/run/cozyplane/agent.json`); create the veth; record net id `0`.
- **VPC path** (`addVPC`): read the pod's `sdn.cozystack.io/vpc` annotation (via
  the agent-written kubeconfig), `Get` the VPC (must be `Ready`), `claimIP`, then
  create the veth with the VPC IP and the VPC's net id.

`claimIP` is the IPAM design point: it lists the VPC's `Port`s, picks the lowest
free address, and **creates a cluster-scoped `Port` named `<vpc>.<ip-dashed>`**.
Because the name encodes the IP, etcd name-uniqueness makes the claim atomic —
concurrent allocators on different nodes that pick the same IP collide on
`AlreadyExists` and retry the next one. No server-side allocator is needed.

Both paths finish in `setupVeth` → `configurePodIface` (pod side: `/32` address,
link-local `169.254.1.1` default route) and `configureHostVeth` (host side:
`proxy_arp`, `/32` route to the pod, attach the classifier, write `ports`).

### CNI DEL

Clear `ports[ifindex]`; delete the pod's `Port`(s) (found by the pod-identifying
labels); release host-local IPAM (no-op for VPC pods); delete the veth (which
also removes the tc filter).

### Agent reconciliation

The agent runs three informers, all best-effort except Nodes:

- **Nodes** → `remotes[node.podCIDR] = node.InternalIP` (skip self). Default
  network reachability.
- **VPCs** → `networks[vpc.cidr] = vpc.vni` when the VNI is assigned.
- **Ports** → `remotes[port.ip/32] = port.nodeIP` for ports on other nodes. VPC
  pod reachability. (`Port.spec.nodeIP` is filled by the plugin from the agent
  state, so no node-name→IP lookup is needed.)

### Controller

`VPCReconciler` lists VPCs, assigns the lowest free VNI ≥ 100 to any VPC without
one, and sets `status.phase = Ready`. (VNI selection is list-then-pick; a
conflicting status update just requeues. Fine for the prototype.)

### Why the plugin needs a kubeconfig

The plugin runs in the host mount namespace and can't read the agent pod's
service-account files, so the agent materializes a self-contained kubeconfig
(embedding its SA token + CA) at `/run/cozyplane/kubeconfig`
(`datapath.WritePluginKubeconfig`). The plugin uses it for the VPC lookup and
Port claims. (Token rotation is a known TODO — it's written once at startup.)

## 5. Code structure (package by package)

```
bpf/overlay.c              the eBPF datapath (one tc program + four maps)
bpf/vmlinux.h              CO-RE kernel types (generated by bpftool; gitignored)

datapath/                  Go wrapper around the eBPF datapath
  bpf.go                   //go:generate bpf2go directive
  overlay_bpfel.{go,o}     generated bindings + compiled object (committed)
  datapath.go              Manager: Load/pin, Geneve device, remotes/networks
                           maps, uplink attach, LPM key/byte-order helpers
  attach.go                clsact + bpf filter attach (ingress/egress)
  ports.go                 plugin-side access to the pinned `ports` map
  firewall.go              the FORWARD ACCEPT rules (go-iptables)
  bpffs.go                 mount bpffs if absent (kind nodes)
  state.go                 AgentState published for the plugin (agent.json)
  kubeconfig.go            write the plugin kubeconfig from the SA token
  paths.go                 pin paths, device name, OverlayMAC, constants

cmd/cni/main.go            CNI plugin (ADD/DEL/CHECK), default + VPC paths
cmd/agent/main.go          node agent: datapath bring-up + Node/VPC/Port watches
cmd/sdn-controller/main.go controller-runtime manager
cmd/apiserver/main.go      aggregated API server entrypoint (scaffolded)

internal/controller/sdn/   VPCReconciler (VNI assignment)
internal/cmd/server/       aggregated apiserver options/wiring (start.go)
internal/setup/            apiserver group registration + openapi merge

api/sdn/                    internal types + register + install
api/sdn/v1alpha1/           versioned VPC/Port types (kubebuilder markers)
pkg/apiserver/              apiserver framework (scheme, codecs, JSON codec)
pkg/registry/               REST storage (vpc; aggregated-apiserver path)
pkg/generated/sdn/          generated clientset/informers/listers/openapi

config/crd/                 generated CRDs (how VPC/Port are served today)
deploy/                     agent DaemonSet, controller Deployment, RBAC
hack/                       codegen scripts; Makefile drives generate/build
```

### The two code lineages

- **Datapath / CNI** (`bpf/`, `datapath/`, `cmd/{cni,agent}`,
  `internal/controller`) is the working prototype.
- **Aggregated API server** (`pkg/apiserver`, `pkg/registry`, `internal/cmd`,
  `internal/setup`, `cmd/apiserver`) is scaffolding adapted from
  `aenix-org/cozyportal`, currently unused at runtime (CRDs serve the API). It
  builds and runs; wiring `Port` storage and deploying it is a later step.

## 6. Build & codegen

- **eBPF:** `go generate ./datapath` runs `bpf2go` (needs `clang`); `bpf/vmlinux.h`
  is produced by `bpftool`. The compiled `overlay_bpfel.o` is committed and
  embedded via `go:embed`, so plain `go build` needs no clang.
- **Kubernetes codegen:** `hack/update-codegen.sh` (deepcopy/conversion/defaults
  for the aggregated apiserver, plus clientset/informers/listers/openapi). The
  CRDs come from `controller-gen` over the kubebuilder markers.
- `make generate` runs the codegen; `make build` builds the binaries into `bin/`;
  the multi-stage `Dockerfile` builds all four binaries and bundles the upstream
  `host-local`/`loopback` plugins and `iptables`.

## 7. Known limitations / divergence from the design

The design (three planes, dual-address bridge, identity-based policy, etc.) is
mostly future work. As built:

- VPC CIDRs must be unique cluster-wide (no overlap support → no dual-address
  bridge yet → no kubelet probes for VPC pods, no fabric hiding).
- VPCs are closed L3 islands: no Services, egress, DNS, or policy for VPC pods.
- IPv4 only; single CIDR per VPC; no VM live-migration plumbing.
- The API is CRD-backed; the aggregated apiserver (and its server-side atomic
  IPAM/validation) is not yet deployed.
- The plugin's kubeconfig token isn't refreshed; VNI allocation and Port IP
  selection are list-then-pick (atomic at the claim, but not high-concurrency
  optimized).
