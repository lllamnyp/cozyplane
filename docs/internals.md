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
networks differ (unless a `VPCPeering` explicitly connects the two). The
default network uses the cluster pod CIDR (unique per node);
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
  map, `Port` → remote VPC pod /32s, `VPCPeering` → the peers map. It depends
  only on the **core** API for the default network, so it can bootstrap before
  the VPC API exists.
- **`cozyplane` CNI plugin** (`cmd/cni`, invoked by kubelet per pod). Sets up the
  pod's veth, allocates the IP, programs the per-veth network id, and attaches
  the classifier. Two paths: default (host-local IPAM) and VPC (claim a `Port`).
- **`sdn-controller`** (`cmd/sdn-controller`, controller-runtime Deployment).
  Assigns each `VPC` a unique network id (VNI) and marks it `Ready`; reaps
  `Port`s on `VPCBinding` deletion; surfaces `VPCPeering` matched/ready status.
- **API** (`api/sdn`, group `sdn.cozystack.io/v1alpha1`): `VPC`, `VPCBinding`,
  `VPCPeering`, `Port`. Served as **CRDs** (`config/crd/`) or by the aggregated
  API server (`pkg/apiserver`, `cmd/apiserver`) — a transparent swap because the
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
| `locals` | hash | pod IP → {veth ifindex, pod MAC} | plugin (per pod) |
| `peers` | hash | {src net id, dst net id} → 1 | agent (VPCPeerings) |
| `params` | array | `[0]`=Geneve ifindex, `[1]`=default VNI | agent |

All are pinned under `/sys/fs/bpf/cozyplane/` (`LIBBPF_PIN_BY_NAME`) so the
short-lived plugin and the long-running agent share the same map instances.

### The programs

cozyplane enforces at **two universal hooks** — see the placement-independence
invariant in [design.md](design.md) §4. Both run for every packet regardless of
where source and destination are scheduled. They are attached with **tcx** (BPF
links, pinned), not classic clsact filters: tcx links coexist with other tcx
users (notably Cilium, which reconciles tc on every device and strips foreign
*classic* filters but leaves tcx links alone), and pinning lets them survive the
short-lived CNI plugin.

**`cozyplane_from_pod`** — the egress hook. Attached at the **ingress of every
pod's host-side veth** (a pod's egress) and at the **egress of the node uplink**
(host-originated traffic). For each IPv4 packet:

1. exempt traffic to the link-local gateway `169.254.1.1` (replies to bridged
   node→pod traffic; the host stack/conntrack handles them);
2. source net = `ports[skb->ifindex]` (absent ⇒ `0`); dest net = `networks[dst]`
   (absent ⇒ `0`); **drop** if they differ *and* `peers[{src,dst}]` misses
   (egress isolation; a `VPCPeering` writes both directions into `peers`);
3. if the destination is a **local pod** (`locals[dst]` hit): rewrite the dst MAC
   to the pod's MAC and `bpf_redirect` to its veth — same-node delivery *through*
   the destination's ingress hook, no kernel-routing shortcut;
4. else if **remote** (`remotes[dst]` hit): rewrite the inner dst MAC to the
   shared overlay MAC, set the Geneve tunnel key (`tunnel_id` = source net id,
   remote = node IP), `bpf_redirect` to the Geneve device;
5. else `TC_ACT_OK` (off-cluster / node / fabric-bridge — the kernel handles it,
   including the conntrack bridge DNAT for VPC fabric IPs).

**`cozyplane_to_pod`** — the ingress hook. Attached at the **egress of every
pod's host-side veth**. Every delivery path leaves via the destination veth
(same-node redirect from step 3, cross-node decap-then-route, node→pod bridge),
so this is the placement-independent point for ingress policy. For each packet:

1. exempt source `169.254.1.1` (bridge/masqueraded node→pod traffic);
2. dest net = `ports[skb->ifindex]`; source net = `networks[src]`; **drop** if
   they differ and `peers[{src,dst}]` misses (ingress isolation); else
   `TC_ACT_OK`.

Cross-node decapsulation itself is still done by the kernel Geneve device (see
the two tricks below); the decapped packet is then routed out the destination
veth and so still passes `to_pod`. Moving decap into an eBPF program (needed for
overlapping CIDRs) is future work and must preserve this invariant.

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
→ `TC_ACT_SHOT`. Same for default→VPC and VPC→other-VPC — unless the two VPCs
are connected by a `VPCPeering`, in which case `peers[{src,dst}]` hits and the
packet is delivered exactly like same-VPC traffic (native IPs, no NAT; `locals`
redirect same-node, `remotes` encap cross-node).

**VPC, cross-node:** identical to the default walk, but srcnet/dstnet are the
VPC's id and the tunnel VNI carries it; delivery still works by `/32` route
because VPC CIDRs are unique cluster-wide today.

### The dual-address bridge (VPC pods)

A VPC pod has two addresses: its `status.podIP` is a unique **fabric** IP from
the node pod CIDR (allocated by host-local, reachable cluster-wide over the
default overlay), while its interface carries the **VPC** (tenant) IP. The fabric
IP is a node-side handle, never configured inside the pod.

The translation is kernel conntrack NAT (in `datapath/bridge.go`, a
`COZYPLANE-BRIDGE` nat chain):

- **node/Service → pod:** `PREROUTING`/`OUTPUT` DNAT `fabricIP → vpcIP`;
  `POSTROUTING` SNAT the source `→ 169.254.1.1` (the gateway) for DNATed
  connections. The pod sees traffic from its gateway and never learns the
  node/fabric address.
- **pod → reply:** the pod replies to `169.254.1.1`; `from_pod` exempts that
  destination (so isolation doesn't drop it), and conntrack reverses the DNAT/SNAT
  back to the original client.

This gives the design's directional trust for free: the system/default network
reaches a VPC pod via its fabric IP (north-south, allowed), but a VPC pod can't
initiate outward (its egress to any non-VPC, non-gateway destination is dropped
by the isolation rule). Because the fabric IP lives in the node pod CIDR, the
existing default overlay carries it cross-node, so Services/Endpoints and
remote-node access to VPC pods work unchanged.

"Stage 1" (built) requires VPC CIDRs unique cluster-wide, because delivery to the
pod after DNAT is by the VPC IP's `/32` route. Overlapping CIDRs ("stage 2") need
eBPF-keyed-by-fabric-IP delivery plus BPF conntrack, replacing the kernel-NAT
path.

### Addressing / byte order (for maintainers)

- `remotes` / `networks` LPM keys are `{prefixlen uint32, addr uint32}` with
  `addr` in **network byte order** (LPM matches MSB-first). In Go the field is
  filled with `binary.LittleEndian.Uint32(ip4)` so its native-endian marshaling
  lands the bytes in network order; the C side uses `ip->daddr` directly. See
  `datapath.lpmKey`.
- `remotes` values are the remote node IP in **host byte order**, because
  `bpf_skb_set_tunnel_key`'s `remote_ipv4` is host-order (the kernel does
  `cpu_to_be32`). Filled with `binary.BigEndian.Uint32(ip4)`.
- `locals` keys are the pod IP in **network byte order** too (the C side keys on
  `ip->daddr`); see `datapath.localKey`.

This byte-order contract is locked by `datapath/keys_test.go`, which asserts the
keys marshal to the address in network order regardless of host endianness — so
an accidental endianness flip fails the build, not just a packet at runtime.

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
- **VPC path** (`addVPC`): parse the pod's `sdn.cozystack.io/vpc` annotation —
  `[<owner-ns>/]<vpc>`, owner namespace defaulting to the pod's (`parseVPCRef`) —
  then **enforce default-deny** (`requireVPCBinding`): a `VPCBinding` in the
  pod's namespace must reference that VPC, or ADD fails. Only then `Get` the VPC
  (must be `Ready`), `claimIP`, and create the veth with the VPC IP and net id.

`claimIP` is the IPAM design point: it lists the VPC's `Port`s, picks the lowest
free address starting at network+2 (`.0` network and `.1` gateway reserved), and
**creates a cluster-scoped `Port` named `v<vni>.<ip-dashed>`**. The name is keyed
by the globally-unique VNI so it stays unique even though VPC names are only
unique per namespace; because the name encodes the IP, etcd name-uniqueness makes
the claim atomic — concurrent allocators on different nodes that pick the same IP
collide on `AlreadyExists` and retry the next one. No server-side allocator is
needed. (`cmd/cni/main_test.go` locks the address selection, naming, labels, the
retry, and the default-deny check.)

Both paths finish in `setupVeth` → `configurePodIface` (pod side: `/32` address,
link-local `169.254.1.1` default route) and `configureHostVeth` (host side:
`proxy_arp`, `/32` route to the pod, attach the classifier, write `ports`).

### CNI DEL

Clear `ports[ifindex]`; delete the pod's `Port`(s) (found by the pod-identifying
labels); release host-local IPAM (no-op for VPC pods); delete the veth (which
also removes the tc filter).

### Agent reconciliation

The agent runs four informers, all best-effort except Nodes (the sdn ones share
one informer factory):

- **Nodes** → `remotes[node.podCIDR] = node.InternalIP` (skip self). Default
  network reachability.
- **VPCs** → `networks[vpc.cidr] = vpc.vni` when the VNI is assigned.
- **Ports** → `remotes[port.ip/32] = port.nodeIP` for ports on other nodes. VPC
  pod reachability. (`Port.spec.nodeIP` is filled by the plugin from the agent
  state, so no node-name→IP lookup is needed.) On a **local** port's deletion
  (its `spec.node` is this node), if the owning pod is still alive — same name,
  same UID, not terminating — the agent treats it as a *revocation*, not ordinary
  teardown, and severs the live datapath (`datapath.SeverLocal`): it reassigns
  the pod's `ports` entry to `QuarantineNet` so `from_pod`/`to_pod` drop both
  directions, drops the `locals` entry, and tears down the bridge.
- **VPCPeerings** → the `peers` map. Every peering or VPC event triggers a full
  recompute (`desiredPeerPairs`): a VNI pair is programmed iff two halves
  mutually reference each other and both VPCs have VNIs. The desired set is
  diffed against the *pinned map itself* (not shadow state), so a restarted
  agent prunes pairs whose peerings vanished while it was down; one
  unconditional resync runs at cache sync for the same reason. Deliberately
  not keyed on the controller's status: severing must happen at watch latency
  even if status is stale, and the reciprocal grant's presence is the
  authorization.

### Controller

`VPCReconciler` lists VPCs cluster-wide, assigns the lowest free VNI ≥ 100 to any
VPC without one, and sets `status.phase = Ready`. (VNI selection is
list-then-pick; a conflicting status update just requeues. Fine for the
prototype.)

`VPCBindingReconciler` holds each `VPCBinding` with a reap finalizer. On deletion
it deletes the `Port`s for `(consumer-namespace, vpcRef)` — unless another live
binding in that namespace still authorizes the same VPC — then removes the
finalizer. Deleting the Ports is what drives the agents' sever above (and the
remote-route cleanup on other nodes). (`*_controller_test.go` lock the VNI
selection, the finalizer lifecycle, the reap, and the another-binding-keeps-alive
rule.)

`VPCPeeringReconciler` is status-only (the agents program the datapath from the
halves' specs): it marks a half `Ready` when a reciprocal half exists and both
VPCs are Ready, surfaces `PeerMatched`/`VPCReady`/`PeerVPCReady` conditions and
the peer's VNI, and reverts to `Pending` when either input goes away. It watches
VPCPeerings (each half re-enqueues its reciprocal) and VPCs (each VPC re-enqueues
the halves referencing it). No finalizer — deleting a half has nothing to reap.

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
  attach.go                tcx link attach/detach (ingress/egress), pinned
  ports.go                 plugin-side access to the pinned `ports` map
  locals.go                plugin-side access to the pinned `locals` map
  peers.go                 agent-side access to the pinned `peers` map
  firewall.go              the FORWARD ACCEPT rules (go-iptables)
  bpffs.go                 mount bpffs if absent (kind nodes)
  state.go                 AgentState published for the plugin (agent.json)
  kubeconfig.go            write the plugin kubeconfig from the SA token
  paths.go                 pin paths, device name, OverlayMAC, constants

cmd/cni/main.go            CNI plugin (ADD/DEL/CHECK), default + VPC paths
cmd/agent/main.go          node agent: datapath bring-up + Node/VPC/Port watches
cmd/sdn-controller/main.go controller-runtime manager
cmd/apiserver/main.go      aggregated API server entrypoint (scaffolded)

internal/controller/sdn/   VPCReconciler (VNI assignment), VPCBindingReconciler
                           (revocation reap), VPCPeeringReconciler (status)
internal/cmd/server/       aggregated apiserver options/wiring (start.go)
internal/setup/            apiserver group registration + openapi merge

api/sdn/                    internal types + register + install
api/sdn/v1alpha1/           versioned VPC/Port types (kubebuilder markers)
pkg/apiserver/              apiserver framework (scheme, codecs, JSON codec)
pkg/registry/               REST storage (vpc, vpcbinding, vpcpeering, port)
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

- VPC CIDRs must be unique cluster-wide (overlap needs bridge stage 2 — see
  "The dual-address bridge").
- VPC pods can't initiate egress (internet/DNS/default network/non-peered
  VPCs); only inbound north-south (via the fabric IP), same-VPC, and peered-VPC
  traffic work. No per-VPC gateway (NAT/DNS/controlled doors) yet, and no
  policy/security groups — a peering opens the two VPCs completely.
- IPv4 only; single CIDR per VPC; no VM live-migration plumbing.
- The API is served as CRDs by default; the aggregated apiserver
  (`apiserver.enabled=true`) serves the same group with server-side validation
  (e.g. VPCPeering spec immutability) in its strategies.
- The plugin's kubeconfig token isn't refreshed; VNI allocation and Port IP
  selection are list-then-pick (atomic at the claim, but not high-concurrency
  optimized).
