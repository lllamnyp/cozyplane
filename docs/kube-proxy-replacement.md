# Kube-proxy replacement by importing Cilium's LB (design draft)

**Status: DRAFT — not implemented.** cozyplane currently requires kube-proxy
(or a full Cilium install) for ClusterIP/NodePort Services. This draft proposes
owning Services **by importing Cilium's kube-proxy-replacement components as a
library**, not by writing an LB from scratch. The feasibility claims below were
verified empirically against **Cilium v1.19.5** (commands included); this is a
reuse plan, not a speculation.

## Why

- **Self-sufficiency.** Today a cozyplane-only cluster still needs kube-proxy.
  Owning Services makes cozyplane a complete CNI.
- **It finishes #10.** The only netfilter cozyplane touches exists to counter
  kube-proxy's conntrack drop, and the reason it *can't* be designed away is
  that ClusterIP replies must traverse the client node's conntrack to reverse
  the service DNAT. Socket-level LB removes the service DNAT from the wire
  entirely: packets leave the client already addressed to the backend. No
  kube-proxy ⇒ no `KUBE-FORWARD` chain ⇒ `firewall.go`'s conditional install
  does nothing ⇒ zero netfilter, by the existing auto-detection, no new code.
- **Don't rewrite what exists.** Cilium's socket LB is years-hardened (UDP
  reverse translation, `getpeername` coherence, terminating endpoints, topology
  hints, session affinity, maglev). Reimplementing it in `overlay.c` would be a
  multi-month project to reach parity Cilium already has.

## What Cilium v1.19 actually offers for import

`pkg/kpr` itself is only a config cell (two flags). The real machinery:

- **`pkg/loadbalancer`** — the rewritten, StateDB-based LB control plane:
  reflectors (Services/EndpointSlices → `Table[Frontend/Service/Backend]`),
  a `Writer` API, and a BPF reconciler that writes the `cilium_lb4/lb6_*`
  maps. Designed to run standalone — `pkg/loadbalancer/repl/main.go` is a
  self-contained ~15-cell hive app that connects to a kube apiserver and
  populates real BPF maps.
- **`pkg/socketlb`** — ~170 lines that load a pre-built `bpf_sock.o` and
  attach its 13 programs to the cgroup root
  (`connect4/6`, `sendmsg4/6`, `recvmsg4/6`, `getpeername4/6`,
  `post_bind4/6`, `pre_bind4/6`, `sock_release`).
- **`bpf/bpf_sock.c`** — the socket-LB datapath. Service resolution happens at
  syscall time (connect/sendmsg), so it needs **no integration with a
  packet-level datapath** — it composes with cozyplane's tc hooks by
  construction, the same way it composes with Cilium's own.

## Verified feasibility (v1.19.5, 2026-07-06)

1. **The Go module imports out-of-tree.** A scratch module importing
   `pkg/loadbalancer/cell` + `pkg/socketlb` (the repl's cell set) against
   `github.com/cilium/cilium v1.19.5` resolves and **builds** on Go 1.26.
   Cilium's two `replace` directives (controller-tools, gobgp) sit outside this
   subtree and don't bite. Weight: 394 modules in the graph, ~400-line go.sum,
   122 MB unstripped binary — which decides the packaging question (below).
2. **`bpf_sock.c` pre-compiles standalone** — no Cilium build system:

   ```
   clang -Ibpf -Ibpf/include -DENABLE_IPV4 -DENABLE_IPV6 \
     -DENABLE_SOCKET_LB_TCP -DENABLE_SOCKET_LB_UDP \
     -g -O2 --target=bpf -std=gnu99 -nostdinc -mcpu=v3 \
     -c bpf/bpf_sock.c -o bpf_sock.o        # 175 KB, all 7 core progs present
   ```

   Cilium compiles this at agent runtime, but only the *family* gates are
   compile-time `#ifdef`s; every per-node knob is a **load-time constant**
   (`.rodata.config`, set via `bpf.LoadCollection{Constants: ...}`). So
   cozyplane's commit-the-object model works: build the `.o` once in the bpf
   pipeline, `go:embed`, configure at load.
3. **The maps contract closes.** The object references exactly the maps the
   imported reconciler creates and pins (`cilium_lb{4,6}_services_v2`,
   `_backends_v3`, `_affinity`, `lb_affinity_match`, `_reverse_sk`,
   `cilium_skip_lb{4,6}`), plus `cilium_ipcache_v2` and `cilium_metrics`,
   which `LoadCollection` auto-creates (empty is acceptable for east-west;
   verify miss semantics in the prototype). Control plane and datapath join
   purely by bpffs pin path.

## Architecture

A **new, separate Go module and binary**: `kpr/` (own `go.mod`) building
`cozyplane-kpr`, deployed as its own DaemonSet.

- Separate module because the Cilium dependency tree (394 modules) must not
  contaminate cozyplane's `go.mod`, and the 122 MB binary must not fatten the
  agent image. The main module never imports Cilium.
- The binary is a hive wiring file (~60 lines, mirroring the repl) + the
  `socketlb` attach call + a stubbed `option.DaemonConfig` (the repl proves a
  stub suffices). No forking, no vendoring: pin `v1.19.x`, upgrade deliberately.
- The committed `bpf_sock.o` is built from the pinned Cilium tag by the same
  workflow that builds `overlay_bpfel.o`; a `NOTICE` records provenance
  (`bpf/` is dual GPL-2.0/BSD-2-Clause — reused under BSD-2-Clause; the
  object's kernel license string stays `Dual BSD/GPL`).

### What socket LB covers — and what it can't

Covered, cluster-wide, at the cgroup root: ClusterIP for every pod **and
host-network process** (TCP + UDP, including the reverse `recvmsg`/
`getpeername` translation), NodePort/LoadBalancer VIPs for **in-cluster**
clients, session affinity, terminating endpoints, topology hints.

Not covered — these bypass host socket syscalls:

1. **External NodePort/LoadBalancer clients** (packets arrive at the NIC).
2. **VM guests** (bridge binding: guest traffic is raw ethernet, no host
   socket traversal — a default-network VM loses ClusterIP access the day
   kube-proxy is removed).
3. Raw-socket users (kube-proxy has the same blind spot; ignorable).

So kube-proxy removal is gated on a **per-packet fallback** for (1) and (2) in
cozyplane's own hooks (increment 3): a service DNAT + rev-NAT on the ct
machinery the masquerade/bridge work already built. Proposal: feed it from the
imported StateDB tables (`Table[Frontend]`/`Table[Backend]` → a small
cozyplane-owned service map), **not** by teaching `overlay.c` to read
`cilium_lb4_services_v2` — the StateDB tables are the natural API boundary;
Cilium's map ABI is not.

### Interaction with the VPC model

- Socket LB attaches at the cgroup root, so it fires for VPC pods too: a VPC
  pod's `connect()` to a ClusterIP is rewritten to a backend **fabric** IP,
  which `from_pod` then drops — exactly as it drops the un-rewritten ClusterIP
  today. **Parity, no isolation change**: socket LB never lets a VPC pod reach
  anything `from_pod` wouldn't already admit. (Tenant-visible services inside a
  VPC remain a separate, future, identity-first feature.)
- Rollout is flag-day-free: socket LB composes with a running kube-proxy
  (connect-time rewrite happens first; backend-addressed packets simply never
  match `KUBE-SERVICES`). Enable it, watch, then remove kube-proxy when the
  per-packet fallback lands.
- **Do not enable on clusters running full Cilium** (Cozystack's default
  today): the cgroup root and the `/sys/fs/bpf` pin namespace are already
  Cilium's. This feature targets cozyplane-only clusters; the chart gates it
  off by default.

## Increments

1. **`cozyplane-kpr` prototype on kind** — separate module, lbcell +
   socketlb + committed `bpf_sock.o`; e2e: ClusterIP from a pod and from the
   host netns resolves to backends with kube-proxy still present (verify
   bypass via iptables counters staying flat).
2. **kube-proxy-less kind e2e** — kind supports `kubeProxyMode: none`; prove
   ClusterIP (pods + hostns) and in-cluster NodePort; document the VM/external
   gaps as expected failures.
3. **Per-packet fallback** — external NodePort + VM-guest ClusterIP in
   `from_uplink`/`from_pod`, fed from the StateDB tables. Needs its own design
   pass on the ct-table interaction (the masquerade tables are close but
   service NAT needs backend selection on the forward path).
4. **Retire kube-proxy on dev4** — at which point `firewall.go` detects no
   `KUBE-FORWARD` and installs nothing: #10 reaches its true end state.

## Open questions (review)

1. **Packaging** — separate `kpr/` Go module + `cozyplane-kpr` DaemonSet
   (proposed), or fold the attach into the agent and accept the dependency
   blast radius in one shared module?
2. **Increment-3 boundary** — feed cozyplane's per-packet fallback from the
   imported StateDB tables (proposed), or have `overlay.c` read Cilium's lb
   maps directly (couples our BPF to their map ABI, saves a reconciler)?
3. **Feature dial for v1** — plain random backend selection, or turn on
   maglev/affinity/topology from day one? (All come along for free in lbcell;
   the question is test surface, not code.)
4. **Version policy** — pin `v1.19.x` and upgrade manually (proposed). Cilium
   makes zero API-stability promises for `pkg/`; the consumer surface is one
   wiring file, but upgrades must be treated as real work, not chores.
5. **NodePort scope** — does Cozystack actually need external NodePort
   clients on cozyplane clusters (LoadBalancer VIPs usually arrive via a
   separate LB layer), or can increment 3 shrink to VM-guest ClusterIP only?
