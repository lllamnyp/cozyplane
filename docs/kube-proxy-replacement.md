# Kube-proxy replacement by importing Cilium's LB (design draft)

**Status: DRAFT — not implemented; sequenced second.** Review outcome
(2026-07-06): [services-in-vpc.md](services-in-vpc.md) lands first — the
net-scoped per-packet service NAT designed there is the foundation this
draft's increment 3 builds on, and it settles review Q2 below (the feed is
StateDB tables → cozyplane maps; Cilium's map ABI cannot express net-scoped
VPC-IP backends).

cozyplane currently requires kube-proxy
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
- **Proven interaction, from the DNS-steering work:** Cilium KPR *forces*
  socket LB on (`NewKPRConfig` overrides `bpf-lb-sock: false` — observed live
  on the dev cluster: `cil_sock4_connect` attached at the cgroup root despite the
  ConfigMap). Any cozyplane feature that matches on a ClusterIP at the tc
  hooks must expect the connect()-time translation instead — the split-horizon
  DNS steer handles it with a small LRU (`dns_ct`) recording the original wire
  destination. The same consideration will apply to our own imported socket
  LB.
- **Do not enable on clusters running full Cilium** (Cozystack's default
  today): the cgroup root and the `/sys/fs/bpf` pin namespace are already
  Cilium's. This feature targets cozyplane-only clusters; the chart gates it
  off by default.

## Increments

1. **`cozyplane-kpr` prototype on kind** — separate module, lbcell +
   socketlb + committed `bpf_sock.o`; e2e: ClusterIP from a pod and from the
   host netns resolves to backends with kube-proxy still present (verify
   bypass via iptables counters staying flat).

   **Started (`kpr/`, scaffold builds).** The separate module (`kpr/go.mod`,
   `github.com/cilium/cilium v1.19.5`) imports `pkg/loadbalancer/cell` +
   support cells, mirroring `pkg/loadbalancer/repl` — `main.go` assembles the
   LB control-plane hive and runs it. `kpr/bpf_sock.o` is committed
   (`kpr/build-bpf.sh` rebuilds it from the pinned tag; the seven core
   socket-LB programs — `cil_sock{4,6}_{connect,sendmsg,recvmsg}` +
   `cil_sock_release` — verified present), `go:embed`-ed, and attached at the
   cgroup root by `socketlb.go` (mirrors `pkg/socketlb` `attachCgroup`: raw
   cgroup link + pin; LB maps resolve by their bpffs pin path, no map-ABI
   coupling in our code). `go build`/`go vet` clean; binary links at ~117 MB
   (confirms the separate-module packaging call).

   **MVP proven on kind (2026-07-07).** Run inside a vanilla kind node
   (kube-proxy + default CNI present), `cozyplane-kpr` connects to the
   apiserver, `lbcell` reconciles Services/EndpointSlices into the pinned
   `cilium_lb4_services_v2`/`_backends_v3`, and all seven socket-LB programs
   attach at the cgroup root. A `connect()` to a ClusterIP — **from the host
   netns *and* from a pod** — is load-balanced across both backends while
   **kube-proxy's `KUBE-SERVICES` counter for the VIP stays flat** (`[1:60]`
   across nine curls): the connect-time rewrite lands before iptables sees the
   VIP, so socket-LB bypasses kube-proxy exactly as intended. Three fixes made
   it run: (1) `loadbalancer.Config` must **not** be re-declared — `lbcell.Cell`
   provides it, a second `cell.Config` panics on duplicate `bpf-lb-*` flags;
   (2) the datapath joins the control plane by bpffs pin path only if
   `socketlb.go` adopts each reconciler map's actual geometry
   (`MaxEntries`/`Flags`) onto the spec before loading — `bpf_sock.o`'s
   compile-time sizing (`cilium_lb4_source_range` 65536) must not fight the
   reconciler's config-driven size (1000); (3) env overrides (`KPR_CGROUP_ROOT`,
   `KPR_BPFFS_ROOT`) cover kind's `/sys/fs/cgroup` cgroup2 root — a flag-cell is
   the eventual home.

2. **kube-proxy-less kind e2e — DONE (`test/kpr-e2e.sh`).** Packaged as an
   image (`kpr/Dockerfile`) + DaemonSet (`deploy/kpr-daemonset.yaml`:
   hostNetwork, privileged, host bpffs + cgroup2 mounts, an init container that
   mounts bpffs on nodes that lack it — e.g. kind), and validated on a
   `kubeProxyMode: none` cluster where **there is no service proxy to fall back
   on**, so a working ClusterIP *is* socket-LB. From a pod: TCP and UDP
   ClusterIP both resolve and load-balance across backends, and cluster DNS
   resolves (`kubernetes.default → 10.96.0.1`) — the UDP path exercises
   `sendmsg` + the reverse `recvmsg` translation (the resolver accepts the
   reply, so the round trip is whole). Bootstrap wrinkle handled: with no
   kube-proxy the `kubernetes.default` ClusterIP is unserved until kpr runs, so
   kpr points at the real apiserver endpoint (`--k8s-api-server-urls`) rather
   than the in-cluster ClusterIP. RBAC is cluster-admin in the prototype
   manifest (a scoped role is a follow-up). In-cluster NodePort and the
   VM/external gaps move to increment 3.
3. **Per-packet fallback** — external NodePort + VM-guest ClusterIP in
   `from_uplink`/`from_pod`, fed from the StateDB tables.

   ### Design pass (2026-07-07)

   Two flows bypass socket-LB and must be caught per-packet, and cozyplane
   already has the datapath for one of them:

   - **VM-guest ClusterIP** enters `from_pod` on the guest's veth with
     `dst = ClusterIP` (a KubeVirt guest is raw ethernet — no host socket, so
     socket-LB never fired). cozyplane's **existing `svc_forward`** already does
     ClusterIP DNAT + ClientIP affinity + `svc_fwd`/`svc_rev` connection
     tracking + hairpin — it is the ServiceVIP datapath. **The one gap:**
     `svc_forward` is called `if (srcnet && !is_gw)`, i.e. **VPC pods only**;
     net-0 default-network traffic is deliberately left to the kernel (so
     kube-proxy's conntrack sees ClusterIP replies — overlay.c ~L3124). Once
     kube-proxy is gone that reason evaporates, so increment 3 calls
     `svc_forward` for **net 0** as well. It composes safely with socket-LB: a
     socket-LB'd pod already carries `dst = backend`, so the `svc_vips` lookup
     misses and the packet is untouched; only un-rewritten (VM-guest) ClusterIP
     packets hit. `dstnet` for a `10.96.x` ClusterIP is `net_of(0, vip) = 0`
     (the service CIDR is not a VPC CIDR), so the `svc_vips` key is `{net:0, …}`.

   - **External NodePort** arrives at the NIC → `from_uplink` with
     `dst = nodeIP:nodePort`. This is **new**: a NodePort DNAT (a small
     `nodeports` map keyed `{proto, nodePort}` → the same backend set) + the
     established `svc_fwd`/`svc_rev` tracking, **plus a masquerade** of the
     client to this node's IP so the reply returns here (external clients route
     asymmetrically) — the uplink masquerade ct tables (#10) already exist and
     are the natural home. Whether Cozystack needs external NodePort at all is
     open question 5 (LoadBalancer VIPs usually arrive via a separate LB layer),
     so this half ships second; VM-guest ClusterIP is the hard KubeVirt blocker
     and ships first.

   **Feeding `svc_vips` from cozyplane-kpr.** kpr reconciles the imported
   `Table[Frontend]`/`Table[Backend]` (or watches Services/EndpointSlices
   directly) into `svc_vips` at **net 0** (default-network ClusterIP) and into
   `nodeports`. Because kpr is a separate module it can't import the agent's
   `datapath` package; it opens the **pinned** `svc_vips`/`nodeports` maps and
   writes them with a locally-replicated key/value layout (the same commit-the-
   struct-shape contract as the socket-LB map adoption). **Ownership is
   partitioned by net:** the agent's `SyncServiceVIPs` owns `net != 0` (VPC
   ServiceVIPs) and must be made to **not prune net-0 keys**; kpr owns net 0.
   One map, one DNAT path, no double-write.

   **Testing.** VM-guest ClusterIP is provable on a cozyplane-CNI kind cluster
   (`from_pod` exists) without a real VM by exercising the un-socket-LB'd path:
   populate `svc_vips` at net 0 and drive a ClusterIP connection that isn't
   connect()-rewritten (socket-LB detached, or a raw send), asserting the
   `from_pod` DNAT reaches a backend. NodePort is driven from the host against
   `nodeIP:nodePort`. Both fold into `test/e2e.sh` (the cozyplane-CNI harness),
   not `kpr-e2e.sh` (which has no `from_pod`).
4. **Retire kube-proxy on the dev cluster** — at which point `firewall.go` detects no
   `KUBE-FORWARD` and installs nothing: #10 reaches its true end state.

## Open questions (review)

1. **Packaging** — separate `kpr/` Go module + `cozyplane-kpr` DaemonSet
   (proposed), or fold the attach into the agent and accept the dependency
   blast radius in one shared module?
2. **Increment-3 boundary** — RESOLVED (increment-3 design pass, above): feed
   from the StateDB tables into the **existing `svc_vips`** at net 0, reusing
   `svc_forward`/`svc_return` — `overlay.c` never reads Cilium's lb maps. The
   only new datapath is un-gating `svc_forward`/`svc_return` for net 0 and a
   `from_uplink` NodePort DNAT; ownership of `svc_vips` is partitioned by net
   (agent `!= 0`, kpr `== 0`).
3. **Feature dial for v1** — plain random backend selection, or turn on
   maglev/affinity/topology from day one? (All come along for free in lbcell;
   the question is test surface, not code.)
4. **Version policy** — pin `v1.19.x` and upgrade manually (proposed). Cilium
   makes zero API-stability promises for `pkg/`; the consumer surface is one
   wiring file, but upgrades must be treated as real work, not chores.
5. **NodePort scope** — does Cozystack actually need external NodePort
   clients on cozyplane clusters (LoadBalancer VIPs usually arrive via a
   separate LB layer), or can increment 3 shrink to VM-guest ClusterIP only?
