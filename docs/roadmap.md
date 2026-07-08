# cozyplane — roadmap

A living checklist of what is built and what is outstanding. It complements the
design docs (`design.md`, `control-plane.md`, `internals.md`, `live-migration.md`)
— those explain *how*; this tracks *what's done*.

**How to read it.** A ticked box is merged on `main` and exercised by the e2e
suite or validated on a real cluster; where a real-cluster validation happened
it's noted. An unticked box is planned work; where a GitHub issue tracks it, the
number is linked (e.g. [#7](../../issues/7)). Keep this file honest — tick a box
only when the thing actually works end to end, and add outstanding items here as
they're discovered rather than leaving them only in issues.

---

## 1. Foundation & control plane

- [x] Object model: `VPC`, `Port`, `VPCBinding`, `VPCPeering`, `ExternalPool`, `FloatingIP`
- [x] CRD-served API (prototype) with RBAC and validation
- [x] Aggregated apiserver (extension API) — built and served
- [x] Durable etcd (operator-managed, TLS/headless) with a built-in single-pod fallback
- [x] Default-deny VPC attachment: a `VPCBinding` authorizes use, the VPC's namespace is ownership
- Migration cutover adopts the Kube-OVN model (replaces the `/migrate`+`/bind` subresource idea — the only caller is our own controller, and Kube-OVN exposes no such API) — `live-migration.md`
  - [x] Stage 1 — cutover follows `VMI.status.nodeName` (phase-explicit, degrades to the pod label without KubeVirt; dev4-validated with a real migration)
  - [x] Stage 2 — source→target forward during the migration window (`migrate_fwd` map + `from_overlay` re-encap; 15 s grace; closes the cross-node cutover gap; OVN's `requested-chassis=src,target`)
  - [x] Stage 3 — guest-announcement cutover: `AF_PACKET` listener on the staged target veth flips `spec.node` on the guest's gratuitous ARP / unsolicited NA (OVN's `activation-strategy=rarp`); VMI-watch is the fallback
- [ ] Observability subresource(s) (e.g. `/ports`) — `control-plane.md`
- [x] Agent token rotation: the plugin kubeconfig references a host-visible tokenFile the agent refreshes as kubelet rotates the projected SA token (the embedded-once copy only worked via the API server's expired-token grace)
- [ ] Multi-tenancy model (the API is single-tenant today) — `design.md`

## 2. Datapath core

- [x] eBPF tc datapath: `from_pod` / `to_pod` / `from_overlay` / `from_uplink`
- [x] Geneve overlay delivery (collect-metadata, per-node device)
- [x] Per-pod dual-address bridge (fabric IP ↔ VPC IP), unique fabric IP per pod
- [x] Overlapping VPC CIDRs: net-scoped (VNI-keyed) delivery, no collision
- [x] eBPF bridge NAT for cozyplane north-south (VPC gateways, floating IPs) — no iptables, no fwmark, no policy routing
- [x] Cluster-egress masquerade: eBPF by default (`iptables`/`off` modes available)
- [x] North-south ICMP through the bridge: echo, and IPv4 ICMP *errors* with embedded-header NAT — port-unreachable/traceroute outward, frag-needed (PMTU) inward, fabric + floating (e2e: UDP traceroute end-to-end) — [#3](../../issues/3)
- [x] Per-VPC traffic counters in the datapath hooks (metering/billing foundation): a PERCPU `vpc_counters` map keyed by net, `count_dir` in `from_pod` (tx) and `to_pod` (rx east-west); the agent serves them as Prometheus text on `:9411/metrics` labeled by VPC (e2e-covered). North-south (gateway/floating) metering is a follow-up — [#2](../../issues/2)
- [x] Netfilter made conditional (#10): cluster-egress masquerade moved to eBPF (`--masquerade=bpf` default; ct-tracked SNAT at the uplink incl. ICMP echo + errors, e2e-proved with the kernel rule absent), and the FORWARD ACCEPT installs only where kube-proxy's `KUBE-FORWARD` exists — **cozyplane touches netfilter only if the cluster's kube-proxy does**. It cannot be removed entirely under an iptables kube-proxy: ClusterIP replies must traverse the client node's conntrack — [#10](../../issues/10)
- [x] **Cross-node node↔pod on a spoof-guarding underlay (OCI)** — the pod's *reply* to a hostNetwork client (pod→node) fell to the kernel and left the wire pod-sourced, which OCI anti-spoofing drops; every cross-node admission webhook hung, wedging cert-manager + ~60 HRs. Fix: a `node_remotes` map (node address → its Geneve endpoint) + `from_pod` encapsulates a default-network pod's traffic to a node over the overlay (gated to the pod-veth path so the uplink-egress hook doesn't re-encap Geneve outer frames); agent learns node addresses from InternalIPs + a `cozyplane.io/node-addresses` annotation (covers multi-NIC nodes where the host sources from a non-InternalIP NIC). Also `CFG_MASQ_IP`: the cluster-egress masquerade SNATs from the **default-route** address, not the InternalIP, so a masqueraded packet is valid for the NIC it egresses (fixed pod→internet on dev4). dev4-validated: full platform converges (90/90 HRs). Diagnosis in [bringup-field-notes.md](bringup-field-notes.md#5-admission-webhooks-fail-cross-node--podnode-reply-un-encapsulated-fixed)

## 3. VPC features — peering, egress, floating IPs

- [x] VPC peering: symmetric halves, native cross-VPC datapath, status controller
- [x] Per-VPC egress NAT gateway (gateway-attach, per-VPC gateway pod)
- [x] Floating IPs: eBPF bridge extension (no gateway pod), true public IP both directions
- [x] Floating-IP advertisement in eBPF (`from_uplink` ARP responder) + readiness gated on a live target Port
- [x] Gate `VPCPeering` creation on a `peer` virtual verb on the local VPC — strategy-enforced in aggregated mode (which also closed the `export` gap there: admission never sees aggregated resources), VAP twin for CRD mode — [#1](../../issues/1)
- [ ] Floating IPs: 1:1 public-address NAT anchored on the per-VPC gateway (internet-gateway equivalent) — [#5](../../issues/5)
- [ ] Site-to-site VPN: authorized-forwarder role + per-VPC route table — [#6](../../issues/6)
- [ ] Network policy / security groups within a VPC — **v1 + peered-group refs + north-south (world) done** ([security-groups.md](security-groups.md)): east-west group-to-group ingress, destination-side eBPF (`sg_members`/`sg_rules`, TCP SYN-gate, per-VPC id allocation, membership from stamped pod labels); **peered-VPC group refs** (`from: {group, vpc}`) authoritative via a Geneve identity TLV; **north-south `from: {cidr}`** (AWS-strict default-deny, kubelet exempt by NS_MARK path; all-addresses via SG_WORLD, specific ranges via an `sg_cidr` LPM); **east-west egress** (`egress: {to: {group, vpc}}`, symmetric default-deny, `sg_egress` mirror enforced beside ingress in to_pod + the TLV path); **north-south/external egress** (`egress: {to: {cidr}}`, source-side default-deny at `from_pod`'s gateway path via a loop-free `ns_egress_ok` + `sg_egress_cidr` LPM — plus the off-VPC-transit fix so the pod→gateway hop isn't re-gated as east-west, which had silently broken all grouped-pod TCP/UDP north-south egress) — all dev4-validated. Outstanding (v2): floating-pod egress gating, FQDN, label-change-follows membership, `from_pod` source-IP RPF, [#11](../../issues/11)
- [ ] Per-VPC metadata endpoint + guest autoconfiguration — **design draft: [vm-provisioning.md](vm-provisioning.md)** (awaiting review; also closes #8)
- [ ] Services in a VPC: per-VPC service VIPs + split-horizon DNS + net-scoped service NAT — **design: [services-in-vpc.md](services-in-vpc.md)** (reviewed; prioritized ahead of the KPR work)
  - [x] Increment 1 — split-horizon resolver: DNS steering in the datapath (`dns_steer`/`dns_return` + the `dns_ct` socket-LB coexistence twist), per-node responder, annotation-gated headless answers as VPC IPs, authoritative NXDOMAIN for the rest of the cluster domain, upstream forwarding (e2e-covered; validated on dev4 under Talos + Cilium KPR)
  - [x] Increment 2 — `ServiceVIP` + the net-scoped `svc_vips` data plane: controller-materialized VIP per attached Service (annotation + VPCBinding gate), live-union allocation walking opposite ends from the CNI, flow-pinned DNAT/rev-NAT with a hairpin loopback, resolver answers, peered clients included (e2e-covered)
  - [x] Increment 3 — v6 guest autoconfiguration: userspace RA (M=1) + per-veth DHCPv6 server in the agent handing out the exact pinned `/128` (Linux ignores a /128 PIO — vm-provisioning.md Q2 answered empirically), closes [#8](../../issues/8) for addresses; the v6-VPC-on-v4-cluster *DNS transport* still waits on cross-family (e2e: RA route received + the stock DHCPv6 client leased the pinned address)
- [ ] Name-based addressing / system-view DNS re-point — `control-plane.md` §5 (the split-horizon resolver in [services-in-vpc.md](services-in-vpc.md) is its first concrete piece)

## 4. IPv6 / dual-stack

- [x] Re-key every map/helper/hook to 128-bit addresses (v4 stored in RFC 6052 NAT64 form)
- [x] Parse IPv6 and deliver v6 VPC traffic over the overlay (intra-VPC, cross-node, isolation, peering)
- [x] IPv6 north-south fabric bridge (v6 masquerade, v6 NAT)
- [x] Dual-stack default network; v6 fabric IPs from the node v6 pod CIDR
- [x] Fabric-IP family decoupled from VPC family — a v6 VPC runs on a v4-only cluster (validated on dev4)
- [ ] IPv6 guest autoconfiguration (RA responder) — **design draft: [vm-provisioning.md](vm-provisioning.md)** — [#8](../../issues/8)
- [ ] North-south to a v6 VPC IP when the fabric IP is v4 (cross-family) — **design draft: [cross-family.md](cross-family.md)** — [#9](../../issues/9)
- [x] ICMPv6 errors through the v6 bridge: packet-too-big (v6 PMTU — vital, v6 never fragments in flight), dest-unreach, time-exceeded, with embedded-header NAT (e2e: UDP traceroute6 end-to-end)
- [x] v6 floating IPs: NDP responder (solicited+override NA from `from_uplink`), stateless v6 DNAT/SNAT halves incl. ICMPv6 error rewrites (e2e: external NDP-resolved HTTP/ping6/EIP-egress/traceroute6)
- [x] v6 gateway egress: dual-family gateway leg (`.1` in either family, `fe80::1` hop, NODAD), dual-family gateway netns firewall (with NDP accepts — ip6tables sees NDP, unlike ARP), and the v6 node masquerade (`masq_snat6`/`masq_reverse6`) that gives pod ULAs an off-cluster return path (e2e: v6 VPC → gateway → external container; isolation held)
- [ ] Cross-family VPC peering (v4 ↔ v6 via a NAT64/SIIT translator) — **design draft: [cross-family.md](cross-family.md)**

## 5. Live migration (KubeVirt)

- [x] Persistent Port pins `{VPC IP, MAC}` to a VM NIC identity (`vm.kubevirt.io/name`)
- [x] CNI binds virt-launcher pods to the persistent Port (reuse IP, pin a stable `02:` MAC)
- [x] DEL preserves the persistent Port; local datapath state cleared by `(net, IP)`
- [x] Cutover controller re-points `spec.node` to the active launcher (`kubevirt.io/nodeName`)
- [x] GC the persistent Port when the VM's pods are all gone
- [x] IP + MAC preservation validated end-to-end on dev4 (both directions)
- [x] IPv6 VM live migration demonstrated on a v4-only cluster (IP+MAC preserved, sub-second cutover)
- [x] Staged locals: same-node delivery flips at cutover on both ends (target's entry gated on `spec.node`, programmed from the veth alias at cutover; source's removed symmetrically) — validated on dev4 with a bandwidth-throttled migration: target locals observed ABSENT mid-window, flip at cutover, gap patterns identical across observers (no path-asymmetric loss), IP+MAC preserved through two consecutive migrations
- [x] Gratuitous ARP / unsolicited NA when a floating IP is programmed locally (fixes external L2 caches on a node move; e2e observes both frames on the wire)
- [ ] VM-migration e2e test (cozystack has none)

## 6. Services (kube-proxy replacement)

Sequenced **after** Services-in-a-VPC ([services-in-vpc.md](services-in-vpc.md), §3 above) — its net-scoped service NAT is the shared foundation.

- [ ] Import Cilium's LB control plane + socket LB (`pkg/loadbalancer`, `pkg/socketlb`, pre-compiled `bpf_sock.o`) as a separate `cozyplane-kpr` component — **design: [kube-proxy-replacement.md](kube-proxy-replacement.md)**; **increments 1–2 done (`kpr/`, `deploy/kpr-daemonset.yaml`, `test/kpr-e2e.sh`): lbcell reconciles Services→pinned LB maps + committed `bpf_sock.o` attached at the cgroup root. Proven on a `kubeProxyMode: none` kind cluster (no service proxy at all) — from a pod, TCP + UDP ClusterIP load-balance and cluster DNS resolves; the UDP path exercises the reverse `recvmsg` translation. Packaged as an image + DaemonSet**. Forcing function: retaining Cilium only for KPR/host-policy keeps a *second IPAM authority* on the podCIDR — it collided a system pod's IP with Cilium's `reserved:health` (cross-node-unreachable; [#12](../../issues/12)) and its unmanaged-pod-watcher churns cozyplane pods. Dropping Cilium (KPR here + host-firewall/NetworkPolicy follow-ups) removes that whole class.
- [~] Per-packet service fallback in cozyplane's hooks — needed before kube-proxy can be removed. **Half A (VM-guest / net-0 ClusterIP) DONE:** `svc_forward`/`svc_return` un-gated for net 0 (kept off the uplink-egress attachment; `svc_return`'s `!dstnet` bail dropped), fed by a self-contained cozyplane-kpr reconciler (client-go Services/EndpointSlices → the pinned `svc_vips` at net 0; ownership partitioned by net, `SyncServiceVIPs` no longer prunes net 0). Composes with socket-LB (a socket-LB'd pod already carries `dst=backend`, so the lookup misses; only VM-guest/raw-socket VIP packets hit). dev4-validated: a raw TCP SYN (socket-LB-bypassing, as a bridge VM guest) to the DNS ClusterIP gets a SYN-ACK back from the ClusterIP — both DNAT directions. **Half B (external NodePort / LoadBalancer) deferred → [#13](../../issues/13)** (needs `from_uplink` NodePort DNAT + client masquerade + `externalTrafficPolicy`).
- [ ] Retire kube-proxy on a cozyplane-only cluster — the endgame of [#10](../../issues/10): `firewall.go` then installs nothing

## 7. Deployment robustness

- [x] Cozystack chart integration (aggregated-apiserver mode, operator etcd, RBAC/CRDs)
- [x] Image digest-pinning in the chart
- [x] Agent recreates incompatible pinned eBPF maps on load and rebuilds pod state from veth alias records — a map-ABI upgrade is a rolling DaemonSet update, no node reboots (e2e-covered) — [#7](../../issues/7)
- [x] Gateway `.1` Port reuse after an unclean death: the controller GCs live Ports whose claimant pod is gone (VM persistent Ports exempt), so the replacement's ADD retry claims the freed `.1` (e2e-covered)
- [x] Digest-reproducible release images: attestations off, SOURCE_DATE_EPOCH + rewrite-timestamp, digest-pinned bases — verified identical across CI reruns, and the pin-commit-rebuild loop converges — [#4](../../issues/4)

## 8. CI & testing

- [x] CI: unit tests, lint, build-drift, image release, datapath e2e
- [x] eBPF bindings check (static bpftool, libbpf-dev)
- [x] Cross-compiled release image
- [x] e2e coverage for the IPv6 north-south paths (cross-node pinned — this caught the missing ip6tables FORWARD ACCEPT)
- [ ] e2e coverage for live migration (needs KubeVirt; kind can't host it)

---

## Open issues index

| # | Title | Area |
|---|-------|------|
| [#1](../../issues/1) | Gate `VPCPeering` creation on a `peer` virtual verb | Peering / RBAC |
| [#2](../../issues/2) | Per-VPC traffic counters in the datapath hooks | Datapath / metering |
| [#3](../../issues/3) | ICMP to a VPC pod's fabric IP is dropped (north-south ping / PMTU) | Datapath |
| [#4](../../issues/4) | Release digest non-determinism (closed: reproducible) | Packaging |
| [#5](../../issues/5) | Floating IPs: 1:1 public-address NAT on the per-VPC gateway | Floating IPs |
| [#6](../../issues/6) | Site-to-site VPN: authorized-forwarder + per-VPC route table | Connectivity |
| [#7](../../issues/7) | Agent: recreate incompatible pinned eBPF maps on load | Deployment |
| [#8](../../issues/8) | IPv6 guests don't autoconfigure (no RA / DHCPv6) | IPv6 |
| [#9](../../issues/9) | North-south to a v6 VPC IP when the fabric IP is v4 | IPv6 |
| [#10](../../issues/10) | Netfilter dependency (closed: conditional; eBPF masquerade default) | Datapath / deployment |
