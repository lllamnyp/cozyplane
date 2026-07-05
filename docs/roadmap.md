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
- [ ] `/migrate` + `/bind` Port subresources (the controller reconciles `spec.node` directly for now) — `live-migration.md`
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
- [ ] Per-VPC traffic counters in the datapath hooks (metering/billing foundation) — [#2](../../issues/2)
- [x] Netfilter made conditional (#10): cluster-egress masquerade moved to eBPF (`--masquerade=bpf` default; ct-tracked SNAT at the uplink incl. ICMP echo + errors, e2e-proved with the kernel rule absent), and the FORWARD ACCEPT installs only where kube-proxy's `KUBE-FORWARD` exists — **cozyplane touches netfilter only if the cluster's kube-proxy does**. It cannot be removed entirely under an iptables kube-proxy: ClusterIP replies must traverse the client node's conntrack — [#10](../../issues/10)

## 3. VPC features — peering, egress, floating IPs

- [x] VPC peering: symmetric halves, native cross-VPC datapath, status controller
- [x] Per-VPC egress NAT gateway (gateway-attach, per-VPC gateway pod)
- [x] Floating IPs: eBPF bridge extension (no gateway pod), true public IP both directions
- [x] Floating-IP advertisement in eBPF (`from_uplink` ARP responder) + readiness gated on a live target Port
- [x] Gate `VPCPeering` creation on a `peer` virtual verb on the local VPC — strategy-enforced in aggregated mode (which also closed the `export` gap there: admission never sees aggregated resources), VAP twin for CRD mode — [#1](../../issues/1)
- [ ] Floating IPs: 1:1 public-address NAT anchored on the per-VPC gateway (internet-gateway equivalent) — [#5](../../issues/5)
- [ ] Site-to-site VPN: authorized-forwarder role + per-VPC route table — [#6](../../issues/6)
- [ ] Network policy / security groups within and across VPCs — `design.md`, `user-guide.md`
- [ ] Per-VPC metadata endpoint (a VPC is a closed island without it) — `user-guide.md`
- [ ] Name-based addressing / system-view DNS re-point — `control-plane.md` §5

## 4. IPv6 / dual-stack

- [x] Re-key every map/helper/hook to 128-bit addresses (v4 stored in RFC 6052 NAT64 form)
- [x] Parse IPv6 and deliver v6 VPC traffic over the overlay (intra-VPC, cross-node, isolation, peering)
- [x] IPv6 north-south fabric bridge (v6 masquerade, v6 NAT)
- [x] Dual-stack default network; v6 fabric IPs from the node v6 pod CIDR
- [x] Fabric-IP family decoupled from VPC family — a v6 VPC runs on a v4-only cluster (validated on dev4)
- [ ] IPv6 guest autoconfiguration: RA + DHCPv6 responder for VM (bridge-binding) NICs — [#8](../../issues/8)
- [ ] North-south to a v6 VPC IP when the fabric IP is v4 (cross-family) — [#9](../../issues/9)
- [x] ICMPv6 errors through the v6 bridge: packet-too-big (v6 PMTU — vital, v6 never fragments in flight), dest-unreach, time-exceeded, with embedded-header NAT (e2e: UDP traceroute6 end-to-end)
- [x] v6 floating IPs: NDP responder (solicited+override NA from `from_uplink`), stateless v6 DNAT/SNAT halves incl. ICMPv6 error rewrites (e2e: external NDP-resolved HTTP/ping6/EIP-egress/traceroute6)
- [x] v6 gateway egress: dual-family gateway leg (`.1` in either family, `fe80::1` hop, NODAD), dual-family gateway netns firewall (with NDP accepts — ip6tables sees NDP, unlike ARP), and the v6 node masquerade (`masq_snat6`/`masq_reverse6`) that gives pod ULAs an off-cluster return path (e2e: v6 VPC → gateway → external container; isolation held)
- [ ] Cross-family VPC peering (v4 ↔ v6 via a NAT64 translator; the `64:ff9b::` map layout accommodates it) — `internals.md`

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

## 6. Deployment robustness

- [x] Cozystack chart integration (aggregated-apiserver mode, operator etcd, RBAC/CRDs)
- [x] Image digest-pinning in the chart
- [x] Agent recreates incompatible pinned eBPF maps on load and rebuilds pod state from veth alias records — a map-ABI upgrade is a rolling DaemonSet update, no node reboots (e2e-covered) — [#7](../../issues/7)
- [x] Gateway `.1` Port reuse after an unclean death: the controller GCs live Ports whose claimant pod is gone (VM persistent Ports exempt), so the replacement's ADD retry claims the freed `.1` (e2e-covered)
- [x] Digest-reproducible release images: attestations off, SOURCE_DATE_EPOCH + rewrite-timestamp, digest-pinned bases — verified identical across CI reruns, and the pin-commit-rebuild loop converges — [#4](../../issues/4)

## 7. CI & testing

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
