# cozyplane — working notes for Claude

cozyplane is a multi-tenant, identity-first CNI for Cozystack: per-pod VPCs, an
eBPF tc datapath, a Geneve overlay, and pinned-identity Ports for VM live
migration. Before writing code, read the design docs — they are the source of
truth and they explain *why*, which is what keeps a change from quietly breaking
an invariant.

## Read first (in this order)

| Doc | Why you'd open it |
|-----|-------------------|
| [docs/design.md](docs/design.md) | The vision and the **design tenets** (§1). Start here. |
| [docs/internals.md](docs/internals.md) | As-built datapath, packet walks, the eBPF hooks, code layout. |
| [docs/control-plane.md](docs/control-plane.md) | Object model + the aggregated-apiserver control plane. |
| [docs/live-migration.md](docs/live-migration.md) | Persistent Ports; IP+MAC preservation across a node move. |
| [docs/roadmap.md](docs/roadmap.md) | What's built vs outstanding. Tick a box when it truly works; add gaps here. |

**Docs before code.** Update the relevant design doc (and `roadmap.md`) as part of
the change, not after. If a change contradicts a doc, the doc is wrong or the
change is — resolve that first, in writing.

## Hard invariants — don't violate these without changing the design first

1. **The datapath is pure eBPF. Never reach for iptables, fwmark, or policy
   routing to move, isolate, or NAT pod/VPC traffic.** Tenant delivery, isolation,
   and cozyplane's own north-south NAT (VPC gateways, floating IPs) all live in the
   four hooks (`from_pod`/`to_pod`/`from_overlay`/`from_uplink`) with the datapath's
   own connection table — no kernel conntrack on the fast path. If you need new
   forwarding behaviour, add/extend an eBPF hook.
   *The only* netfilter in the tree is `firewall.go`, and it is conditional
   (#10): the `FORWARD ... ACCEPT` pair installs per family **only when that
   family's `KUBE-FORWARD` chain exists** (it counters kube-proxy's `ctstate
   INVALID` drop, which is the only reason it exists — and it cannot be designed
   away under an iptables kube-proxy, because ClusterIP replies must traverse the
   client node's conntrack to reverse the service DNAT); the cluster-egress
   masquerade defaults to **`--masquerade=bpf`** (eBPF SNAT at the uplink hooks,
   ct-tracked in the bridge's tables, masquerade ports 16384–29999, disjoint
   from host-ephemeral and NodePort ranges), with `iptables` as the legacy mode.
   Net rule: **cozyplane touches netfilter only if the cluster's kube-proxy
   does** — don't add new netfilter rules; new NAT/forwarding behaviour goes in
   the eBPF hooks. (internals.md § "Trick 2", "eBPF NAT", "node masquerade")

2. **Addresses are 128-bit everywhere; a v4 address is stored in RFC 6052 NAT64
   form `64:ff9b::a.b.c.d`, never `::ffff:a.b.c.d`.** One map set, not parallel
   v4/v6 sets. The NAT64 form is a real routable v6 address a future cross-family
   translator can act on; `::ffff:` is non-routable and would preclude it. Use the
   `addr128`/`v4_to_128` helpers, never hand-roll the encoding. (internals.md §3)

3. **Placement independence.** Enforcement must never depend on whether two pods
   share a node. No same-node fast path that skips the policy hooks — locality
   affects transport only. (design.md §1 tenet 6)

4. **Identity, not addresses.** Membership, policy, and selection key on
   metadata/identity (labels, VPC, VNI). IP ranges are an implementation detail and
   **may overlap** between tenants — the datapath is net/VNI-scoped so overlapping
   CIDRs don't collide. Don't add logic that assumes globally-unique VPC IPs.
   (design.md §1 tenet 3)

5. **The dual-address bridge is the model.** A VPC pod has a unique **fabric IP**
   (`status.podIP`, the underlay/default-network identity, one per node) and a
   tenant **VPC IP** on its interface. East-west VPC traffic keys on the **VPC
   IP** over the overlay; the fabric IP is only the underlay handle (same-node
   bridge + node-originated ingress, e.g. kubelet probes). The fabric IP's family
   need not match the VPC's — a v6 VPC runs on a v4-only cluster. (internals.md §
   "dual-address bridge"; cmd/cni `nodeCIDRFor`)

6. **Pinned MAC + IP per Port, declared up front — non-negotiable for VM live
   migration.** A VM NIC's `{VPC IP, MAC}` must survive a node move. Persistent
   Ports pin identity to the VM, a launcher pod *binds* rather than claims, CNI DEL
   *preserves* a persistent Port, and cutover re-points `spec.node` only. Don't add
   a path that reallocates or renames a VM's Port on pod churn. (live-migration.md)

7. **The Kubernetes contract is plumbing, not a tenant surface.** Satisfy what the
   kernel/kubelet need (probes reach a pod on `status.podIP`) so K8s keeps working;
   never expose the host/management network inside tenant pods. (design.md §1)

## Generated artifacts — regenerate, never hand-edit

- Deepcopy / CRDs / clientset / OpenAPI: `make generate`.
- The compiled eBPF object (`datapath/overlay_bpfel.o`) is **committed and
  `go:embed`-ed** — the Go image build needs no clang. Change `bpf/overlay.c`, then
  regenerate the object via the bpf build; never edit the `.o` or the generated
  `overlay_bpfel.go`.

## Testing

- e2e: `test/e2e.sh` on kind (`test/kind.yaml`, dual-stack). Real-cluster behaviour
  (KubeVirt migration, IPv6) is validated on the dev cluster — see the session
  memory for cluster specifics.
- Don't write tests that grep source, chart templates, or rendered manifests as
  "drift guards" — assert real behaviour (unit logic or e2e), not text.

## Repo workflow

- This is a private repo; commit to `main` directly. `--signoff` on every commit
  (see the global notes); no `Co-Authored-By` (use `Assisted-By` for agent work).
- The aggregated apiserver is the direction; the CRD-served API is the prototype
  scaffold. New API surface targets the aggregated server. (control-plane.md)
