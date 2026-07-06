# VM live migration — persistent Ports (IP + MAC preservation)

**Hard requirement** (`design.md` §1, §5): a VM's NIC identity — its **VPC IP and
MAC** — must survive live migration between nodes. The system-fabric `fabricIP`
(`status.podIP`) may change; the VM never sees it. This doc is the *as-built*
plan for realizing `design.md` §5 / `control-plane.md` §5 as a first increment.

## What KubeVirt does, and what it needs from us

A live migration spins up a **second** virt-launcher pod (the *target*) on the
destination node while the *source* keeps running; the VM's memory is copied over
a source→target connection (default/fabric network, not the VPC IP); at cutover
KubeVirt flips execution to the target and tears the source down. Source and
target are **different pods with different names** for the **same VMI**.

For the VM's L2/L3 identity to survive, the target pod's interface must carry the
**same IP and MAC** as the source's. KubeVirt only permits this for the **pod
(bridge) binding** and only when the VM template is annotated
`kubevirt.io/allow-pod-bridge-network-live-migration: ""` — then the VMI reports
`LiveMigratable=True`. (Masquerade binding NATs the VM behind a stable internal
IP, so the pod IP is irrelevant and *not* preserved — it is not the target of
this feature.) With bridge binding KubeVirt takes the IP+MAC cozyplane configured
on the pod interface and hands them to the guest via its **own DHCP**; so all
cozyplane must do is put the **same IP+MAC on the target pod's interface** and
make the overlay deliver to wherever the VM currently runs.

This is exactly OVN-Kubernetes' model (ovn-kubernetes.io/features/live-migration):
a persistent logical-switch-port pins IP+MAC; only the *chassis* (node) binding
moves; the guest keeps its DHCP lease. cozyplane's `Port` is the logical port and
`locals`/`remotes` are the chassis binding — so the pieces already exist.

## Identity: the persistent Port

A **persistent Port** pins `{VPC, VPC IP, MAC}` to a **VM NIC identity**, not to a
pod. A virt-launcher pod's CNI ADD **binds** to it instead of claiming a fresh IP.

A pod is a VM NIC pod when it carries the label **`vm.kubevirt.io/name`** (the VM
name); `kubevirt.io/created-by` is the VMI UID (stable across migration) and
`kubevirt.io/nodeName` is the **active** location (the node the VM currently runs
on — set on the target only *after* cutover). The stable key is
`{vpcNamespace, vpc, vm.kubevirt.io/name}`; the Port is named
`v<vni>-vm-<vmname>` (distinct from the ephemeral `v<vni>.<ip>` shape), so a
lookup by VM identity needs no IP.

- **First pod** (VM start): no persistent Port exists → **create** it, allocating
  the VPC IP (as today) and **generating a stable locally-administered MAC**
  (`02:…`), stored in `spec.mac`. Report the fabric IP as `status.podIP` as usual.
- **Later pod** (restart or migration target): the persistent Port exists →
  **bind**: reuse `spec.ip` and `spec.mac`, set the **pod interface MAC** to it,
  configure the same VPC IP. A fresh fabric IP is still allocated (per pod).

The pod interface MAC is pinned because KubeVirt copies it to the guest; the
host-veth MAC (used only for same-node redirect delivery) stays per-pod and is
re-learned in `locals` on each bind — internal, never guest-visible.

## Cutover: the location follows `kubevirt.io/nodeName`

`locals` is per-node: every node programs its **local** virt-launcher pod's
`{net, vpcIP} → veth,MAC` at CNI ADD, so during the overlap both the source and
target nodes can deliver locally. `remotes` (the cross-node location) must point
at the **active** node — the one where the VM actually runs.

The active node is where the VM currently runs. A **persistent-Port
controller** keeps the Port's `spec.node`/`spec.nodeIP` = that node; the agent
already turns `spec.node` into the `remotes` entry, so the cutover is: the VM
becomes live on the target → controller flips `spec.node` → every agent's
`remotes[{net,vpcIP}]` re-points to the target. The VPC IP/MAC never change, so
the VM and its in-VPC peers see only a sub-second reroute.

**The cutover signal (the Kube-OVN model, as built).** The controller keys on
the **VirtualMachineInstance's `status.nodeName`** — the phase-explicit signal
KubeVirt flips to the target at cutover — mirroring how Kube-OVN reads
`VMI.status.MigrationState` rather than guessing from pod labels. It reads the
VMI as unstructured (no `kubevirt.io/api` dependency) and watches it only when
the CRD is served; without KubeVirt it degrades to the launcher pod's
`kubevirt.io/nodeName` label. The launcher-pod list is still consulted for the
target's **fabric IP** and for GC. Validated on dev4 with a real `VMIM`
migration (IP+MAC preserved, cross-VPC 0% loss). Kube-OVN goes one step
further — it delegates the *instant* of cutover to the guest's RARP via OVN's
`activation-strategy=rarp`, so the control-plane only opens a dual-bound
(`requested-chassis=src,target`) window and pins the winner. The cozyplane
analogs are the source→target forward (stage 2, below) and a GARP-triggered
datapath flip (stage 3, planned).

**Source-forward window (stage 2, as built).** Cutover flips `spec.node` on the
Port; every agent re-points its `remotes[{net,vpcIP}]` entry, but not
simultaneously — an agent that is slow to observe the update keeps encapsulating
to the *old* node for a few informer beats. To keep that in-flight east-west
traffic from being black-holed, the former source node bridges the gap: when a
VM Port's `spec.node` moves off this node, the agent installs a `migrate_fwd`
entry keyed on `{net, vpcIP}` with the target's node IP, and the `from_overlay`
hook — after its `locals` lookup misses (local delivery was already torn down at
cutover) — re-encapsulates the packet to the target instead of dropping it. The
entry is removed after a 15 s grace period (`migrateFwdGrace`), comfortably
longer than fleet-wide informer propagation. This is one-directional and
transient: it only catches traffic that still arrives at the old node, and only
until every remote agent has re-pointed. The map is `LIBBPF_PIN_BY_NAME` so it
survives an agent restart mid-window.

**Staged locals (as built):** the target's `locals` entry is gated on the
cutover, closing the overlap window v1 had. A migration-target ADD (the bound
persistent Port's `spec.node` is another node) stages everything — interface,
bridge, ports entry, alias record — but removes its own `locals` entry, so a
client co-located with the target keeps delivering to the *active* location
via `remotes`. At cutover the agent watching Ports sees `spec.node` become its
node and programs `locals` from the veth's alias record (and drops the stale
remote route); the source node's agent symmetrically removes its `locals`
entry the moment `spec.node` leaves it — so same-node delivery flips exactly
when cross-node delivery does, on both ends. One residue: the agent's
local-state rebuild (an agent restart mid-migration) re-programs a staged
target's locals from the alias for the remainder of that window — rare enough
to accept and documented in `internals.md`.

## Lifecycle / GC

Ports are cluster-scoped, so a namespaced VMI ownerRef can't GC them. The
persistent-Port controller owns the lifecycle: it **keeps** the Port while any
virt-launcher pod (or the VMI) for its identity exists, and **deletes** it once
they are all gone (VM stopped/deleted). A single virt-launcher pod's CNI DEL must
**not** delete a persistent Port (that is what lets IP+MAC survive pod churn) — it
only clears that pod's local datapath state; contrast the ephemeral path, where
DEL deletes the Port. The sever finalizer still guarantees the owning node drains
before the Port is really removed.

## Scope of this increment

- Bridge-binding VMs on the **default network path into a VPC** (primary network),
  matching KubeVirt's "only primary networks are live-migratable".
- IP + MAC preserved; fabric IP (and thus `status.podIP`) changes per pod, and the
  system-view DNS re-point (`control-plane.md` §5) is **later** — name-based
  addressing isn't wired yet, so nothing depends on a stable fabric A record.
- Cutover follows the VMI's `status.nodeName` (the Kube-OVN model, stage 1 —
  done), backed by the source→target forward during the propagation window
  (stage 2 — done). Planned: a GARP-triggered datapath flip (stage 3) to drive
  the residual cutover gap to zero, the way OVN's `requested-chassis=src,target`
  + `activation-strategy=rarp` does.
- Dropped: the `/migrate` + `/bind` Port subresources — investigation of the
  callers showed the only caller is cozyplane's own controller, and Kube-OVN
  (the reference) exposes no such API (it sets OVN NB options directly). The
  authz value didn't justify the API surface; the effort went into the
  Kube-OVN cutover model instead.

## Test (dev4, real KubeVirt)

A bridge-bound cirros VM (annotation set) attached to a VPC: capture its VPC IP +
MAC, `virtctl migrate`, and assert **the VPC IP and MAC are identical** on the
target, the same guest keeps running, and an in-VPC peer reaches it throughout
(the IP never moved from the guest's view). Repeat on the default network (no VPC)
for the non-VPC case. Contrast with the earlier masquerade test, which could not
show preservation because the guest IP was NATed.
