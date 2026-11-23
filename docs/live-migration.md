# VM live migration and restarts — PortClaims (IP + MAC preservation)

**Hard requirement** (`design.md` §1, §5): a VM's NIC identity — its **VPC IP and
MAC** — must survive live migration between nodes, and a stop/start or a
recreated VirtualMachineInstance. The system-fabric `fabricIP` (`status.podIP`)
may change; the VM never sees it. This doc is the *as-built* design.

**cozyplane knows nothing about KubeVirt.** It offers one generic mechanism, the
`PortClaim`, and any workload controller (KubeVirt among them) maps its own
lifecycle onto it from outside cozyplane (§ "Wiring KubeVirt").

## What KubeVirt does, and what it needs from us

A live migration spins up a **second** virt-launcher pod (the *target*) on the
destination node while the *source* keeps running; the VM's memory is copied over
a source→target connection (default/fabric network, not the VPC IP); at cutover
KubeVirt flips execution to the target and tears the source down. Source and
target are **different pods with different names** for the **same VMI**. A
stop/start deletes the VMI and its pod and later creates new ones.

For the VM's L2/L3 identity to survive, every launcher pod's interface must carry
the **same IP and MAC**. KubeVirt only permits migration for the **pod (bridge)
binding** when the VM template is annotated
`kubevirt.io/allow-pod-bridge-network-live-migration: ""`. With bridge binding
KubeVirt moves the MAC cozyplane configured on the pod interface to the guest
(unless the VM spec sets `interfaces[].macAddress`, which then must equal the
MAC cozyplane pins) and hands the guest the pod IP via its **own DHCP**. A guest
whose cloud-init netplan matches the first MAC it saw loses its network the
moment that MAC changes, so a restart must keep it as surely as a migration.

KubeVirt passes nothing to the primary CNI: no MAC, no IP, no claim reference
(Multus forwards `mac`/`ips` only to secondary networks). The only channel is pod
metadata, which KubeVirt copies from `spec.template.metadata` of the
VirtualMachine to each VMI and its launcher pod.

This is OVN-Kubernetes' model (persistent IPs via a namespaced `IPAMClaim`, made
by the external kubevirt/ipam-extensions controller), with the MAC kept too.
cozyplane's `Port` is the logical port and `locals`/`remotes` are the chassis
binding.

## Identity: the PortClaim

The model is PersistentVolumeClaim / PersistentVolume:

| storage | cozyplane |
|---|---|
| PersistentVolume (cluster-scoped) | `Port` — the atomic `v<vni>.<ip>` address claim |
| PersistentVolumeClaim (namespaced, tenant-owned) | `PortClaim` (aggregated API, `sdn.cozystack.io`) |
| a pod volume naming `claimName` | pod annotation `sdn.cozystack.io/port-claim: <name>` |
| an ephemeral volume | no annotation: the Port is created at ADD and deleted at DEL |
| `WaitForFirstConsumer` binding | the Port is created at the first binding pod's ADD |
| the PV's `claimRef` | the Port's `claim-namespace` / `claim-name` / `claim-uid` labels |
| `Delete` reclaim policy | deleting the claim deletes the Port (after the node drains it) |

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: PortClaim
metadata: {name: vm1, namespace: tenant-a}
spec:
  vpcRef: {name: vpc-a}         # namespace defaults to the claim's
  mac: "02:00:00:00:00:42"      # optional; immutable
  ip: "10.10.0.42"              # optional; immutable
status:
  ip: 10.10.0.42                # pinned at first bind; never changes
  mac: "02:00:00:00:00:42"
  conditions: [{type: Bound, status: "True", reason: PodBound}]
```

The annotation's value is a bare name, resolved **in the pod's own namespace**: a
pod can never bind another namespace's claim. When the pod has no
`sdn.cozystack.io/vpc` annotation, the claim's VPC is used; when it has one, the
two must agree. The VPCBinding check applies as for any pod.

**First pod (CNI ADD), no Port yet.** The CNI creates the Port with the claim's
labels. The IP is `status.ip`, else `spec.ip`, else the next free address; a
pinned or requested address that another Port holds, that lies outside the
VPC's CIDR, or that is the network or `.1` address fails the ADD. The MAC is
`status.mac`, else `spec.mac`, else a random locally-administered unicast MAC;
one already used by another Port in the VPC fails the ADD. Because the claim's
status keeps the identity, a Port lost to a VPCBinding revocation or an operator
deletion comes back with the same IP and MAC.

**Later pod, Port exists.** The CNI **binds**: same `spec.ip` and `spec.mac`, the
pod interface MAC set to it, a fresh fabric IP. If the Port is detached
(`spec.node` empty) or the pod it records is gone or finished, the CNI takes it
over immediately (`spec.node` = this node). If another live pod still holds it,
this pod is a **migration target**: it stages (below) and waits for cutover.

The pod interface MAC is pinned because KubeVirt copies it to the guest; the
host-veth MAC (used only for same-node redirect delivery) stays per-pod and is
re-learned in `locals` on each bind — internal, never guest-visible.

## Cutover: the guest decides, the pods confirm

`locals` is per-node: every node programs its **local** pod's
`{net, vpcIP} → veth,MAC` at CNI ADD, so during the overlap both the source and
target nodes could deliver locally. `remotes` (the cross-node location) must point
at the **active** node, and the Port's `spec.node` is that location.

**Guest-announcement cutover (as built).** When a VM resumes on the target it
emits a gratuitous ARP (v4) or an unsolicited Neighbor Advertisement (v6). The
target agent, while a target Port is staged on it (`spec.node` elsewhere, but
the CNI ADD's veth already present), opens an `AF_PACKET` socket on that veth
and waits for a frame whose sender is the pinned `{VPC IP, MAC}`. `from_pod`
passes ARP/NDP straight to the kernel, so the announcement reaches the tap. On
a match the agent patches the Port's `spec.node`/`spec.nodeIP` to itself,
driving the fleet-wide cutover. This is the analog of OVN's
`activation-strategy=rarp`. The listener runs only while the target is staged.

**The PortClaim controller** keeps `spec.node` consistent with the pods that
bind the claim (found by the annotation, via a pod index):

- a live pod on the Port's current node keeps it there — this is what stops the
  controller reverting a guest-announcement cutover while the source pod still
  runs;
- otherwise, if exactly one live pod remains, the Port moves to it — the source
  exited after a migration the announcement missed, or a fresh start raced the
  detach;
- no live pod: the Port is **detached** (`spec.node`/`spec.nodeIP` cleared);
- several live pods and none on the current node: no change.

A failed migration leaves the source on the current node, so nothing moves. A
guest that never announces itself is unreachable from the moment it resumes on
the target until KubeVirt's source pod exits — seconds. cozyplane reads no
KubeVirt object for any of this.

**Source-forward window (stage 2, as built).** Cutover flips `spec.node` on the
Port; every agent re-points its `remotes[{net,vpcIP}]` entry, but not
simultaneously. The former source node bridges the gap: when a claimed Port's
`spec.node` moves off this node, the agent installs a `migrate_fwd` entry keyed
on `{net, vpcIP}` with the target's node IP, and the `from_overlay` hook — after
its `locals` lookup misses — re-encapsulates the packet to the target instead of
dropping it. The entry is removed after a 15 s grace period (`migrateFwdGrace`),
longer than fleet-wide informer propagation. The map is `LIBBPF_PIN_BY_NAME` so
it survives an agent restart mid-window.

**Staged locals (as built).** A migration-target ADD (the bound Port's
`spec.node` is another node) stages everything — interface, bridge, ports entry,
alias record — but removes its own `locals` entry, so a client co-located with
the target keeps delivering to the *active* location via `remotes`. At cutover
the agent watching Ports sees `spec.node` become its node and programs `locals`
from the veth's alias record (and drops the stale remote route); the source
node's agent symmetrically removes its `locals` entry. One residue: the agent's
local-state rebuild (an agent restart mid-migration) re-programs a staged
target's locals from the alias for the remainder of that window — documented in
`internals.md`.

## Lifecycle / GC

The Port lives exactly as long as its PortClaim; the claim's lifetime belongs to
whoever creates it — an ownerReference to any object (Kubernetes GC, so
cozyplane never reads the owner's kind), a Helm release, or a person. A Port
cannot carry the ownerReference itself: it is cluster-scoped, and Kubernetes GC
never resolves a namespaced owner for a cluster-scoped dependent.

- **Pods come and go** (stop/start, a deleted VMI, migration): CNI DEL never
  deletes a claimed Port; it only clears that pod's local datapath state. With
  no live pod left the controller detaches the Port: agents drop their routes to
  it, a FloatingIP on its address reports `TargetLive=False`, and the address
  stays reserved, so no other workload can inherit it.
- **The claim is deleted:** the registry put the `sdn.cozystack.io/port`
  finalizer on every claim at create. The controller deletes the Port, the sever
  finalizer makes the node's agent drain the datapath first (or the Port GC
  releases it when the Port is detached or its node is gone), and only then is
  the claim's finalizer released.
- **Orphans:** a Port whose claim no longer exists, or belongs to an earlier
  claim of the same name (UID mismatch), is deleted.
- **Status:** `status.ip`/`status.mac` are pinned at first bind and immutable
  afterwards; the `Bound` condition says whether a live pod holds the Port
  (`PodBound`), a live pod that does not name the claim holds it
  (`PreClaimPod`, below), it is reserved with no pod (`Detached`), or no pod has
  bound it yet (`NoPort`).
- **Quota:** `count/portclaims.sdn.cozystack.io` bounds how many addresses a
  namespace can hold while no pod uses them.

**Ports from before PortClaim.** Earlier releases keyed VM Ports on the KubeVirt
label `vm.kubevirt.io/name` and marked them `sdn.cozystack.io/vm-name`. Creating
a PortClaim named after the VM adopts such a Port (same name, pod namespace and
VPC; the claim's `spec.ip`, if set, must match): it gets the claim's labels,
loses `vm-name`, and takes `spec.mac` if the claim requests one.

A VM running at adoption time keeps its IP, MAC and binding: its launcher pod
predates the `sdn.cozystack.io/port-claim` annotation, but it is the pod the
Port records (same name and UID), so the controller counts it as the holder
until it ends, and reports `Bound=True` with reason `PreClaimPod`. Such a VM
must be **restarted before it is live-migrated**: KubeVirt builds the migration
target from the running VMI, which predates the annotation, so the target would
get an ordinary Port with a new IP. A restart creates a VMI that carries the
annotation (KubeVirt marks VMs whose template changed `RestartRequired`). An unadopted legacy Port is an
ordinary Port: deleted with its pod. A VM without a PortClaim gets an ordinary
Port per launcher pod, so its identity does not survive a restart or a migration.

## Wiring KubeVirt (outside cozyplane)

What a KubeVirt integration sets, per VirtualMachine NIC on a VPC:

1. a `PortClaim` in the VM's namespace, typically named after the VM, with
   `spec.vpcRef` and, if the VM spec sets `interfaces[].macAddress`, the same
   value in `spec.mac`;
2. `sdn.cozystack.io/port-claim: <claim name>` (and `sdn.cozystack.io/vpc`) in
   the VM's `spec.template.metadata.annotations`, which KubeVirt copies onto
   every launcher pod;
3. the claim's lifetime: a chart that renders the claim next to the
   VirtualMachine (in Cozystack, the `vm-instance` chart) ties it to the Helm
   release; an adapter controller would create the claim with an ownerReference
   to the VirtualMachine.

## Scope

- Bridge-binding VMs on the **default network path into a VPC** (primary network),
  matching KubeVirt's "only primary networks are live-migratable".
- IP + MAC preserved across migration, restart and VMI recreation; fabric IP (and
  thus `status.podIP`) changes per pod.

## Test

- Unit: `cmd/cni` (first bind, rebind after the holder is gone, take-over of a
  detached Port, staged target, recreation from status, requests, cross-VPC and
  cross-namespace refusal), `internal/controller/sdn` (detach, rebind, deletion
  order, cutover cases, adoption, orphans), `pkg/registry/sdn/portclaim`.
- e2e (`test/e2e.sh`, kind, no KubeVirt): pods sharing a PortClaim keep the IP
  and MAC across pod deletion and a node change; requested IP/MAC; deleting the
  claim frees the Port.
- Real cluster (KubeVirt): stop/start, VMI deletion and `virtctl migrate` keep
  the VPC IP and MAC; an in-VPC peer reaches the VM throughout the migration.
