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
`{vpcNamespace, vpc, vm.kubevirt.io/name}`; the Port keeps the ordinary
`v<vni>.<ip>` claim name (the name is the *address* claim, uniform across all
Ports and registry-enforced) and carries the VM identity as the
`sdn.cozystack.io/vm-name` label, so a lookup by VM identity is a label
selection and needs no IP.

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
target's **fabric IP** and for GC. Validated on the dev cluster with a real `VMIM`
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

**Guest-announcement cutover (stage 3, as built).** The tightest cutover signal
is the guest itself: when a VM resumes on the target it emits a gratuitous ARP
(v4) or an unsolicited Neighbor Advertisement (v6) — "I am here now" — earlier
and more precise than `VMI.status.nodeName`, which KubeVirt updates only after
the migration bookkeeping settles. The target agent, while a migration-target
Port is staged on it (`spec.node` elsewhere, but the CNI ADD's veth already
present), opens an `AF_PACKET` socket on that veth bound to the announcement's
ethertype and waits for a frame whose sender is the pinned `{VPC IP, MAC}`.
`from_pod` passes ARP/NDP straight to the kernel, so the announcement reaches
the tap. On a match the agent patches the Port's `spec.node`/`spec.nodeIP` to
itself, driving the fleet-wide cutover immediately rather than waiting out
informer + VMI-status propagation. The controller's VMI-watch (stage 1) is the
fallback for a missed announcement; the two writers converge on the same value
(the target), so a merge patch races cleanly. This is the analog of OVN's
`activation-strategy=rarp`. The listener's lifecycle is bounded by the staging
window: it starts when the target is staged and stops the moment `spec.node`
becomes this node (whether its own patch or the fallback drove it) or the Port
is removed.

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

Migration announcement listeners must sleep while their socket is idle and
observe cancellation within 100 ms. A nonblocking socket with `SO_RCVTIMEO`
does not provide that wait: readiness polling is required before receiving.
Every listener releases its child context on success, receive failure, and
cancellation. A finishing listener may remove only its own registration;
it must not remove a replacement started after cancellation.

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
  (stage 2 — done) and driven to its tightest instant by the guest's own
  gratuitous ARP / unsolicited NA (stage 3 — done), the way OVN's
  `requested-chassis=src,target` + `activation-strategy=rarp` does. The
  VMI-watch is the fallback when the announcement is missed.
- Dropped: the `/migrate` + `/bind` Port subresources — investigation of the
  callers showed the only caller is cozyplane's own controller, and Kube-OVN
  (the reference) exposes no such API (it sets OVN NB options directly). The
  authz value didn't justify the API surface; the effort went into the
  Kube-OVN cutover model instead.

## Test (dev cluster, real KubeVirt)

A bridge-bound cirros VM (annotation set) attached to a VPC: capture its VPC IP +
MAC, `virtctl migrate`, and assert **the VPC IP and MAC are identical** on the
target, the same guest keeps running, and an in-VPC peer reaches it throughout
(the IP never moved from the guest's view). Repeat on the default network (no VPC)
for the non-VPC case. Contrast with the earlier masquerade test, which could not
show preservation because the guest IP was NATed.
Guest-announcement listeners retain the Port UID and observed resourceVersion.
Cutover first reads the live Port and rejects replacement, termination, or a
changed binding. The patch includes UID/resourceVersion preconditions so a late
announcement cannot move a different claim that reused the same address/name.

### Source-forward lifetime

Each source-forward installation owns its cleanup lease. Expiry of an older move cannot delete a newer move, including a later move to the same target. Revocation and local cutover remove the forward immediately. Migration forwards are temporary propagation aids: agent load clears retained entries before attaching the new programs, so a crash cannot make them permanent.

Port event handlers reread the current informer object before applying routes or migration updates. A delayed deletion for a replaced Port cannot remove its replacement, and a source-forward installation requires the event to remain current.

Guest-announcement sockets use readiness polling while idle. The nonblocking receive path must not retry EAGAIN in a busy loop per staged VM; poll periodically checks cancellation and bounds idle CPU use.

Each listener also cancels its child context when the receive worker finishes,
including a successful announcement or socket failure. Removing the listener
from the running map alone does not release its registration on the long-lived
agent context. Retries must not retain finished child contexts until shutdown.

The packet socket installs a bounded classic BPF filter for the expected
announcement shape, pinned MAC and IP before receiving. Unrelated ARP/IPv6
traffic is rejected in the kernel instead of waking a userspace poll/receive
loop per frame. Both ARP announcement opcodes and IPv6 Neighbor Advertisements
remain accepted. A filter installation failure closes the listener and leaves
the controller-driven cutover fallback; it never falls back to an unfiltered
socket. The existing live Port/sandbox ownership checks still govern cutover.

### Staged endpoint ownership and revocation

VPC veth aliases record the owning Port UID and whether local delivery is staged. CNI writes that identity before publishing maps. A staged alias never restores a locals entry on agent restart; cutover clears staging on the chosen sandbox, while move-away stages the old endpoint durably. Binding revocation and Port termination quarantine every local veth owned by that Port, including targets without locals, and synchronize forwarding rights for staged legs too. A stale Port UID cannot sever a replacement address owner. Legacy ownership must be proven by its sandbox, or by a live FabricIP-to-launcher/VMI UID join before adoption; an ambiguous endpoint is not adopted. A quarantined veth cannot be reactivated by an ADD retry; re-grant requires a new sandbox.

Guest-driven cutover rechecks the live endpoint and its sandbox claim, joins
the claim to the protected launcher owner, and updates the Port's pod/sandbox
binding together with placement. It must not enable local delivery using the
old source container ID while waiting for the controller to observe the move.
Secondary NICs prove their sandbox through the primary FabricIP claim and keep
their own interface name; their Port generation is still distinct.

Deleting an old Port generation still drains its own veths when its name has
already been reused; it never removes the replacement's routes or endpoints.
After the complete Port cache is ready, grant reconciliation quarantines local
veths whose recorded Port UID no longer exists. This covers a staged target
that missed deletion while its agent was down. Missing or partial caches never
authorize orphan cleanup. Unidentified legacy endpoints require ownership proof.

### VPC generation during persistent attachment

Rebinding a persistent Port also verifies that its claim name encodes the
current VPC VNI and pinned address. A VPC recreated under the same name has
a different, durably reserved VNI; a Port of the previous network cannot be
rekeyed into it. CNI refuses that attachment before changing pod identity,
and preserves the old Port, IP and MAC for explicit reconciliation. Matching
VMI UID, namespace and VPC name alone does not establish network generation.

Persistent Port GC confirms an empty verified launcher cache view with the live
API reader before deleting the claim. The confirmation keeps the same namespace,
VM-name label and verified VMI owner UID filter: a foreign or replacement VM
launcher cannot retain the old claim. A verified live launcher defers GC and
requeues while the informer catches up; a failed live list preserves the Port
and returns an error. Deletion still uses UID/resourceVersion preconditions
and the sever finalizer. This confirmation never reallocates the VM IP or MAC.

### Persistent NIC creation transaction

Within a VNI, persistent Port creation checks the current namespace/VM/VPC/NIC identity in a paged etcd snapshot before writing. The transaction compares the modification revision of every Port key in that VNI with the snapshot revision, alongside the existing Port/ServiceVIP address guards. A concurrent creation or identity-affecting update invalidates the snapshot; eight retries and a 65,536-claim/128-per-page scan ceiling bound the work. The allocation client caps each gRPC response at 16 MiB, and each scan stops before decoding more than 64 MiB of stored data; exceeding either limit fails ADD without a partial allocation. This includes legacy claims without adding an index, lease or historical reservation. Empty-collection compares admit the first claim. A matching claim returns AlreadyExists with the actual holding Port name, so ADD can fetch it, verify the instance UID and pinned IP/MAC, and bind or stage it. NIC identity fields are immutable through normal and status updates; pinned VM MAC changes are refused. Unrelated status changes within a busy VNI may cause a bounded retry or an ADD failure for kubelet to retry; they cannot permit a second identity.

### Migration cleanup resource budget

Repeated moves of the same VM address must retain one current expiry record, rather than a goroutine and timer for every event within the grace window. The migration forwarding map has 1024 entries, so expiry state is admitted up to the actual map capacity even if another loader cleared kernel entries while old owners remain. Generation leases still fence old cleanup against replacement and same-target ABA. The agent can sweep current installation timestamps from its existing five-second reconciliation ticker after the fifteen-second propagation grace; expiry runs under the migration lock, preserves newer installations, and retries failed deletion on the next sweep. Revocation and local cutover stay immediate. This caps retained scheduling state and cleanup scan work independently of event rate. Behavior tests reproduce the former 2000-event/2000-goroutine burst. Current-owner sweeps, same-target renewal, concurrent replacement, deletion retry and 1200-address churn are verified against real kernel maps. Expiry normally occurs 15–20 seconds after installation, subject to scheduling; no real-time deadline is claimed.

### Guest cutover request lifetime

A guest-announcement worker must keep its per-Port registration while validating and patching the live API binding. Releasing that registration before API work finishes allows the two-second reconciliation loop to create another worker for the same Port when the API stalls. Cutover API work must use the listener child context and a five-second total deadline; endpoint or Port replacement cancels both packet reception and in-flight API requests. Remove the registration on worker completion only if it still refers to that worker, preserving replacement listeners. This bounds overlapping cutover work per current Port and releases request/goroutine state on cancellation. Real HTTP-client tests reproduce the former early slot release and ignored child cancellation. Tests verify cancellation, a five-second stalled-request deadline, failed receive, and 25 cancellation cycles without descriptor or goroutine growth.

### Migration sandbox claim lookup work

Persistent Port event lookup: a launcher or VMI event
must select only current Ports with the exact consumer namespace and VM name,
using a composite cache index registered before the watches. A common VM name
in another tenant must not cause its payloads to be copied on every event.
Retargeting and deletion remove old memberships; missing indexes cannot fall
back to a cluster scan. Include terminating and old-generation Ports in the
notification set so existing reconciliation/UID fences still decide cleanup.
The index stores current objects only and never changes pinned IP or MAC.

Guest-driven cutover and legacy veth adoption identify the target launcher through a FabricIP claim matching the local node, consumer namespace and full container ID. Those joins must retrieve that tuple from the current informer index instead of copying every cluster claim. Interface and protected Pod/VMI UID checks remain in launcherClaimPod, including the primary-claim join for secondary NICs. The tuple lookup does not assume globally unique container IDs across nodes or namespaces. Index updates/deletions must remove old memberships; missing indexes cannot authorize a broader scan or adoption. Both paths now retrieve only current tuple members. Behavior tests cover index retarget/deletion, full sandbox scoping and secondary NIC ownership through the primary claim; the 10,005-claim benchmark falls from 474,233 to 72 allocated bytes per lookup.

### Revocation API dependency

Revocation of an endpoint carrying the exact Port UID should quarantine it using the live alias witness even when the core Pod API is unavailable. An unused Pod read must not delay this proven-owner path. Legacy endpoints still require the existing sandbox or protected launcher/instance ownership proof before adoption. Real kernel tests verify quarantine despite Pod API errors, replacement-owner preservation, failed legacy proof with the finalizer retained, and 100 idempotent cleanup calls without descriptor growth.

### Mixed endpoint revocation

A legacy endpoint with unverified ownership must not prevent quarantine of other endpoints carrying the exact Port UID. Revocation should drain proven generations before attempting uncertain legacy adoption, while retaining the sever finalizer if any ownership or cleanup step fails. No uncertain endpoint may be adopted or quarantined just because it shares a VPC address. Kernel tests reproduce the former all-or-nothing rejection. Both inventory orders now drain UID-owned and independently proven legacy endpoints, retain the uncertain endpoint and finalizer, and preserve descriptor counts through repeated retries.

### Mixed endpoint forwarding updates

A failure to establish legacy ownership must not keep stale forwarding grants on endpoints already carrying the exact Port UID. Binding reconciliation must still apply current forwarding consent to verified endpoints without granting rights to uncertain aliases. Reconciliation now completes the UID-owned batch before any legacy lookup, then applies individually verified legacy grants in a second batch. Kernel TCP tests verify foreign-source refusal after withdrawal, scoped re-grant through current informer updates, and stable descriptors over 50 repeated passes.

Persistent-NIC client concurrency tests must model the server-side NIC uniqueness contract for both identical and differing candidate schedules. Even after simultaneous empty identity lookups, later occupancy scans can legally observe different snapshots and propose different address keys; the registry transaction remains the allocation authority.

### Legacy ownership request lifetime

The launcher ownership join is also called before guest listeners exist and by binding/revocation reconciliation. Those calls can receive the long-lived agent context, so the guest cutover deadline alone does not bound them. A stalled live Pod read must terminate within a five-second ownership-read budget while preserving the caller context and refusing unproven adoption. Real HTTP tests reproduce the former unbounded read, verify expiration with a healthy parent, preserve a shorter parent deadline and drain 25 cancellation cycles without descriptor or goroutine growth. This bounds each read, not every informer backlog or the sum of many independent reads.

### Guest candidate lookup work

The two-second guest listener reconciler needs Ports corresponding to local endpoint inventory. Ports use registry-enforced canonical allocation names derived from the full VNI and IP; candidate reads use the existing lister key lookup instead of copying the complete cluster Port cache. A recorded alias UID must match the current object, and legacy candidates still need the sandbox and protected launcher proof before cutover. No broader scan may substitute for an absent claim. Behavior tests cover overlapping IPv4/IPv6 VNIs, replacement UID ordering, duplicates, missing or mismatched claims, inactive inventory and actual primary/secondary veth ownership. The 10,002-Port benchmark decreases from 474,233 to 488 allocated bytes per lookup; this measures transient work, not a permanent leak.

### Sever acknowledgement request lifetime

The Port watch acknowledges completed local revocation through live SDN reads and a resource-version-checked update. These requests share a five-second operation deadline, including conflict retries, instead of inheriting the agent lifetime. Failed confirmation retains the sever barrier and preserves the healthy parent context. A lost write response cannot prove whether the API server committed the already-validated update. Real generated-client tests cover stalled initial/confirmation reads, a stalled PUT response, shorter parent deadlines and 25 cancellation cycles with stable descriptors and goroutines. This budget does not make client-go's notification ring globally bounded.

### Sever acknowledgement notification work

A per-request deadline alone still caused one API retry for every old notification of a terminating Port. The real watch retained 17.2 MB after 512 updates, stalled an unrelated route and delayed proven-owner quarantine. The callback now applies UID-proven quarantine immediately and coalesces API acknowledgement/legacy proof work into one cache-driven worker with one pending notification. Its index contains only current terminating claims; no event history is retained. Initial cache replay quarantines all proven owners before API work. Kernel/informer tests verify prompt quarantine and unrelated route delivery, small retained heap after the burst, one conditional acknowledgement PUT after API recovery, replacement-UID preservation and index membership cleanup through 1,000 claims. Deletion and migration source-forward witnesses remain in their existing handlers. This concerns acknowledgement stalls, not a guarantee that all informer buffers or all other callbacks are bounded.

### Revocation retry without a new event

The agent creates SDK informers with resync disabled. In this configuration client-go ignores a handler's requested 15-second resync period, so that option did not retry a transient API or datapath failure. Sever acknowledgement and forwarding reconciliation now own a 15-second retry tick after complete cache synchronization, keeping one pending pass and stopping the ticker on cancellation. Real HTTP/informer/kernel tests recover acknowledgement and remove stale forwarding permission without a new watched-object change. Scheduling tests cover cache readiness, blocked passes with 10,000 notifications and multiple ticks, cancellation, and 100 worker lifetimes without retained goroutines. Ordinary route-event processing and informer factory defaults remain unchanged. Binding reconciliation does read its current snapshots every 15 seconds; it does not rewrite unchanged grants or periodically replay all routes.

### Aggregate legacy ownership work

Binding reconciliation applies UID-proven endpoints before legacy ownership reads, but a sequence of stalled legacy reads previously delayed the next pass after a new grant withdrawal. The complete legacy phase now shares one five-second child deadline, preserves the healthy agent context and stops further reads after expiration. This bounds cumulative HTTP waiting, not all kernel scheduling or lock delays. Real informer/HTTP/kernel tests withdraw proven-owner forwarding in about 5.4 seconds despite three stalled legacy endpoints. Unproven endpoints remain unadopted and can be retried on later passes; the current sandbox/Pod/VMI checks and batching remain in place.

### Consent after a legacy ownership read

A protected launcher proof identifies an endpoint owner; it does not preserve the forwarding grant that existed when the HTTP read started. Before publishing the verified legacy batch, reconciliation reads current bindings once and resolves grants for the verified Ports only. Current Port UID, address, VPC and namespace are checked again; a missing, replaced or terminating Port quarantines only the proven old alias. Attachment withdrawal uses the same ownership-fenced cleanup and forwarding withdrawal uses the batch diff. Kernel tests release a valid Pod response only after the informer observes withdrawal. They also cover Port termination/replacement, a recreated physical veth with a different sandbox, scoped consent recovery and 50 repeated reconciliations with stable descriptors. These are current-cache checks, not a transaction across API watches and kernel publication.
