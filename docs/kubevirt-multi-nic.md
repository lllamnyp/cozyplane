# Multi-NIC KubeVirt VMs: the Multus adapter

`multi-attach.md` gives a **pod** several VPCs. This document is about why that
does not, on its own, give a **VM** several VPCs, and what closes the gap.

The short version: a guest only sees NICs KubeVirt put in its domain, KubeVirt
only declares NICs it has a `spec.networks` entry for, and its only vocabulary for
a *secondary* network is Multus. So cozyplane grows a delegate mode and emits a
`NetworkAttachmentDefinition` — as an **adapter**, not as a change of direction.

## 1. Why the pod path stops at the launcher

Multi-attach adds interfaces to the pod. For an ordinary workload that is the
whole story: the process in the container sees `eth1` and uses it.

A VM is not the workload — the VM is a *guest* inside the `virt-launcher` pod, and
`virt-launcher` builds a libvirt domain from the VMI spec. It wires exactly the
interfaces named in `spec.domain.devices.interfaces[]`, each paired by name to an
entry in `spec.template.spec.networks[]`. An interface that appears in the pod
without a matching `networks` entry is not in that list, so nothing bridges it
into the guest. It sits in the launcher's namespace, configured, carrying an
address, and completely unused.

That is not a bug to fix in cozyplane. It is KubeVirt's contract, and it is the
reason its network model is declarative in the VMI rather than inferred from
whatever the CNI happened to create.

`spec.networks` admits exactly two kinds: `pod: {}` (at most one — the primary)
and `multus: {networkName: ...}`. There is no third. **Multus is not one way to
give a VM a second NIC; it is the only way**, and a `NetworkAttachmentDefinition`
is what `networkName` resolves to.

## 2. This is an adapter, not a retreat from §9

`design.md` §9 is titled *Replacing Multus* and phase 6 of the roadmap says *kill
Multus*. Both stand, and both are about **pods**: a pod attaches to several VPCs
through one annotation read by one CNI, with no meta-CNI and no delegation chain.
Nothing here weakens that — the annotation path is unchanged and remains the
native form.

What changes is that cozyplane also answers when Multus calls it, for the one
case where the consumer's API leaves no alternative. §9's claim is that a pod does
not *need* a meta-CNI. It was never that KubeVirt could be made to speak a
vocabulary it does not have.

The NAD cozyplane emits is a shim of one line of config. It carries no addressing,
no policy and no identity — all of that stays in cozyplane's own objects. It says
only "this network is that VPC".

## 3. The contract

### The NAD

Generated from a **`VPCBinding`**, into the binding's namespace:

```yaml
apiVersion: k8s.cni.cncf.io/v1
kind: NetworkAttachmentDefinition
metadata:
  name: back              # the VPC's name
  namespace: tenant-a     # the binding's namespace
spec:
  config: '{"cniVersion":"1.0.0","type":"cozyplane","vpc":"tenant-a/back"}'
```

The binding, not the VPC, and that placement is the point. Multus resolves
`networkName` in the **pod's** namespace, and a `VPCBinding` is exactly the object
that says "pods in this namespace may attach to that VPC" — created by whoever
holds `export` on the VPC. So the NAD exists precisely where attachment is already
authorized, and generating it introduces **no new authorization surface**. A VPC
consumed across namespaces gets one NAD per consuming namespace, which is what a
tenant needs to reference it.

It is owned by the binding, so revoking the binding removes the NAD by ordinary
garbage collection.

**The NAD is not a grant.** Hand-writing one that names another tenant's VPC gets
you nothing: the CNI still resolves the `VPCBinding` before it attaches, exactly
as the annotation path does. The NAD tells cozyplane *which* VPC is being asked
for; the binding decides whether the answer is yes.

Generation is conditional on the cluster serving `k8s.cni.cncf.io` — a cluster
without Multus is a cluster without KubeVirt secondary networks, and there is
nothing to emit. This is the same `RESTMapping` gate the persistent-Port
controller already uses for KubeVirt's VMI.

### The VM

```yaml
spec:
  template:
    spec:
      domain:
        devices:
          interfaces:
            - name: primary
              bridge: {}
            - name: back
              bridge: {}
      networks:
        - name: primary
          pod: {}                            # cozyplane's annotation path
        - name: back
          multus: {networkName: back}        # the generated NAD
```

The **primary** network stays the pod network, so it keeps everything that hangs
off being primary: the fabric IP, `status.podIP`, kubelet probes, the default
route, and the persistent-Port live-migration machinery of `live-migration.md`.
Secondary NICs are additions to that, never a replacement for it.

## 4. Delegate mode

Multus invokes the delegate once per NAD, passing the NAD's `config` as the
plugin's stdin and the interface name (`net1`, `net2`, …) as `CNI_IFNAME`. The
plugin as written for the annotation path would do the wrong thing three times
over: it ignores `args.IfName` and derives names from the annotation, it rebuilds
the *entire* attachment list on every invocation, and its DEL enumerates every
index and tears all of them down. A DEL for `net1` would take `eth0` with it.

So delegate mode is explicit, and its discriminant is the NAD's own config:

**`vpc` present in the plugin config ⇒ this is a delegate invocation.**

An invocation in delegate mode:

- builds exactly **one** attachment, for `conf.vpc`, on `args.IfName`;
- is **never primary** — no fabric IP claim, no default route, only the on-link
  route to its own VPC CIDR. The primary is the pod network, and there is one;
- never reads `sdn.cozystack.io/vpc` and never iterates the list;
- returns a result naming `args.IfName`, which Multus checks;
- on DEL, removes only its own interface and releases only its own Port.

### Two host-veth name spaces, and why

The annotation path names host veths `cph<digit><id>`, the digit being the
attachment's index. Delegate mode uses a **letter**: `cph<letter><id>`, where the
letter is derived from the `netN` suffix. Both keep the `cph` prefix that
`datapath`'s rebuild scan and the masquerade RETURN rule match on, and both still
fit `IFNAMSIZ`.

The separation is not tidiness. The two paths delete independently — Multus calls
the delegate's DEL separately from the primary's — and the primary's DEL works by
enumerating the name space rather than by consulting state. Sharing one space
would let a primary DEL reconstruct, and destroy, a delegated interface's name.
Disjoint spaces make that impossible by construction rather than by care.

### VM NIC index

The persistent Port that pins a VM NIC's `{VPC IP, MAC}` is selected by
`{vpc, vm-name, nic-index}` (`multi-attach.md`). In delegate mode the index is the
`netN` suffix. It is stable across a migration because KubeVirt's `spec.networks`
ordering is, which is the property the selector actually needs.

## 5. Static addressing on a secondary NIC

The NAD is per-VPC and shared by every VM that references it, so an address
cannot live there. It stays on the pod, in the same
`sdn.cozystack.io/networks` annotation, in an entry whose `name` is the Multus
interface:

```yaml
sdn.cozystack.io/networks: |
  [{"vpc":"tenant-a/front"},
   {"name":"net1","vpc":"tenant-a/back","ip":"10.20.0.5","mac":"02:00:00:00:20:05"}]
```

**`net[0-9]+` is reserved for Multus delegation.** The primary invocation skips
such entries — they are not legs it builds — and the delegate looks up the one
matching its own `args.IfName` for `ip`/`mac`. One list, two readers, no second
annotation to keep in step.

An entry is optional: a NAD with no matching entry gets an ordinary IPAM walk, so
a VM that only wants "a NIC on that VPC" works with no annotation at all. If an
entry names a `vpc` other than the NAD's, that is a **hard error** — two sources
disagreeing about which network a NIC is on is not a precedence to resolve.

## 6. Known limits

- **Secondary NICs are not live-migratable.** `live-migration.md`'s scope —
  bridge binding on the primary network — is unchanged, and KubeVirt restricts
  this itself. A multi-NIC firewall VM keeps its identity across a *restart*
  (persistent Ports) but is not a live-migration candidate.
- **A NAD is namespace-local.** A VPC consumed from three namespaces has three
  NADs. That is Multus's resolution rule, not a choice.
- **The primary must be the pod network.** A VM whose `spec.networks` has no
  `pod: {}` entry has no fabric handle, so no `status.podIP` and no kubelet
  probes. cozyplane does not stop you; Kubernetes will notice.
