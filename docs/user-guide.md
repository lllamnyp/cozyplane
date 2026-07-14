# cozyplane user guide

How to deploy cozyplane, create a VPC, attach pods to it, and verify
connectivity and isolation. This covers the prototype as it exists today; see
[internals.md](internals.md) for how it works and [design.md](design.md) for
where it's headed.

## What you get

- **Default network.** Every pod that doesn't opt into a VPC joins the
  default/system network: a normal flat pod network (its IP comes from the
  node's pod CIDR) carried over an eBPF Geneve overlay. Pods reach each other
  across nodes, the node reaches pods (so kubelet probes work), and Services
  keep working through your existing kube-proxy / Cilium-KPR.
- **VPCs.** A `VPC` is **namespaced** — its namespace is its owner. A pod
  attaches to a VPC by annotation, but attachment is **default-deny**: a
  `VPCBinding` in the pod's namespace must grant use of that VPC first (even when
  the pod and VPC share a namespace). Once attached, the pod's interface gets a
  (tenant) IP from the VPC's CIDR, while its `status.podIP` is a separate
  **fabric** IP from the node pod CIDR — so the pod is first-class to Kubernetes
  (kubelet probes work, Services/Endpoints resolve, controllers can reach it on
  `status.podIP`) without ever seeing the node/management network. Pods in the
  same VPC reach each other across nodes; the system/default network can reach a
  VPC pod via its fabric IP (north-south). A VPC pod itself cannot initiate to
  anything outside its VPC — the default network, the node, other VPCs, the
  internet are all dropped — unless the owner opens a path: a `VPCPeering` to
  another VPC, or a `VPCGateway` for internet + DNS via a per-VPC
  gateway.
- **Tenancy.** The VPC owner controls who may use it: a `VPCBinding` is created
  by someone holding both `create vpcbindings` in the consumer namespace and the
  `export` verb on the VPC. Deleting the binding **revokes** access and severs
  the attached pods. See [control-plane.md §6](control-plane.md) for the model.

## Requirements

- A Linux kernel with BTF (`/sys/kernel/btf/vmlinux`) — 5.10+; tested on 6.8.
- A cluster pod CIDR, passed to the agent as `--cluster-cidr`. Fabric addresses are
  drawn from that **flat, cluster-wide** pool — a node's `spec.podCIDR` is no longer
  carved up (it survives only as a fallback when `--cluster-cidr` is unset).
- A Service implementation: stock **kube-proxy**, or **`cozyplane-kpr`**
  (`deploy/kpr-daemonset.yaml`) — cozyplane can now be the cluster's only service
  proxy. See [kube-proxy-replacement.md](kube-proxy-replacement.md).
- For building the image: Docker. For regenerating code: `clang`, `bpftool`.

## Prerequisite: a cluster with no other CNI

cozyplane must be the primary CNI. On a fresh cluster, install it before any
other CNI. If replacing kube-ovn, remove kube-ovn first (and keep Cilium for
Services/policy).

### Try it on kind

```bash
kind create cluster --name cozyplane --config test/kind.yaml   # default CNI disabled
```

Nodes will be `NotReady` until cozyplane is installed.

## Install

Build and load the image, then apply the manifests in order.

**The tenant API is not CRDs.** cozyplane serves two API groups, and this trips
people up: `local.sdn.cozystack.io` (just `FabricIP`) is a CRD, but the tenant kinds
— `VPC`, `VPCBinding`, `VPCGateway`, `Port`, `FloatingIP`, `ExternalPool`,
`SecurityGroup`, … — live in `sdn.cozystack.io`, which is served **only by the
aggregated apiserver**. Skip that component and every example below fails with
`no matches for kind "VPC"`. (Why the groups are disjoint: [api-groups.md](api-groups.md).)

```bash
docker build -t ghcr.io/lllamnyp/cozyplane:dev .
kind load docker-image ghcr.io/lllamnyp/cozyplane:dev --name cozyplane   # kind only

# the local CRD (FabricIP) — fabric IPAM. NOT the tenant API.
kubectl apply -f config/crd/

# the node agent (DaemonSet) — brings up the default network; nodes go Ready
kubectl apply -f deploy/agent.yaml

# the controller (assigns each VPC a network id)
kubectl apply -f deploy/controller.yaml

# the aggregated apiserver — REQUIRED, it serves sdn.cozystack.io
kubectl apply -f deploy/apiserver.yaml
```

Or as Helm charts — note these are **two** charts, and you need both:

```bash
helm install cozyplane ./chart/cozyplane \
  --namespace cozy-cozyplane --create-namespace
# override e.g. the CNI conf precedence and MTU:
#   --set cniConfName=00-cozyplane.conflist --set mtu=1450

helm install cozyplane-apiserver ./chart/cozyplane-apiserver \
  --namespace cozy-cozyplane          # serves sdn.cozystack.io; needs cert-manager
```

See [chart/cozyplane/README.md](../chart/cozyplane/README.md) for the values.
The raw `deploy/*.yaml` above are the same objects for a quick kind loop; the
chart is the canonical packaging.

Verify the base is healthy:

```bash
kubectl get nodes                                   # all Ready
kubectl -n kube-system get pods -l app=cozyplane-agent   # one per node, Running
kubectl -n kube-system get pods -l k8s-app=kube-dns      # CoreDNS Ready
```

> **Bootstrap note.** The agent is `hostNetwork` and depends only on the core
> API (Node objects) to bring up the default network — never on the VPC API — so
> it can start before everything else. Apply kube-proxy (or Cilium) **before**
> cozyplane so the agent and other components can reach the API server during
> bootstrap.

## Create a VPC

A `VPC` is **namespaced** — create it in the owner tenant's namespace. Give it a
CIDR; the controller assigns a globally-unique VNI and marks it `Ready`.

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata:
  name: tenant-a
  namespace: team-a
spec:
  cidrs: ["10.10.0.0/24"]   # IPv4; may overlap other VPCs (see Limitations)
  mtu: 1450
```

```bash
kubectl apply -f vpc.yaml
kubectl -n team-a get vpc tenant-a -o wide
# NAME       VNI   PHASE
# tenant-a   100   Ready
```

## Authorize use with a VPCBinding

Attachment is default-deny. Create a `VPCBinding` **in the namespace whose pods
will attach** (the consumer namespace), pointing at the VPC. Even the owner
attaching its own pods needs one — the VPC's namespace expresses *ownership*; a
`VPCBinding` expresses *use*.

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata:
  name: tenant-a            # any name; one per (namespace, VPC) is typical
  namespace: team-a         # the consumer namespace (here, same as the owner)
spec:
  vpcRef:
    namespace: team-a       # the VPC's owner namespace
    name: tenant-a
```

Creating it requires the **`export`** verb on the referenced VPC, so a tenant can't
bind to a VPC it doesn't own. Because `sdn.cozystack.io` is aggregated-only, that is
enforced in the apiserver's **create strategy** — admission webhooks never see
aggregated resources.

The tenant roles ship with the chart: `cozyplane-tenant-edit` and
`cozyplane-tenant-view` (`deploy/tenant-rbac.yaml`) aggregate into the built-in
`admin`/`edit`/`view` ClusterRoles, so a namespace admin gets cozyplane's tenant
surface with nothing to wire up. They grant `export` and `peer` on VPCs, and they
name **only namespaced kinds** — deliberately: a RoleBinding cannot grant
cluster-scoped access, so a tenant can never be given `list ports` (which would
expose every other tenant's pods, addresses, MACs and placement). Never add a
cluster-scoped kind to a tenant role. See [multitenancy.md](multitenancy.md).

## Attach pods to the VPC

Add the `sdn.cozystack.io/vpc` annotation. Its value is the VPC name (owner
namespace defaults to the pod's namespace) or `<owner-ns>/<vpc>` to use a VPC
owned by another namespace. A matching `VPCBinding` must exist in the pod's
namespace or the pod fails to start (default-deny).

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-1
  namespace: team-a
  annotations:
    sdn.cozystack.io/vpc: tenant-a          # or "team-a/tenant-a"
spec:
  containers:
    - name: app
      image: busybox:1.36
      command: ["sleep", "3600"]
```

The pod's `status.podIP` is a fabric IP (from the node pod CIDR), while its
interface inside the netns carries the VPC IP. The `Port` shows both:

```bash
kubectl get pod app-1 -o wide    # status.podIP is the fabric IP, e.g. 10.244.2.16
kubectl exec app-1 -- ip -4 addr show eth0   # the VPC IP, e.g. 10.10.0.2/32

# A tenant reads its OWN address off its own pod — no cluster-scoped read needed:
kubectl get pod app-1 -o jsonpath='{.metadata.annotations.sdn\.cozystack\.io/vpc-ip}'

# An OPERATOR can see the Port (cluster-scoped; a tenant may not read these):
kubectl get ports -o custom-columns=NAME:.metadata.name,VPCIP:.spec.ip,NODE:.spec.node
# NAME              VPCIP       NODE
# v100.10-10-0-2    10.10.0.2   node-2
kubectl get fabricips            # the fabric address lives here, not on the Port
```

> Ports are cluster-scoped and named `v<vni>.<ip-dashed>` — keyed by the
> globally-unique VNI so the name stays unique across namespaces. The name *is*
> the IP claim: creating it is atomic via etcd name-uniqueness.

Create a second pod (`app-2`) the same way — ideally on another node — and:

```bash
kubectl exec app-1 -- ping -c2 10.10.0.3        # same VPC: works (use app-2's VPC IP)
kubectl exec <default-pod> -- wget -qO- <app-1-fabric-ip>   # north-south: works
kubectl exec app-1 -- ping -c2 <default-pod>    # isolated: 100% loss
kubectl exec app-1 -- ping -c2 8.8.8.8          # isolated: 100% loss
```

VPC pods support `httpGet`/`tcpSocket` probes (kubelet reaches them via the
fabric IP through the bridge), and a `Service` whose selector matches VPC pods
works for traffic *into* them (Endpoints use the fabric IP).

To remove a pod from the VPC, delete the pod; its `Port` (and IP) is released
automatically.

**Revoking access.** Deleting the `VPCBinding` reaps the `Port`s of the pods it
authorized (unless another binding in that namespace still grants the VPC) and
severs those pods' VPC connectivity — they keep running but are cut off, like a
deny-all NetworkPolicy. Re-granting requires recreating the pod.

## Peer two VPCs

A `VPCPeering` connects two VPCs — including two owned by different tenants —
so their pods reach each other with **native addresses, no NAT** (the AWS
VPC-peering model). It is made of **two symmetric halves**, one created by each
owner in their own namespace; the peering is live only while both halves exist
and reference each other:

```yaml
# created by team-a (owner of vpc-a)
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata:
  name: to-team-b
  namespace: team-a
spec:
  vpcRef:
    name: vpc-a              # the local VPC (this namespace)
  peerRef:
    namespace: team-b        # the remote VPC
    name: vpc-b
---
# created by team-b (owner of vpc-b) — its existence IS the acceptance
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata:
  name: to-team-a
  namespace: team-b
spec:
  vpcRef:
    name: vpc-b
  peerRef:
    namespace: team-a
    name: vpc-a
```

There is no accept workflow: **consent is reciprocity**. A lone half sits
`Pending` — that is the visible peering request — and flips `Ready` when the
matching half appears and both VPCs are Ready:

```bash
kubectl -n team-a get vpcpeering to-team-b
# NAME        VPC     PEERNAMESPACE   PEER    PHASE
# to-team-b   vpc-a   team-b          vpc-b   Ready
kubectl exec -n team-a app-1 -- ping -c2 <vpc-b pod IP>   # works, native IPs
```

To revoke, **either** owner deletes their half — cross-VPC traffic drops
immediately, and the surviving half returns to `Pending`. Recreating the
deleted half re-activates the peering; unlike a `VPCBinding` revocation, no
pods are severed from their *own* VPC.

Notes:

- The spec is immutable — re-pointing a peering means replacing the object,
  which re-runs the two-sided handshake.
- Peering is pairwise and **non-transitive**: a↔b plus b↔c does not connect
  a and c.
- The two CIDRs must not overlap (automatic today, since VPC CIDRs are unique
  cluster-wide).
- Peering only makes traffic *admissible* between the two VPCs; it grants no
  rights on the peer VPC itself (no attach, no export).

## Open a path to the outside (the VPC's gateway)

By default a VPC is a **closed island**: no way out, and no way in. Its
north-south boundary is a separate object — a `VPCGateway`
([docs/north-south.md](north-south.md)) — because opening a door onto an
`ExternalPool` is the *operator's* grant, not something a tenant takes by
flipping a field on a VPC it owns:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCGateway
metadata: {name: door, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  poolRef: {name: public}      # requires the "attach" verb on the pool
  nat:
    enabled: true              # outbound for pods with no floating address
  ingress:
    loadBalancer: false        # may a Service type=LB land on this VPC's pods?
```

A VPC has **exactly one** boundary (the oldest gateway wins), and everything
that crosses it is counted per VPC and per door — `cozyplane_vpc_ns_bytes_total`.

**With a `poolRef` (the example above), there is no gateway pod.** Egress is
realized in eBPF at each pod's own veth: the VPC's off-net traffic is SNATed
straight out the uplink to `status.natAddress` — **an address of the VPC's own**,
drawn from the pool. It is distributed across nodes (each node draws ports from its
own shard of the address), so there is no hairpin, no single conntrack point, and no
per-VPC single point of failure. Cluster-internal destinations are still refused;
cluster DNS still works, because the split-horizon resolver serves VPC pods directly
and never needed a pod to proxy it.

Only a `nat.enabled` gateway with **no `poolRef`** still spawns a per-VPC **gateway
pod** (a default-network pod with a second leg on the VPC's reserved `.1`), which
forwards under a default-deny filter: internet forwarded, cluster DNS on `:53`
allowed, everything else cluster-internal dropped. That path has no address of its
own, so its egress is masqueraded to the gateway pod's fabric address and then again
to the **node's** — meaning the tenant is indistinguishable from the platform on the
wire. Prefer a pool.

```bash
kubectl exec app-1 -- ping -c2 1.1.1.1          # works
kubectl exec app-1 -- nslookup example.com       # resolves (via the gateway)
kubectl exec app-1 -- wget -qO- http://<any-cluster-pod-ip>   # still blocked
```

Setting `nat.enabled: false` (or deleting the VPCGateway, or the VPC) tears the
gateway down and the VPC closes again.

**Ingress is closed by default too.** A `Service` of type `LoadBalancer` whose
backends are VPC pods is *refused* unless this VPC's gateway sets
`ingress.loadBalancer: true` — whoever created the Service, and in whatever
namespace. Without it the platform would attract the address, deliver it, and
hand it to a tenant's pod with the tenant's own networking never consulted.
Refusals are counted (`cozyplane_vpc_ns_denied_total`), so "my LoadBalancer
doesn't reach the VPC" has an answer. The gateway needs the chart's `egress.*` values (cluster pod/service
CIDRs, cluster DNS IP) to know what to deny — set `egress.internalCIDRs` to
also cover your node/management networks.

> **Node masquerade.** With `egress.clusterCIDR` set, the agents also install
> the classic node masquerade rule, so *default-network* pods get an internet
> return path too (pod CIDRs aren't routable outside the cluster). VPC pods
> never use it directly — their egress path is always their gateway.

## Expose a workload with a floating IP

An egress gateway gets a VPC *out*; a **floating IP** gets one workload *in* — an
externally-routable address, reachable from outside the cluster, mapped 1:1 to a
tenant IP, with the caller's **real source address preserved**. Unlike a Service
`type=LoadBalancer` (one VIP over many backends), a floating IP points at a single
workload. It is a **true public IP**: the workload also *egresses the internet
from it*, so its outbound source address equals the public IP it is reached on
(what external allow-listing needs). Cluster-internal traffic (its own VPC, cluster
DNS) is unaffected — only internet egress takes the public IP. Its *delivery* does
not route through the gateway: the address maps straight to the tenant IP in the
eBPF datapath.

Its *address*, though, comes from the VPC's gateway. **A VPC with no `VPCGateway`
gets no floating address at all** — the `attach` verb on the pool is what governs
every address a tenant can wear, so create the gateway (above) first.

> **cozyplane does not announce the address.** It *delivers* it. Something else must
> attract it to a node — a CCM assigning it to a VNIC, MetalLB, a static route, or
> simply the address configured on a node. Whichever node it lands on will deliver
> it, because the uplink hook runs at tc ingress, ahead of the kernel's routing
> decision. There is no ARP/NDP responder and no BGP speaker here, by design.

An operator defines a pool of routable addresses once, cluster-wide:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: ExternalPool
metadata: {name: public}
spec:
  cidrs: ["203.0.113.0/24"]
```

A tenant then claims one for a workload in their VPC:

```yaml
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}      # a VPC in this namespace
  target: 10.0.0.5           # the tenant IP to expose
  # poolRef: {name: public}  # optional; defaults to this VPC's VPCGateway's pool
                             # (no gateway => no pool => no address, ever)
  # address: 203.0.113.7     # optional; a specific address, else lowest free
```

The address is **reserved** as soon as the binding is created, but it is only
advertised and made reachable while the `target` IP belongs to a **live Port** —
a running pod. That gives the datapath a node to advertise the address from and
deliver to, and it means the address follows the pod across reschedules. Until a
pod is actually running with the target IP, the binding holds its address but
stays `Pending` — the address is yours, just not yet announced:

```bash
kubectl -n team-a get floatingip web
# NAME   ADDRESS       VPC     TARGET     PHASE
# web    203.0.113.7   vpc-a   10.0.0.5   Pending

kubectl -n team-a get floatingip web -o \
  jsonpath='{range .status.conditions[*]}{.type}={.status}{"\n"}{end}'
# PoolResolved=True
# AddressAssigned=True
# TargetLive=False           <- no running pod has 10.0.0.5 in vpc-a yet
```

Start a pod with `10.0.0.5` in `vpc-a` and the binding goes `Ready`. Binding a
floating IP to a VM NIC's persistent address makes it a stable public IP that
survives pod churn and live migration.

> **Status today.** Live and dev-cluster-validated end to end: the `floating` map,
> the uplink-ingress DNAT with source preservation, the `from_pod` SNAT reply, and
> delivery to the pod wherever it lives (over the overlay if the address landed on a
> different node). What does *not* exist, and never will, is an announcement layer —
> see the note above: attraction is the platform's job.

## Limitations (today)

These are prototype constraints, not permanent:

- **Overlapping VPC CIDRs are supported.** Two tenants may both use
  `10.0.0.0/24` (or any range, including the cluster pod CIDR): everything is
  delivered by (network id, IP), so identical VPC IPs in different VPCs stay
  distinct — same node or across nodes, and for north-south too. The one
  restriction: **overlapping VPCs cannot peer** (peered traffic is routed
  natively, so a shared address would be ambiguous); a `VPCPeering` between them
  stays `Pending` with `CIDRsDisjoint=False`.
- **A VPC's way in and out is its `VPCGateway`, not a field on the VPC.** With no
  gateway a VPC is a closed island (no internet, no external address, no
  LoadBalancer ingress); same-VPC and peered-VPC traffic still work. `nat.enabled`
  opens outbound; `ingress.loadBalancer` admits a `Service type=LB` onto its pods.
  Still missing: per-destination *egress* policy beyond SecurityGroups, and a
  metadata endpoint ([vm-provisioning.md](vm-provisioning.md)).
- **The single-pod gateway is gone — unless you skip the pool.** A gateway with a
  `poolRef` has no pod at all (eBPF SNAT at each pod's veth, state on the pod's own
  node). A `nat.enabled` gateway with *no* pool still gets one pod per VPC (Recreate
  strategy): a node failure or image roll interrupts that VPC's egress until it
  reschedules, and established flows don't survive the move (conntrack is in the
  pod). Give the gateway a pool.
- **All three policy layers exist**: `SecurityGroup` (within and across peered
  VPCs), upstream `NetworkPolicy` (the default network) and `HostFirewall` (nodes).
  A `VPCPeering` no longer opens two VPCs to each other completely — SecurityGroups
  still gate what crosses. See [policy-layers.md](policy-layers.md). Known gaps:
  ICMP rules, and the TCP SYN-gate standing in for a real connection table.
- **IPv4 only.**
- **Revocation is one-way:** deleting a `VPCBinding` severs attached pods, but
  recreating the binding does not reattach a running pod — recreate the pod.
  (Revocation *is* replayed across agent outages: a sever finalizer holds each
  reaped `Port` terminating until the node's agent acknowledges, and the
  controller releases it if the node itself is gone. `VPCPeering` revocation is
  simpler still: recreating a deleted half re-activates the peering.)
- **The tenant API is aggregated-only.** `sdn.cozystack.io` (VPC, Port, VPCGateway,
  FloatingIP, …) is served *exclusively* by the aggregated apiserver — there is no
  CRD mode and no `apiserver.enabled` switch. Only `local.sdn.cozystack.io`
  (`FabricIP`) is a CRD. The two groups are disjoint on purpose: a CRD keeps
  publishing OpenAPI paths after an APIService takes its group over, the specs
  collide, and `kubectl apply` of every cozyplane object then fails client-side.
  ([api-groups.md](api-groups.md).) This is also *why* `export`/`peer`/`attach` are
  enforced in the registry strategies: admission never sees aggregated resources.

## Troubleshooting

- **Nodes stay NotReady / no CNI conf:** check the agent logs
  (`kubectl -n kube-system logs -l app=cozyplane-agent`). The agent writes
  `/etc/cni/net.d/10-cozyplane.conflist` only after the datapath is up. A common
  cause is the agent having no pod supernet to allocate from — check `--cluster-cidr`.
- **`no matches for kind "VPC"`:** the aggregated apiserver isn't installed or isn't
  Ready. The tenant kinds are not CRDs — see Install. Check
  `kubectl get apiservices | grep sdn.cozystack.io`.
- **VPC pod stuck ContainerCreating:** the VPC may not be `Ready` (no VNI yet —
  check the controller), or the plugin couldn't reach the API. The plugin uses a
  kubeconfig the agent writes to `/run/cozyplane/kubeconfig` from its
  service-account token.
- **Cross-node traffic fails but same-node works:** check that UDP 6081 (Geneve)
  flows between nodes and that the agent populated the maps — agent logs show
  `remote set` (Node CIDRs) and `remote port set` (VPC pods).
- **Inspecting the datapath on a node** (kind): `docker exec <node> ip -d link
  show cozyplane0` (the Geneve device), and for captures attach netshoot to the
  node's netns: `docker run --rm --net=container:<node> --privileged
  nicolaka/netshoot tcpdump -ni any udp port 6081`.
