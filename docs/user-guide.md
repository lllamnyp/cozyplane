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
  internet are all dropped.
- **Tenancy.** The VPC owner controls who may use it: a `VPCBinding` is created
  by someone holding both `create vpcbindings` in the consumer namespace and the
  `export` verb on the VPC. Deleting the binding **revokes** access and severs
  the attached pods. See [control-plane.md §6](control-plane.md) for the model.

## Requirements

- A Linux kernel with BTF (`/sys/kernel/btf/vmlinux`) — 5.10+; tested on 6.8.
- A cluster where each node has `spec.podCIDR` set (`kube-controller-manager
  --allocate-node-cidrs`, which kubeadm/kind set by default).
- A Service implementation: stock **kube-proxy** (iptables/nft) or Cilium in
  kube-proxy-replacement mode. cozyplane does **not** provide Services.
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

```bash
docker build -t ghcr.io/lllamnyp/cozyplane:dev .
kind load docker-image ghcr.io/lllamnyp/cozyplane:dev --name cozyplane   # kind only

# CRDs for the VPC/Port API (served as CRDs in the prototype)
kubectl apply -f config/crd/

# the node agent (DaemonSet) — brings up the default network; nodes go Ready
kubectl apply -f deploy/agent.yaml

# the controller (assigns each VPC a network id)
kubectl apply -f deploy/controller.yaml
```

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
  cidrs: ["10.10.0.0/24"]   # IPv4, unique cluster-wide (see Limitations)
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

Creating it requires the `export` verb on the referenced VPC (enforced by a
`ValidatingAdmissionPolicy`), so a tenant can't bind to a VPC it doesn't own.
Bind the sample `cozyplane-vpc-owner` ClusterRole (`deploy/authz.yaml`) into a
namespace to grant ownership there.

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
kubectl get ports -o custom-columns=NAME:.metadata.name,VPCIP:.spec.ip,FABRIC:.spec.fabricIP
# NAME              VPCIP       FABRIC
# v100.10-10-0-2    10.10.0.2   10.244.2.16
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

## Limitations (today)

These are prototype constraints, not permanent:

- **VPC CIDRs must be unique cluster-wide** (and must not overlap the cluster pod
  CIDR). Overlapping per-tenant CIDRs need bridge "stage 2" (eBPF-keyed delivery
  by fabric IP); stage 1 keeps delivery IP-keyed.
- **VPC pods cannot initiate egress** — no internet, no DNS, no reaching the
  default network or other VPCs. A VPC is a closed island for outbound traffic;
  only inbound (north-south, via the fabric IP) and same-VPC traffic work. A per
  VPC gateway (NAT/DNS/controlled doors) is future work.
- **No network policy / security groups yet** within or across VPCs.
- **IPv4 only.**
- **Revocation is one-way:** deleting a `VPCBinding` severs attached pods, but
  recreating the binding does not reattach a running pod — recreate the pod. A
  revocation that lands while a node's agent is down isn't replayed on restart.
- **No cross-tenant peering:** a `VPCBinding` is intra-domain (one principal with
  authority on both ends); connecting two separately-owned VPCs (peering) is
  future work.
- **VPC/Port/VPCBinding are served as CRDs**, not yet the aggregated API server
  (the swap is transparent to clients; the `/ports` observability subresource
  needs it).

## Troubleshooting

- **Nodes stay NotReady / no CNI conf:** check the agent logs
  (`kubectl -n kube-system logs -l app=cozyplane-agent`). The agent writes
  `/etc/cni/net.d/10-cozyplane.conflist` only after the datapath is up. A common
  cause is a node without `spec.podCIDR`.
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
