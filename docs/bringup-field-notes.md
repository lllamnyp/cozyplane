# Bring-up field notes: cozyplane as a cluster's sole CNI

Running cozyplane as the **only** CNI — no Cilium, no kube-ovn, no kube-proxy —
surfaces a class of problems that the e2e harness and the "coexist with Cilium"
mode never hit. This is the log of what broke bringing the
[cozyplane networking variant of Cozystack](deploy-on-cozystack.md) up on a fresh
three-node Talos cluster, the root cause of each, and the fix (or, for the last
one, the open gap). Cozystack is the worked example, but every item here is about
*cozyplane as a primary CNI*, not about Cozystack specifically — expect the same
knots on any kube-proxy-less, single-CNI cluster.

## 1. cert-manager ordering — the CNI installs before cert-manager (solved)

**Symptom.** The whole cozyplane Helm release failed with `no matches for kind
"Certificate" in version "cert-manager.io/v1"`, and the CNI never came up.

**Root cause.** cozyplane is the CNI, so it must install *first* — before almost
everything, including cert-manager. But the aggregated apiserver and its etcd
want cert-manager `Certificate`/`Issuer` objects. Bundling the apiserver into the
first (CNI) Helm release makes the release depend on a CRD that does not exist
yet.

**Fix.** Split the concern at deploy time: the CNI slot installs **cert-manager-free**
(`apiserver.enabled: false` in the Talos values). The default network, Services,
and DNS all work without the aggregated apiserver; VPC tenancy (`sdn.cozystack.io`)
is deferred. The proper fix (tracked, not yet done) is to split the chart so the
apiserver+etcd is a *separate* component that `dependsOn` cert-manager, restoring
tenancy without wedging the CNI. See [roadmap.md](roadmap.md).

## 2. The agent can't reach the apiserver with no kube-proxy (solved)

**Symptom.** The hostNetwork agent crashlooped: `get self node "nodeN": dial tcp
10.96.0.1:443: i/o timeout`.

**Root cause.** A bootstrap cycle. The agent needs the kube-apiserver. With no
kube-proxy, the `kubernetes.default` ClusterIP (10.96.0.1) is unserved until
cozyplane-kpr programs it — and cozyplane-kpr needs the agent up first. So at
agent start there is *no* service proxy for 10.96.0.1.

**Fix.** Point the agent at a *real* apiserver endpoint instead of the ClusterIP.
On Talos that is **KubePrism**, a node-local apiserver load balancer at
`localhost:7445`; the chart gained a `kubeApiServer.{host,port}` value wired into
the agent and responder as `KUBERNETES_SERVICE_HOST/PORT` (empty default =
ClusterIP, unchanged for proxied clusters). Note this is *not* the same problem as
#5: the apiserver's own ClusterIP resolves to **node** IPs (the apiservers are
hostNetwork), so once kpr is up it rides the underlay fine — it was purely the
pre-kpr window that needed KubePrism.

## 3. Orphaned Cilium/kube-ovn packages (solved)

**Symptom.** `multus` and `securitygroup-controller` in `CrashLoopBackOff`;
`kubeovn-webhook`/`kubeovn-plunger` stuck.

**Root cause.** The Cozystack platform bundle swapped the networking *variant*
(Cilium+kube-ovn → cozyplane) but a *shared* `common-packages` helper still
instantiated four data-plane packages that assume Cilium/kube-ovn:

- **multus** delegates to the Cilium primary conflist `05-cilium.conflist`, which
  cozyplane never writes (it writes `00-cozyplane.conflist`).
- **securitygroup-controller** projects `sdn.cozystack.io` SecurityGroups onto
  `CiliumNetworkPolicy` (no `cilium.io/v2` CRD present) — and see #4.
- **kubeovn-webhook/-plunger** are the kube-ovn control plane; the webhook would
  fail *closed* once cert-manager landed and block resource creation cluster-wide.

**Fix.** Gate those four in `common-packages` on `networkingVariant != cozyplane`.
The `kubeovn-cilium` variant is unchanged.

## 4. `sdn.cozystack.io` is a two-owner collision (solved, with a caveat)

**Symptom.** Latent, not yet firing on the cluster — found by inspection.

**Root cause.** Stock Cozystack has had its **own** `sdn.cozystack.io` API group
since `feat(sdn): add SecurityGroup API types`: a single `SecurityGroup` kind,
served by the **cozystack-api** aggregated apiserver as a projection over a
`CiliumNetworkPolicy`, reconciled by securitygroup-controller. cozyplane
*independently* uses `sdn.cozystack.io` for its whole object model (`vpcs, ports,
securitygroups, floatingips, servicevips, vpcbindings, vpcpeerings,
externalpools`), served as CRDs. Both define `securitygroups.sdn.cozystack.io`
with incompatible schemas, and the `v1alpha1.sdn.cozystack.io` APIService is a
name-singleton: the moment cozystack-api deploys, its explicit APIService
*hijacks* the group from cozyplane's CRDs and every non-SecurityGroup kind (VPC,
Port, …) starts 404ing.

**Fix (this fork).** cozyplane owns the group in the cozyplane variant:
`cozystack-api` gained a `serveSDN` value (default `true`) that the platform
bundle sets to `false` on the cozyplane path, so cozystack-api does not aggregate
`sdn.cozystack.io`; securitygroup-controller is disabled (#3).

**Caveat.** This makes cozyplane *squat* Cozystack's group name — the two SDN
features can never coexist, and upstreaming is blocked. The clean long-term fix is
to move cozyplane to its own API group (e.g. `sdn.cozyplane.io`). Deferred by
choice for now.

## 5. Admission webhooks fail cross-node — node-origin → remote-pod (OPEN)

**This is the real blocker, and it is a cozyplane datapath gap, not a packaging
one.** It is why the platform stops converging above the CNI+kpr layer:
`cert-manager-issuers` fails its Helm upgrade on `failed calling webhook
"webhook.cert-manager.io": ... context deadline exceeded`, and ~60 downstream
HelmReleases (kubevirt, cluster-api, kamaji, linstor, every operator with a
webhook) cascade to `False` behind it.

**Root cause, isolated on the cluster.** The kube-apiserver is hostNetwork; the
cert-manager webhook is an ordinary **pod**, one replica, on one node. A webhook
call is therefore *node-originated* (host netns) traffic to a **remote pod**.
Measured from a hostNetwork probe pod vs. a pod-network probe pod, both dialing
the webhook (pod IP `…2.8` / ClusterIP `…1.180`) on the node that hosts it:

| source (on a node *without* the webhook pod) | pod IP | ClusterIP |
|---|---|---|
| **hostNetwork** (as the apiserver is) | timeout | **timeout (~5 s)** |
| pod-network (control) | 404 in 6 ms | 404 in 6 ms |
| hostNetwork on the webhook's *own* node | 404 | 404 |

So: pod→pod east-west over the Geneve overlay works; socket-LB works; **same-node**
host→pod works; **cross-node host→pod does not** — node-originated traffic to a
remote pod is never encapsulated into the overlay. With three apiservers and one
webhook pod, ~2/3 of webhook calls land on an apiserver that cannot reach it.

By design ([internals.md](internals.md#the-dual-address-bridge)) the datapath
steers node-originated traffic (kubelet probes) to `to_pod` via a `/32
fabricIP → veth` route — which only exists for a **local** pod. The design assumed
node-origin is always same-node (kubelet only probes local pods). Admission
webhooks break that assumption: the apiserver probes pods anywhere in the cluster.

**What it would take to fix.** A node-originated egress path to remote pods: a
host-sourced packet to a remote pod's fabric/VPC identity has to enter the Geneve
overlay (and its reply come back), the same encapsulation `from_pod`/`from_overlay`
already do for pod→pod — but for the host netns as the source. Until then, any
webhook-backed component is only reachable from the apiserver co-located with its
(single) backing pod; spreading replicas across all control-plane nodes is a
per-component band-aid, not a fix. Tracked in [roadmap.md](roadmap.md).

## What works today

CNI (default network + VPC), cozyplane-kpr socket-LB (in-cluster ClusterIP + DNS
from **pods**), east-west overlay, same-node host→pod, and the underlay path to
hostNetwork ClusterIPs (e.g. `kubernetes.default`). The open item above (#5) is the
gate on running the *full* Cozystack platform, whose operators lean on admission
webhooks.
