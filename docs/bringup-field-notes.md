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

**Fix (interim).** Split the concern at deploy time: the CNI slot installed
**cert-manager-free** (`apiserver.enabled: false` in the Talos values), tenancy
served as CRDs.

**Fix (proper, done).** The chart is split: `chart/cozyplane` (the CNI) serves
the group as **CRDs from the moment it lands** — the bootstrap surface — and
`chart/cozyplane-apiserver` (apiserver + etcd + certs) is a separate component
that `dependsOn` cert-manager. When it installs, its explicit APIService
atomically takes over the group's serving from the CRDs (they stay, shadowed).
Fresh clusters migrate nothing (the CRD store is empty at takeover); clusters
with live CRD objects export → install → re-apply. See
[control-plane.md](control-plane.md) §0.

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

## 5. Admission webhooks fail cross-node — pod→node reply un-encapsulated (FIXED)

**This was the real blocker, and it was a cozyplane datapath bug, not a packaging
one.** It was why the platform stopped converging above the CNI+kpr layer:
`cert-manager-issuers` failed its Helm upgrade on `failed calling webhook
"webhook.cert-manager.io": ... context deadline exceeded`, and ~60 downstream
HelmReleases (kubevirt, cluster-api, kamaji, linstor, every operator with a
webhook) cascaded to `False` behind it.

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

**The first diagnosis was wrong, and the capture proved it.** It looked like the
forward (node→pod) wasn't encapsulated. In fact a capture on the *webhook's* node
showed the forward SYN arriving decapsulated, the pod **SYN-ACKing**, and the
reply leaving `eth0` as `pod-IP → node-IP` — **un-encapsulated, with a pod source
on the bare underlay.** dev4 is OCI, whose fabric drops any frame whose source is
not its VNIC's assigned address (anti-spoofing). So node→pod worked (encapsulated,
node-source outer); **pod→node — the reply — did not** (`from_pod` fell to
`TC_ACT_OK`, the kernel routed it out `eth0` pod-sourced, OCI dropped it). Result:
retransmitting SYNs, no connection, on ~2/3 of webhook calls. pod→pod works because
*both* directions are encapsulated (`remote_of` resolves for pod CIDRs).

**The fix (`node_remotes`, committed).** Encapsulate pod→node traffic over the
overlay too, so the underlay only ever carries node source IPs. A `node_remotes`
map (node address → that node's Geneve endpoint); `from_pod` encapsulates a
default-network pod's traffic to a node — but **only on the pod-veth path**, since
at the uplink egress the same hook sees the Geneve *outer* frames and encapsulating
those would loop. The agent learns node addresses from Node InternalIPs plus a
`cozyplane.io/node-addresses` annotation each agent publishes (its default-route
source), which is what covers the **multi-NIC** case: on dev4 the host sources
from `eth0` (10.4.0.x), *not* the InternalIP (10.4.100.x / the Geneve+floating-IP
NIC), so the reply is addressed to `eth0` and cozyplane must know that address
belongs to a node. On a single-NIC node the two coincide and it is a no-op.

### 5a. Bridged replies to a remote node — the third instance (FIXED, same root)

Found by the dev4 VPC smoke test after 5 and 5b were fixed: a hostNetwork client
on another node couldn't reach a **VPC pod's fabric IP** (the kubelet-probe /
north-south bridge path) — forward fine, reply dropped. `deliver_net0`, which all
six bridge/DNS reverse paths use to send the un-NAT'd reply back to the client,
handled local pods and remote *pod-CIDR* clients but let a remote *node* client
fall to the kernel — pod-sourced frame on the wire again. Fix: the same
`node_remotes` leg in `deliver_net0`. Same-node clients (kubelet itself) are
unaffected — a node's own addresses are never in the map.

### 5b. Pod internet egress — masquerade from the wrong NIC (FIXED, same root)

Same OCI anti-spoofing, exposed once webhooks worked: the node reached the internet
but **pods could not** (ACME ClusterIssuers `i/o timeout` to Let's Encrypt). The
cluster-egress masquerade SNAT'd pod→internet to the **InternalIP** (`eth1`), but
the packet egresses the **default-route link** (`eth0`) — so the source was invalid
for the egress VNIC and OCI dropped it. Fix: a separate `CFG_MASQ_IP` = the
default-route source address, distinct from `CFG_NODE_IP` (still the InternalIP,
which the Geneve endpoint and DNS-steer handle need). Single-NIC: the two coincide.

## 6. `virtctl ssh` / `port-forward` to a VPC VM (KNOWN GAP, by design)

`virtctl ssh` fails with `dialing VM: dial tcp <vpc-ip>:22: ... timed out` for a
VM inside a VPC. Mechanics (kubevirt `pkg/virt-api/rest/`): `virtctl ssh` wraps
the local `ssh` with `ProxyCommand=virtctl port-forward --stdio`, which opens a
websocket to the apiserver's `.../virtualmachineinstances/<vm>/portforward/22`
subresource; the aggregated **virt-api** pod terminates it and does a plain
`net.Dial("tcp", vmi.Status.Interfaces[0].IP + ":22")` (`dialers.go` `netDial`)
**from its own pod netns** — an ordinary default-network pod on an arbitrary
node. That target is the guest IP = the **VPC IP**, which from the default
network doesn't exist at all: VPC CIDRs live at their VNI's scope (they may
overlap between tenants), so the packet matches nothing and falls to the default
route — hang, then timeout. Security groups are unrelated (intra-VPC only). The
K8s-contract door is the **fabric IP** (`status.podIP` — the bridge DNATs any
port, `:22` included), but the portforward dialer doesn't know to use it.
(`virtctl console`/VNC use the *other* dialer — virt-api → virt-handler →
virt-launcher unix socket, no IP networking — and work fine for VPC VMs.)

Operator conveniences, all verified: `virtctl console`; ssh via an in-VPC jump pod
(`ssh -o ProxyCommand="kubectl -n <ns> exec -i <jump> -- nc %h %p" user@<vpc-ip>`);
ssh to the **fabric IP** from any default-network pod or node.

**Decision: not pursued as a cozyplane concern.** A KubeVirt fix is not small:
the VMI API surfaces no launcher-pod IP (`VirtualMachineInstanceStatus` has no
`podIP` field), so the dialer change is gated on first adding one and having
virt-controller populate it — an upstream API change (being explored separately).
More to the point, `virtctl ssh` reachability is a platform internal, not a
tenant contract: the supported way for a user to SSH into a VPC VM is the same as
any cloud — **expose it (floating/public IP) or be inside the network (VPN /
in-VPC client)** and SSH directly. The jump-pod/fabric paths above are operator
tooling, not the product surface.

## What works today

**Everything, end to end.** With the two datapath fixes above the full Cozystack
platform converges on cozyplane — all HelmReleases Ready, cross-node admission
webhooks (cert-manager, kubevirt, cluster-api, kamaji, …), pod internet egress, in
addition to the CNI, cozyplane-kpr socket-LB (ClusterIP + DNS from pods), the
east-west overlay, and same-node host→pod. (Stock components that embed
`CiliumNetworkPolicy`/`CiliumClusterwideNetworkPolicy` also need those CRDs present
— shipped inert in the variant, since cozyplane enforces no NetworkPolicy yet.)

## 7. Floating IPs on a multi-NIC node — the uplink follows the FIB (FIXED)

Two more instances of "the wrong link", found wiring a FloatingIP to the smoke
VM: **(a)** all floating machinery — the `from_uplink` attach, the ARP/NDP
responder MAC, the GARP announcement, the egress redirect — bound to the
*default-route* link, while the floating range lives on the eth1 VLAN, exactly
as the FIB says (`10.4.100.0/24 dev eth1`). `EnsureFloatingUplink` now derives
the owning link from a route lookup per floating address and programs
`CFG_FLOAT_IFINDEX` / `float_uplink_mac` / `CFG_FLOAT_NH` (the fabric's virtual
router = first host of the covering subnet) / `float_net` (the subnet). Egress
picks the neighbour by subnet: ON-subnet destinations resolve directly — OCI's
virtual router answers ARP but will NOT hairpin intra-subnet traffic — while
off-subnet ones go via the router (the FIB would offer the *default* gateway,
wrong for this link). Single-NIC: the lookup lands on the default uplink, no-op.
**(b)** `SetInternal` never pruned the pinned `internal` LPM map, so a CIDR
removed from `--internal-cidrs` kept classifying destinations as
cluster-internal and dropped floating replies into the closed-island path
(diagnosed via `kfree_skb` reason `TC_INGRESS` + `bpftool map dump`). Now
diff-synced like the masquerade sources.

Exposure recipe (OCI): a reserved public IP cannot attach to a VLAN address —
use a **public Network Load Balancer** (free) in the VCN subnet with the
floating IP as an IP backend (`is-preserve-source=false` for symmetric return);
the VCN virtual router ARPs on the VLAN and cozyplane answers/GARPs on
migration. The VLAN NSG must admit the traffic; the NLB needs an NSG allowing
its listener from outside and egress to the VLAN.
