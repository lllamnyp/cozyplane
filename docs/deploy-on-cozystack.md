# Deploying the cozyplane networking variant of Cozystack (runbook)

This installs Cozystack with **cozyplane as the CNI and cozyplane-kpr as the
kube-proxy replacement — no Cilium, no kube-proxy**. It follows the stock
Cozystack install flow and only changes two things: the **platform source**
(point it at the cozyplane fork) and the **networking variant** (`cozyplane`).

The stock tutorial is the source of truth for the surrounding steps; this runbook
assumes you have it open:

- [Install Talos](https://cozystack.io/docs/next/getting-started/install-talos/)
- [Install Kubernetes](https://cozystack.io/docs/next/getting-started/install-kubernetes/)
  (cozystack/website `content/en/docs/next/getting-started/`)
- [Install Cozystack](https://cozystack.io/docs/next/getting-started/install-cozystack/)

## What this variant is (and isn't)

`packages/core/platform/sources/networking.yaml` variant **`cozyplane`** deploys:

- **cozyplane** — the eBPF CNI (flat default network + per-pod VPC tenancy,
  Geneve overlay). Owns the CNI conflist (`00-cozyplane.conflist`, sorts first).
- **cozyplane-kpr** — socket-LB kube-proxy replacement (imports Cilium's LB
  control plane; **no Cilium agent**).

**One IPAM authority** (cozyplane) over the podCIDR — this is the whole point:
it removes the Cilium standalone-IPAM coexistence hazard
([lllamnyp/cozyplane#12](https://github.com/lllamnyp/cozyplane/issues/12)).

**Not yet covered** (works on stock Cilium, must be planned around here):

- **host-firewall** and **default-network `NetworkPolicy`** — Cilium provided
  these; not replaced yet.
- **External NodePort** — needs cozyplane-kpr increment 3 Half B
  ([lllamnyp/cozyplane#13](https://github.com/lllamnyp/cozyplane/issues/13)):
  `externalTrafficPolicy`, client masquerade. In-cluster ClusterIP + DNS
  (socket-LB) and **VM-guest ClusterIP** (the net-0 per-packet DNAT, increment 3
  Half A) work today; earlier blockers — cross-node admission webhooks
  (field note #5) and the floating-IP uplink (field note #7) — are fixed.

The full set of bring-up difficulties (cert-manager ordering, the KubePrism agent
bootstrap, the orphaned Cilium/kube-ovn packages, the `sdn.cozystack.io` group
collision, and the webhook gap above) is written up in
[bringup-field-notes.md](bringup-field-notes.md).

## The bootstrap ordering, and why the etcd is memory-backed

Fresh clusters have a dependency knot: the CNI must come up first (nothing
networks without it), but cozyplane's **aggregated apiserver** needs
cert-manager (its serving cert and etcd PKI) and etcd, and persistent etcd
needs storage (Linstor), and Linstor needs the CNI. Two mechanisms break it:

- **The chart split + CRD bootstrap.** The CNI chart serves `sdn.cozystack.io`
  as **CRDs** from the moment it lands (no cert-manager), so tenancy never
  waits. The aggregated apiserver is a **separate component**
  (`cozystack.cozyplane-apiserver`, chart `cozyplane-apiserver`) that
  `dependsOn` cert-manager and etcd-operator; when it installs, its explicit
  `APIService` **atomically takes over** the group's serving from the CRDs
  (they stay installed, shadowed). On a fresh cluster the CRD store is empty at
  takeover — tenants come later — so nothing migrates.
- **Memory-backed etcd.** The apiserver's etcd is
  `etcd-operator.cozystack.io/v1alpha2` with `storage.medium: Memory` — no PVC,
  no wait on storage.

So the order is:

1. **cozyplane CNI** installs first (default network + CRD-served tenancy).
2. **cert-manager** and the operator layer converge (webhooks work — field
   note #5 is fixed).
3. **cozyplane-apiserver + memory etcd** install and take over the group.
4. **Linstor** installs (as usual).

There is a second bootstrap cycle to break: the hostNetwork **agent** needs the
kube-apiserver, but with no kube-proxy the `kubernetes.default` ClusterIP
(10.96.0.1) is unserved until cozyplane-kpr is up — and kpr needs the agent. So
the agent must dial a *real* apiserver endpoint, not the ClusterIP. On Talos
that is **KubePrism** (a node-local apiserver load balancer at `localhost:7445`);
`values-talos.yaml` sets `kubeApiServer.{host,port}` to it, wired into the agent
and responder as `KUBERNETES_SERVICE_HOST/PORT`. On a non-Talos cluster, point
`kubeApiServer` at whatever node-local apiserver reachability you have (e.g. a
per-node HAProxy, or a control-plane VIP). Leave it empty only where a service
proxy already serves the ClusterIP at agent start.

Trade-off: the memory etcd's `sdn.cozystack.io` objects (VPCs, Ports, …) survive
single-pod restarts (3-replica raft) but **not a full-cluster restart**. A
persistent (`storageClassName`) mode is a follow-up once storage is sequenced
after the CNI. For a demo/eval this is fine; for durable VPC state, plan the
persistent-etcd follow-up.

## Install

Do the stock **Install Talos** and **Install Kubernetes** steps unchanged.
`serviceCIDR` must match `cluster.network.serviceSubnets` from bootstrap
(baked into kube-apiserver). Then:

### 1. Install the operator against the fork's package source

Install the Cozystack operator exactly as the tutorial says, **but point its
platform source at the cozyplane fork** (built from cozystack#3149):

```
oci://ghcr.io/lllamnyp/cozystack-packages
digest = sha256:aee0d62537e45eb908e4c14c4ae79e5c4690e7a9a10884cca6dd3e2a41a5d1e4   # tag: feat-cozyplane
```

Set the operator deploy args `--platform-source-url=oci://ghcr.io/lllamnyp/cozystack-packages`
and `--platform-source-ref=digest=sha256:b60d5176…` (the same fields the
installer's `make image-packages` writes into its values). Re-push the artifact
and bump the digest to pick up fork changes (`flux push artifact
oci://ghcr.io/lllamnyp/cozystack-packages:feat-cozyplane --path=packages
--source=https://github.com/cozystack/cozystack --revision="feat/cozyplane@sha1:<sha>"`
from the cozystack checkout).

Both fork images must be public: `ghcr.io/lllamnyp/cozyplane` and
`ghcr.io/lllamnyp/cozyplane-kpr`.

### 2. Platform Package: select the cozyplane variant

Same `cozystack-platform.yaml` as the tutorial, with `bundles.system.networkingVariant`
set to `cozyplane`:

```yaml
apiVersion: cozystack.io/v1alpha1
kind: Package
metadata:
  name: cozystack.cozystack-platform
spec:
  variant: isp-full
  components:
    platform:
      values:
        bundles:
          system:
            networkingVariant: cozyplane   # <-- cozyplane + cozyplane-kpr, no Cilium
        publishing:
          host: "example.org"
          apiServerEndpoint: "https://api.example.org:443"
          exposedServices: [dashboard, api]
        networking:
          podCIDR: "10.244.0.0/16"
          podGateway: "10.244.0.1"
          serviceCIDR: "10.96.0.0/16"
          joinCIDR: "100.64.0.0/16"
```

Apply it and watch as in the tutorial's step 2.3. Expect this order to settle:
cozyplane agent Ready → cozyplane-kpr Ready (socket-LB attached) → cert-manager
→ cozyplane-apiserver Ready (memory etcd; the APIService takes over the group
from the bootstrap CRDs) → the rest of the system bundle.

### 3. Storage / networking / finalize

Continue with the tutorial's storage (Linstor), networking (MetalLB), and
finalize steps unchanged.

## Smoke tests

```sh
# in-cluster ClusterIP + DNS from a pod (socket-LB, no kube-proxy present)
kubectl run t --rm -it --image=busybox:1.36 --restart=Never -- \
  sh -c 'nslookup kubernetes.default && wget -qO- -T3 https://kubernetes.default/version'
# no kube-proxy DaemonSet exists:
kubectl -n kube-system get ds kube-proxy   # -> NotFound (expected)
# cozyplane-kpr attached socket-LB:
kubectl -n cozy-cozyplane logs ds/cozyplane-kpr | grep 'attached socket-LB'
```

VM-guest ClusterIP and external NodePort will **not** work yet (increment 3).

## Demo bundle — drop the components a cozyplane eval doesn't need

For a lean demo you don't need the backup stack (etc.). Disable heavy optional
system packages via `bundles.system.disabledPackages` (RFC7386 merge keeps
siblings; already-installed leftovers need a manual `kubectl delete` of the
Package/HelmRelease). Add under `components.platform.values`:

```yaml
        bundles:
          system:
            networkingVariant: cozyplane
            disabledPackages:
              - cozystack.backup-controller
              - cozystack.backupstrategy-controller
              # add others you don't want for the eval, e.g. monitoring, once
              # you've confirmed nothing you're testing depends on them.
```

Keep `linstor` (memory etcd defers *cozyplane's* storage need, but Cozystack's
own components still want a storageClass), the aggregated API, and the scheduler.
Trim outward from there and re-check the cluster settles after each removal
(don't silently drop a package something you're testing depends on).

## References

- Variant + package definitions: cozystack#3149 (`feat/cozyplane`),
  `packages/system/cozyplane*`, `packages/core/platform/sources/networking.yaml`.
- KPR design + status: [kube-proxy-replacement.md](kube-proxy-replacement.md).
- IPAM-authority rationale: [lllamnyp/cozyplane#12](https://github.com/lllamnyp/cozyplane/issues/12).
