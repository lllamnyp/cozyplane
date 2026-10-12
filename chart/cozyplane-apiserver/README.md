# cozyplane-apiserver Helm chart

The `sdn.cozystack.io` API group served by a real **aggregated API server**
(backed by a dedicated etcd) instead of CRDs — the design target: custom
validation, the export/peer verb checks in-server, and subresources (e.g. the
`/ports` observability subresource) beyond CRD ergonomics.

This is a **separate chart from [cozyplane](../cozyplane)** by design. cozyplane
is the CNI and must install before almost everything — including cert-manager —
while this apiserver needs cert-manager `Certificate`s (its serving cert, the
etcd PKI). Splitting lets the CNI slot stay cert-manager-free and this chart
install later, once cert-manager is up (in Cozystack: a component that
`dependsOn` cert-manager).

## Exclusive distribution and bootstrap

Set the same `api.mode` (`aggregated` by default, or `crd`) in both charts.
Use one fresh regional cluster per distribution; changing a populated cluster
in place or taking over its APIService is unsupported. The CNI chart serves
FabricIP independently and installs tenant CRDs only in CRD mode.

Installation is deliberately two phases. Install the CNI chart first; in CRD
mode its tenant webhook is fail-closed while the admission service is absent.
Default-network bootstrap uses FabricIP and remains available. Install
cert-manager next, then this chart in the same namespace and mode. In CRD mode
this chart installs only the TLS admission service, its RBAC and certificates;
it installs no aggregated server or dedicated etcd. In aggregated mode it
installs the existing server/etcd distribution.

For a standalone fixture without cert-manager, precreate a TLS Secret and pass
the same `admission.tls.existingSecret` and public `admission.tls.caBundle` to
both charts. No key material belongs in values or source control. See
[CRD distribution](../../../docs/crd-distribution.md) for the required recipe
and compatibility inventory. Never remove CRDs as a deployment shortcut.

## Requirements

- cert-manager (serving certificates, aggregated etcd PKI), or an operator-provided admission TLS Secret for CRD mode.
- For production aggregated etcd: the aenix-io etcd-operator (`etcd.operator.enabled`),
  replicated and PVC-backed. The default is a built-in single-pod etcd with
  emptyDir storage — dev/evaluation only; a pod reschedule erases every
  `sdn.cozystack.io` object.
- The [cozyplane](../cozyplane) chart (any order relative to it — but the CNI
  normally lands first).
