# cozyplane Helm chart

Packages cozyplane — a multi-tenant eBPF CNI (flat default network + VPC
tenancy) — as the node agent DaemonSet, the controller Deployment, the
`sdn.cozystack.io` CRDs, RBAC, and the VPCBinding `export` admission policy.

cozyplane is the **primary CNI**. Install it on a cluster with no other CNI
(or in place of one being removed), and keep a Service implementation — stock
kube-proxy or Cilium in kube-proxy-replacement mode — alongside it. See
[../../docs/user-guide.md](../../docs/user-guide.md) for the full deployment and
usage walkthrough and [../../docs/control-plane.md](../../docs/control-plane.md)
for the tenancy model.

## Requirements

- Kubernetes >= 1.30 (the `export` ValidatingAdmissionPolicy; set
  `exportPolicy.enabled=false` for older clusters).
- A Linux kernel with BTF (`/sys/kernel/btf/vmlinux`), 5.10+.
- Each node has `spec.podCIDR` set.

## Install

```bash
helm install cozyplane ./chart/cozyplane --namespace cozy-cozyplane --create-namespace
```

The chart's CRDs in `crds/` are installed first (Helm does not template or
upgrade them; manage CRD upgrades out of band).

## Configuration

All knobs are documented inline in [`values.yaml`](values.yaml). The ones you are
most likely to set:

- `image` — the cozyplane container image (digest-pinned by the release
  pipeline).
- `mtu` — pod MTU (underlay MTU minus ~50 bytes of Geneve overhead).
- `cniConfName` — the CNI conflist filename; use a low prefix such as
  `00-cozyplane.conflist` to sort ahead of a co-installed CNI (e.g. Cilium).
- `genevePort` — override only to avoid a clash with another overlay on 6081.
- `exportPolicy.enabled` — the VPCBinding export admission gate (needs k8s 1.30+).

## What gets installed

- `cozyplane-agent` (DaemonSet, hostNetwork + privileged): the datapath manager
  and CNI binary installer, one per node.
- `cozyplane-controller` (Deployment): assigns VNIs and reaps Ports on VPCBinding
  revocation.
- CRDs: `vpcs`, `vpcbindings`, `ports` (`sdn.cozystack.io`).
- RBAC for both components, the `cozyplane-vpc-owner` sample role, and the export
  ValidatingAdmissionPolicy.
