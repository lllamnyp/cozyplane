# Packaging: charts, images, and the digest pin

cozyplane ships as **four Helm charts under `chart/`**, consumed straight out of
this git repository by Cozystack — no OCI artifact, no vendoring into the
`cozystack/cozystack` tree. This document covers the two things that are not
obvious from reading the charts: **how a cluster consumes them**, and **where the
container images come from and how their digest pins stay honest**.

## 1. The four charts

| Chart | What it is | Namespace |
|---|---|---|
| `chart/cozyplane` | The CNI: agent/controller, FabricIP, RBAC and policies; CRD mode also installs eleven tenant schemas and the fail-closed webhook configuration | `cozy-cozyplane` |
| `chart/cozyplane-kpr` | Kube-proxy replacement: socket-LB service load balancing, importing Cilium's LB control plane with no Cilium agent ([kube-proxy-replacement.md](kube-proxy-replacement.md)) | `cozy-cozyplane` |
| `chart/cozyplane-apiserver` | Tenant control-plane phase: aggregated server/dedicated etcd by default, or CRD admission service and TLS ([crd-distribution.md](crd-distribution.md)) | `cozy-cozyplane` |
| `chart/cozyplane-cilium-crds` | The `cilium.io/v2` policy CRDs, **inert**. Nothing enforces them; stock Cozystack charts embed `CiliumNetworkPolicy` / `CiliumClusterwideNetworkPolicy` objects and fail to install when the CRDs are absent | `cozy-system` |

None of them depends on `cozy-lib` or any other chart library, and none has a
`charts/` directory. That is a requirement, not an accident: the `PackageSource`
manifests declare no `libraries`, so a library dependency would break rendering.
Each must render standalone:

```sh
helm template cozyplane            chart/cozyplane            -f chart/cozyplane/values.yaml -f chart/cozyplane/values-talos.yaml
helm template cozyplane-kpr        chart/cozyplane-kpr        -f chart/cozyplane-kpr/values.yaml -f chart/cozyplane-kpr/values-talos.yaml
helm template cozyplane-apiserver  chart/cozyplane-apiserver  -f chart/cozyplane-apiserver/values.yaml
helm template cozyplane-cilium-crds chart/cozyplane-cilium-crds
```

The `version:` in each `Chart.yaml` is `0.0.0` and means nothing — the chart is
addressed by git commit, so the commit *is* the version.

## 2. How a cluster consumes them

`packages/packagesources/` holds two ready-to-apply Cozystack manifests:

- **`networking.yaml`** — a Flux `GitRepository` pointing at this repo, plus the
  `cozyplane.networking` `PackageSource`: cilium-crds, then the CNI, then kpr.
  It has **no `dependsOn`**, because it is the CNI: it installs ahead of
  cert-manager and everything else, since nothing can be scheduled until it is up.
- **`apiserver.yaml`** — the `cozyplane.apiserver` `PackageSource`, sequenced
  *after* cert-manager, the etcd-operator and the storage layer, because the
  aggregated API server needs `Certificate`s, an `EtcdCluster` and a
  `StorageClass`. One `PackageSource` cannot hold both positions, which is the
  only reason there are two files.

The `GitRepository` lives in `networking.yaml` only; one source object serves
both. Its `ref` carries `branch: main` and **no `commit`** — a repository that
pinned a commit to itself could never be updated in place. A cluster that wants
a fixed build stamps `commit: <sha>` onto its own copy of that object.

Both PackageSources have a `default` aggregated variant and a `crd` variant.
Select the matching pair in a **fresh regional cluster**; an existing populated
distribution cannot be switched in place. CRD networking applies
`values-crd.yaml` after the default and Talos overlays. Its dependency list is
still empty: default-network/FabricIP bootstrap must work before cert-manager.
The CRD control-plane variant applies its own `values-crd.yaml` and depends only
on cert-manager, without the etcd-operator or storage layer. Tenant writes fail
closed until that second phase is ready. Keep both chart releases in the same
namespace with matching TLS settings.

`valuesFiles` are ordered: the Cozystack operator applies the **first** with
strategy `Overwrite` and **every later one** with `Merge`. That is why
`values-talos.yaml` must stay a separate file — its contents (notably
`kubeApiServer: {host: localhost, port: 7445}`, Talos's KubePrism, which the
hostNetwork agent dials during bootstrap before any service proxy exists) are
wrong off Talos and must never become chart defaults.

`apiserver.yaml`'s `dependsOn` names `blockstor.storage`. A cluster running the
stock storage package must change that one line to `cozystack.linstor`;
otherwise the PackageSource waits forever on a package that never appears.

## 3. Where the images are built

The default networking image and the separate KPR image are built in CI.
An optional distroless target supplies the static control-plane services.

### Distroless control plane

Build the root Dockerfile with `--target control-plane` to package only
`sdn-controller`, `cozyplane-apiserver` and `cozyplane-admission` on the
digest-pinned `gcr.io/distroless/static-debian13:nonroot` base. These Go binaries
are statically linked; the runtime has no shell or package manager and runs as
UID/GID 65532. The controller and API server charts also use a read-only root
filesystem and drop all capabilities, as the CRD admission deployment already
does. Mounted service-account and TLS files remain readable by that user.

```sh
docker build --target control-plane -t cozyplane-control-plane:dev .
helm template cozyplane chart/cozyplane \
  --set controller.image=cozyplane-control-plane:dev
helm template cozyplane-apiserver chart/cozyplane-apiserver \
  --set image=cozyplane-control-plane:dev
```

For a cluster, pin both image references by digest after scanning every
advertised architecture. Set `controller.image` in the networking release and
`image` in the API/admission release. An empty `controller.image` preserves the
existing single-image deployment. The controller's `--agent-image` and
`--gateway-image` still use the networking release's top-level `image`, so
generated VPN and gateway workloads retain their required executables.

The default `runtime` target remains the networking image: agents and gateways
execute iptables, StrongSwan or FRR, and the CNI installer uses a shell and `cp`.
Copying their dynamic libraries into a distroless image without distribution
package metadata would obscure vulnerability scans. Those components therefore
retain the Debian runtime and its full package inventory.

### `ghcr.io/lllamnyp/cozyplane` — CI-built, multi-arch, reproducible

The runtime uses digest-pinned Debian 13 and applies security updates before
installing its networking tools. The Go binaries remain statically linked and
use the existing pinned builder. Debian 12's available FRR and strongSwan
packages retain HIGH/CRITICAL findings even after an ordinary rebuild; a scan
that ignores findings without a distribution fix does not establish that a
registry with an all-findings pull policy will accept the image.

Install `strongswan-charon` explicitly: the IPsec wrapper executes
`/usr/lib/ipsec/charon` and manages its child lifetime and VICI socket. The
Debian 13 default `charon-systemd` package does not provide this executable;
there is no systemd process in the gateway container.

Scan each advertised architecture, including findings without a fix, and
verify the actual registry pull before changing a cluster. An updated Debian 13
runtime removes the two previously observed CRITICAL findings and includes the
strongSwan authentication-bypass fix. Unfixed HIGH findings remain in other
distribution packages; production activation and the real-cluster recipe remain
pending. Do not lower a registry threshold or inherit another image's CVE
exceptions to make this image downloadable.

Relevant distribution reports:
[FRR](https://security-tracker.debian.org/tracker/source-package/frr),
[strongSwan](https://security-tracker.debian.org/tracker/CVE-2026-78135).

Built and pushed by [`.github/workflows/release.yml`](../.github/workflows/release.yml)
on every push to `main` (and on `v*` tags), for `linux/amd64` and `linux/arm64`,
from the repository root `Dockerfile`. It carries the agent, the CNI plugin, the
controller, aggregated apiserver, CRD admission server, gateway, responder and
VPN components, plus the CNI plugins — one image. Tags: `main`,
`main-<short-sha>`, and semver on tags. The workflow
prints the resulting digest into the run's job summary.

The build is **digest-reproducible** ([#4](../../issues/4)): `SOURCE_DATE_EPOCH=0`
plus `rewrite-timestamp=true` to pin layer and config timestamps, digest-pinned
base images, `-trimpath -buildvcs=false` on every `go build`, and apt byproducts
removed in the same layer. The same source tree therefore always produces the
same index digest.

Both legs are verified after the push: `.github/scripts/verify-arch.sh` reads one
binary out of each advertised platform and fails the job unless `file` agrees.
This is not hypothetical — `ARG TARGETARCH=amd64` once made both legs amd64 while
the index still advertised arm64 (see the script, and
[bringup-field-notes.md](bringup-field-notes.md)).

**Attestations are on for `v*` tags and off for `main`**, because they cannot be
both. A provenance or SBOM manifest embeds run metadata and lands in the index,
so the digest moves on every run — which is exactly what the pin loop in §4 needs
not to happen. A release is pinned once as `vX.Y.Z@sha256:…` and never chased, so
it can afford them; `main`, which dev clusters track through a digest that gets
refreshed commit by commit, cannot. If provenance is ever wanted on `main` too,
the pin loop has to change with it — pin tagged releases instead of chasing
`main` — rather than the two being switched on together and the convergence
quietly breaking.

### `ghcr.io/lllamnyp/cozyplane-kpr` — CI-built, multi-arch, reproducible

Built and pushed by the `kpr-image` job in the same workflow, on the same
triggers, for the same two platforms, from `kpr/Dockerfile` with `kpr/` as the
build context — so nothing outside that module reaches the image. Same tags,
same digest in the job summary, and the same reproducibility measures as above.

It is a separate image because it is a separate module: it imports Cilium's
load-balancer control plane, which the main cozyplane module never does
(`kpr/go.mod`). Both images are built for every commit to `main`, so a commit
always has both and the digest-pin loop below converges for each.

The arm64 leg costs almost nothing despite Cilium's ~394-module tree, because
nothing is emulated: the builder stage is pinned to `$BUILDPLATFORM` and
cross-compiles via `GOARCH`, and the final stage only `COPY`s — there is no
`RUN` under the target platform. The embedded `bpf_sock.o` is `--target=bpf`
bytecode (`kpr/build-bpf.sh`), which is architecture-neutral, so one object
serves both legs. CI cross-compiles for arm64 on every PR, where a break is one
line rather than a failed release build.

Building it locally:

```sh
docker build -t cozyplane-kpr:dev -f kpr/Dockerfile kpr
```

## 3a. Cutting a tagged release

`release.yml` already triggers on `v*` as well as on `main`, so a release is one
push:

```bash
git tag -s v0.1.0 -m 'cozyplane v0.1.0'   # annotated; signed if you have a key
git push origin v0.1.0
```

That builds both images for both platforms, verifies both legs, attaches
provenance and an SBOM, and tags the result `v0.1.0`, `0.1.0` and `0.1` (the
`{{raw}}` form is there so the literal `vX.Y.Z` a consumer expects exists). Read
the digest out of the run summary and pin the release form:

```
ghcr.io/lllamnyp/cozyplane:v0.1.0@sha256:…
```

The tag and the digest together are what a downstream repository should vendor: the
tag says which release, the digest says exactly which bytes, and the digest is
what actually resolves.

Two things are deliberately **not** set up here, both operator decisions:

- **Signing.** No cosign step and no key material in this repository. Adding one
  means deciding where the key lives (keyless OIDC against the workflow identity
  is the obvious candidate) — a decision about the project's trust root, not
  about packaging.
- **Where releases ultimately live.** These images are built under
  `ghcr.io/lllamnyp`, which is a personal namespace. If cozyplane ships as part
  of Cozystack, `ghcr.io/cozystack` is the likelier home; that move changes every
  pin in §4 and the registry credentials CI uses, so it wants doing once,
  deliberately.

## 4. The digest pin, and why it isn't circular

Three `values.yaml` files pin an image by digest:

| File | Image |
|---|---|
| `chart/cozyplane/values.yaml` | `ghcr.io/lllamnyp/cozyplane` |
| `chart/cozyplane-apiserver/values.yaml` | `ghcr.io/lllamnyp/cozyplane` (the same pin — keep them equal) |
| `chart/cozyplane-kpr/values.yaml` | `ghcr.io/lllamnyp/cozyplane-kpr` |

Because a cluster tracks a **commit** of this repository, the digest recorded at
that commit must be a build of *that same commit*. Written out, that looks
circular: writing the digest into `values.yaml` creates a new commit, whose build
would presumably have a different digest, which would then need writing in, and
so on.

It is not circular, for one reason: **`chart/` does not reach the image.** The
final stage of the `Dockerfile` copies only compiled binaries out of the build
stage; charts, docs and manifests are in the build context but contribute nothing
to any layer of the published image. Combined with the reproducibility measures
above — in particular `-buildvcs=false`, without which the embedded commit hash
made every commit produce a different binary — a commit that changes only
`values.yaml` rebuilds to **exactly the digest it just pinned**. The loop
converges after one step:

1. Land the source change on `main`. CI publishes an image; note its digest `D`.
2. Write `D` into the `values.yaml` files and land that as a second commit.
3. CI rebuilds. Because nothing that reaches the image changed, the digest is
   still `D` — so commit 2's pin *is* a build of commit 2. That is the commit to
   hand a cluster.

This is checkable after the fact, and it holds today: `main-e1f36dd` (a datapath
fix) and `main-b10baf0` (a docs-only commit on top of it) both resolve to
`sha256:79866d68…`.

`cozyplane-kpr` now follows the same two-step, for the same reason: `chart/` is
not even in its build context, and its build carries the same reproducibility
measures. Note that `kpr/` is a separate module, so a commit touching only the
main module still rebuilds it to the identical digest.

### Refreshing a pin

```sh
# the digest CI published for a commit (anonymous; no docker login needed)
TOK=$(curl -s "https://ghcr.io/token?scope=repository:lllamnyp/cozyplane:pull&service=ghcr.io" \
      | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -sI -H "Authorization: Bearer $TOK" \
     -H "Accept: application/vnd.oci.image.index.v1+json" \
     "https://ghcr.io/v2/lllamnyp/cozyplane/manifests/main-<short-sha>" \
  | grep -i docker-content-digest
```

The same request with no `Authorization` header at all is what a cluster does, so
running it that way also confirms the **anonymous pullability** the charts rely
on: neither image needs an `imagePullSecret`, and both packages must stay public.

### Pin status

Verified 2026-08-25 against ghcr.io, anonymously:

- `ghcr.io/lllamnyp/cozyplane@sha256:681e37c0d8f919829879bb74eb0419b8a0c7b43694ff94904d3935bc0eb22a0c`
  — an OCI index with `linux/amd64` + `linux/arm64`, and the current `main` /
  `main-17b707f` build.
- `ghcr.io/lllamnyp/cozyplane-kpr@sha256:425693919d8a4f24daea9629548180ef5cef72dece4d31bf5b6505a671147766`
  — `linux/amd64` only, pushed 2026-07-18 (tag `spn`) from the `kpr/` tree as of
  commit `72e72df`, which is still the tip state of `kpr/`.
