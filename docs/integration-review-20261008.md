# Integrated review tree

This branch combines upstream `main` at `d328c1d`, the feature stack in PR #56
at `e1f510e`, and the audited local source snapshot at `b59874f`. It is a review
and build candidate. The historical laboratory results quoted in feature design
documents do not certify this combined tree on a Kubernetes/Talos cluster.

## Content retained

| Source PRs | Integrated behavior |
| --- | --- |
| #23, #24 | Multi-attach design, per-interface CNI addressing, forwarding grants |
| #25 | Selected tenant gateway appliances, explicit routes and blackholes |
| #26, #27 | KubeVirt multi-NIC design and Multus adapter |
| #37 | WireGuard/IPsec, roadwarrior, HA and multi-VPC VPN hubs |
| #38 | Flow ring buffer, bounded streaming, metrics and flowctl |
| #39, #40 | CNI configuration ownership and periodic TCX ordering |
| #55, #56 | Operator VPC boundaries, managed-resource authorization and optional native CRD distribution |
| Current main | Leader election, authenticated IPv6 metrics, KPR restart handling, periodic FabricIP healing |
| Local audit | UID/sandbox/ifindex ownership, revocation guards, persistent VNI allocation, admission and work/memory budgets |

Focused upstream review is available in draft PRs #59 (SecurityGroup inputs),
#60 (CNI ownership) and #61 (guarded TCX ordering). This larger integration
candidate retains their behavior alongside the feature stack; the old feature
PRs remain open for review and attribution.

## Corrections found while integrating real code

- Restore ownership-aware interface alias parsing and the preservation of a
  halted VM's Port, while retaining live reads and UID/RV deletion preconditions.
- Publish routes and blocked prefixes separately for each VPN hub VPC. Reject
  foreign Ports, revoke all owned bindings, and include additional VPCs in event
  indexes. Oversized or undeclared hub route input denies the owner's scopes.
- Retain one authoritative off-VPC route lookup in the overlay receiver. A
  duplicated route block could redirect native VPC prefixes into an appliance.
- Keep eBPF continuations below the kernel's combined stack budget using aligned
  per-CPU packet/tunnel scratch. Packet tests install the real continuations;
  production loading still fails closed if an entry is missing.
- Stream live Port pages for boundary identity acknowledgement and retain the
  indexed ServiceVIP candidate lookup rather than copying unrelated claims.
- Reconcile shared API signatures and authorization once per spec update;
  regenerate conversion, clients, OpenAPI, CRDs and the embedded eBPF object.
- Build all twelve binaries in `make build`, including the separate KPR module;
  exclude output binaries from the Docker build context.
- Remove wget from the image. The flowctl exec helper uses Go HTTP against only
  the fixed loopback flow paths, with no proxy/redirect and bounded snapshots.

## Performance measurement

`BenchmarkServiceVIPCandidateCacheLargeData`, on Linux amd64 / Go 1.26.8,
uses 4,000 unrelated claims carrying 64 KiB annotations, representing over
250 MiB of synthetic API data. With setup excluded, 100 resolutions measured
14,913 ns/op, 12,767 B/op and 146 allocs/op. This measures candidate resolution,
not total process RSS or end-to-end network throughput.

## Acceptance boundary

Validation completed on Linux / Go 1.26.8:

- Full root-module and KPR tests with `-race`, plus `go vet` for both modules.
- All twelve Linux amd64 executables, and arm64 compilation of root commands
  and KPR. The final flowctl change also passes its HTTP/race tests and both builds.
- 186 generated API/CRD files regenerated with no drift; embedded eBPF bindings
  and object compiled from the C source. All entry programs pass the kernel verifier.
- Real kernel/netlink tests with `COZYPLANE_BPF_TEST=1`, `COZYPLANE_REQUIRE_BPF=1`
  and `COZYPLANE_CNI_NETLINK_TEST=1`, with race detection, using private bpffs.
- Four Helm charts linted/rendered, including both API modes and Talos values.
- Gitleaks source scan without detected secrets. `govulncheck` reports no affected
  imported package/symbol in either module; its root module inventory includes
  the unmaintained, unimported `x/crypto/openpgp` advisory GO-2026-5932.
- Default runtime and optional control-plane Docker targets build successfully.

Release acceptance still requires a disposable Kubernetes/Talos run of the
combined CNI, boundary acknowledgement, native CRD webhook rotation/outage, VPN
crypto and KubeVirt migration paths. The native CRD cross-kind GET is not an
atomic address reservation; its documented controller conflict recovery remains
distinct from the aggregated registry's atomic storage claim.

## Runtime dependency release blockers

Trivy 0.74.0, with a fresh database on 2026-10-08, finds no HIGH/CRITICAL issues
in the optional control-plane image (six Debian packages, three Go binaries).
The final default network/VPN runtime has 127 Debian packages and thirteen Go
binaries. It still has **50 HIGH/CRITICAL package entries covering 13 unique
CVEs**, all in Debian packages, with no `FixedVersion` supplied by the scanner.
No Go binary findings are reported. Removing wget eliminated CVE-2026-58471
and CVE-2026-58472 and reduced the package inventory from 135 to 127.

| Dependency family | CVEs still reported |
| --- | --- |
| FRR 10.3-3+deb13u1 | CVE-2026-37460 |
| c-ares 1.34.5-1+deb13u1 | CVE-2026-33630, CVE-2026-69184, CVE-2026-69186 |
| libyang 3.12.2-1 | CVE-2026-44673 |
| util-linux 2.41.5-0+deb13u1 | CVE-2026-76642, CVE-2026-78408, CVE-2026-78409, CVE-2026-78410 |
| systemd 257.13-1~deb13u1 | CVE-2026-16742 |
| ACL 2.3.2-2+b1 | CVE-2026-54369 |
| ncurses 6.5+20250216-2 | CVE-2025-69720 |
| Perl 5.40.1-6+deb13u1 | CVE-2026-9538 |

This is a package inventory, not proof that every CVE is exploitable by a tenant.
Affected runtime paths and upstream/distribution fixes must still be reviewed
and validated; these findings are not suppressed or declared resolved. The
default image is **not security-cleared for release**. Separating the control
plane does not clear the network/VPN workload image. Images were built locally,
not published or deployed, and existing chart image pins were not release-bumped.

## Publication constraint

The OAuth token used to publish this draft lacks GitHub's `workflow` scope.
The published code matches the tested integration source, but the upstream
workflow files are kept unchanged. `docs/ci-verifier-hardening.patch` contains
the proposed CI change for maintainer review: make compilation/verifier loading
blocking and verify all entry programs in a private CI pin directory. The full
local integration includes it; the actual kernel checks above were run locally.
The patch also retains the feature stack's hosted VPN backend matrix and manual/
scheduled laboratory job. These e2e workflow changes are supplied for review;
their cluster acceptance jobs have not been run on this combined tree.
This draft's GitHub CI alone therefore does not enforce the proposed verifier gate.
The supplied patch uses zero context; apply it with
`git apply --unidiff-zero docs/ci-verifier-hardening.patch` after review.
