# CRD distribution

The requested CRD distribution must provide the same eleven tenant kinds,
group/version, scopes, status subresources and admission contract as the
aggregated distribution. A namespace does not isolate this choice. A fresh
regional cluster is required for the first recipe; switching a populated
cluster during Helm upgrade is unsupported.

The `api.mode` is `aggregated` (existing default) or `crd`. CRD mode
installs structural schemas generated from `api/sdn/v1alpha1`, the required
export/peer/boundary admission policies and a validating webhook. It does not
install the tenant APIService, aggregated server or its dedicated etcd.
FabricIP remains independently served by the local group for bootstrap.

Helm lookup is only a connected preflight. CRD mode also installs a fail-closed
ValidatingAdmissionPolicy/Binding Deny on APIService CREATE/UPDATE, rejecting a
remote service for the tenant group while allowing its native local
autoregistration and unrelated groups. This stops an old aggregated server's
registration/recovery loop from redirecting CRD traffic later. It does not
repair an already populated mixed-mode cluster: the fresh-cluster prerequisite
and inventory before installation remain mandatory.

The webhook reuses existing Go strategies through scheme conversion. Its real
SubjectAccessReviews use AdmissionReview user identity; it fails closed on
authorization errors. It is bounded in request size and execution time,
uses TLS, has no mutation side effects and does not intercept its own bootstrap
resources. CREATE/UPDATE/status/DELETE and cross-kind conflict responses must
match the aggregated contract. Native CRD status handling must preserve spec
and ownership metadata in actual kube-apiserver tests.

The TLS listener must reload the mounted serving certificate after Secret
rotation without restarting the webhook. Check file metadata at most once per
minute under a shared lock and load only a changed pair; never log certificate
key material. A malformed rotated pair fails TLS closed until repaired. No
background watch, per-handshake disk reads or unbounded certificate cache is
needed. A real local TLS handshake with two generated synthetic certificates
must prove rotation and failure/recovery.

VNI/group allocation remains in the controllers, IP allocation in CNI and
ServiceVIP controllers. Same-kind claims are serialized by name uniqueness.
The existing cross-kind GET is not an atomic reservation; retain its conflict
filter and Port-wins repair and test concurrent allocation without promising
a stronger guarantee. Claim names must encode canonical IPv6 addresses into
valid DNS subdomains, including compression at the beginning/end. Mixed
versions and existing claims require an explicit compatibility procedure.

Retain every already valid legacy claim name. Canonical IPv6 addresses whose
legacy escaped suffix starts or ends with a hyphen use `x` followed by the
32 lowercase hex digits of the address instead. `x` cannot begin a legacy
numeric IPv4 or hexadecimal IPv6 suffix, so these encodings cannot collide.
Such legacy names are invalid CRD DNS metadata names, but the old aggregated
server's PathSegmentName validation could store them. No automatic renaming or
populated-cluster mode switch is supported. Before upgrading a legacy lab,
inventory its claims by name using the normal client (no credentials output),
reject malformed claims, and upgrade all allocators/agents together before
allowing new edge-compressed IPv6 claims. Existing valid VM identities keep
their names. Old allocators must not run alongside the new encoding.

Bootstrap retains the existing two-chart dependency sequence. The CNI chart
installs FabricIP, tenant CRDs and fail-closed webhook/policies first. It installs
no tenant admission Pod or cert-manager kinds that could block CNI readiness.
FabricIP/default-network bootstrap does not match the webhook. Install
cert-manager, then `cozyplane-apiserver` with the same namespace and `api.mode`.
In CRD mode that second chart installs only the admission TLS service/RBAC and
certificates, without aggregated server/etcd. Before phase two, tenant writes
must fail while bootstrap/default-network Pods can run. Standalone fixtures can
precreate TLS and pass existingSecret+public caBundle to both charts.

The two PackageSources expose matching `default` (aggregated) and `crd`
variants. Select `crd` for both in the regional bundle before first installation.
The networking variant still has no package dependency; the CRD control-plane
variant depends only on cert-manager, with no dedicated etcd/storage dependency.
Both apply their chart's `values-crd.yaml` overlay. A connected Helm preflight
rejects a second chart whose mode differs from the CNI's recorded mode.

The recipe must cover all kinds, discovery, schemas/pruning, CRUD/watch/patch,
SSA, dry-run, typed errors, quotas, hostile status writes, required policies,
webhook failure, controller allocation/repair, namespace cleanup and cluster
scoped claims. A distinct regional dataplane recipe must then cover CNI,
DNS/ServiceVIP/FloatingIP, IPv4/IPv6, revocation and VM primary migration with
durable rollback and complete fixture cleanup.

Select an explicitly disposable cluster with `CRD_RECIPE_KUBECONFIG`. The
admission fixture namespace defaults to `b195-crd`; set
`CRD_RECIPE_NAMESPACE` when the two charts were installed in another namespace.
The recipe checks that namespace's recorded CRD mode before any writes or
admission outage. Pause the fixture's chart reconciliation and tenant controller
for this API-only recipe, then restore both for the separate controller tests.
Its HostFirewall selects a generated fixture label that must match no node,
so testing CRUD cannot change the lab's host firewall policy.

Status: implementation under review. The dedicated Kubernetes 1.35.5 API
fixture exercises all eleven kinds, status preservation, typed errors, export/
peer permissions, managed objects, native quota, IPv6 claim names and the
persistent APIService guard. It also stops/restores the admission Deployment:
tenant CREATE/UPDATE/status/DELETE fail closed, tenant reads and FabricIP/core
bootstrap remain available, and real tenant admission recovers. Its seventeen
subtests pass in 30.70 seconds, including collection DELETE and observed fixture
namespace removal. This API fixture retains KindNet and does not
certify the CNI, controller lifecycle or regional KubeVirt migration recipe.

A separate fresh three-node Kind cluster with default CNI disabled boots the
actual Cozyplane image before cert-manager/admission: three nodes and CoreDNS
are Ready, FabricIP claims exist and a tenant CREATE fails closed on the absent
admission Service. This proves the first bootstrap phase, not Talos/KubeVirt
certification. The default image pins still require a published artifact with
the admission binary before this draft can be treated as an installable release.

The second phase has also booted on that CNI with cert-manager v1.20.2 and the
default chart TLS path: both CA/serving Certificates are Ready and both admission
replicas roll out. No precreated serving Secret or copied private key is used
for this phase. Controller/dataplane/VM certification remains outstanding.

Collection DELETE AdmissionReviews can have an empty request name while the
old object carries the individual identity. Accept that case only for DELETE,
with a nonempty old name and the same namespace/scope checks. Managed-object
authorization still uses the old object's concrete name. Prove collection
deletion on the real API and wait for the fixture namespace to disappear;
issuing a namespace DELETE alone is not cleanup proof.
