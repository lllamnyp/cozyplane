# Operator-managed VPC boundaries

This extension adds an optional boundary to VPCs without changing legacy VPC
behavior. The boundary is independent of the union of tenant SecurityGroups.
For cross-VPC traffic between two managed VPCs, these rules are authoritative:
tenant SecurityGroups cannot widen or narrow an imposed common path. Intra-VPC
traffic and legacy VPC pairs retain their SecurityGroup checks.
Only a principal granted the virtual `manage-boundary` verb on the VPC may set,
change or remove it. A managed VPC may not be deleted or have its CIDRs or MTU
changed without that grant. Metadata-only VPC updates remain permitted.

Derived VPCPeerings carrying `app.kubernetes.io/managed-by=neosequentia-portal`
require the virtual `manage-boundary` verb on `vpcpeerings` for creation,
modification and deletion. The check uses both the stored and requested label,
so removing the marker cannot bypass protection. Status updates preserve the
marker and spec while allowing controller observations. Ordinary peerings retain
the existing local-VPC `peer` consent and immutable-reference rules.

`spec.boundary` contains a content revision, an Internet permission and directed
peer rules. Peer rules identify a VPC by namespace and name, specify ingress or
egress, and admit TCP/UDP destination ports or an explicit ICMP type and code.
An empty rule set denies inter-VPC traffic. Reciprocal VPCPeering objects remain
necessary transport grants. A rule never creates a route or a peering.

The agent compiles the complete desired boundary into versioned maps, publishes
its revision only after all entries were written, and reports successful
application in VPC status for its current agent instance. Successful applications
are acknowledged with the exact VPC generation and a digest of its current
primary Port UID/IP set. A CIDR change or a primary attachment change invalidates
an earlier acknowledgement even when the policy content revision is unchanged.
Partial map writes must leave the previous revision live; first application remains closed until
complete. Capacity exhaustion is an error, never a shortened rule set.
Compilation rejects negative VNI values and malformed address masks before any
map publication. ICMP type/code packing preserves the validated eight-bit values.

Every cross-VPC packet is checked at source and destination, independently of
placement. TCP ACK without tracked admission is denied. UDP and ICMP replies
require a tracked forward flow. Flow state includes endpoint VNI and the current
boundary revisions, so replacing a policy invalidates established flows. State
at one hook cannot bypass admission at the other hook.

Internet permission gates outbound NAT and floating-IP paths before translation.
Secondary VM legs cannot originate Internet flows. DNS and the existing
node-origin probe bridge retain their separate, narrow plumbing exceptions.
Tenant forwarding legs are denied transit by a managed boundary unless future
policy explicitly supports it; forwarding grants do not bypass this boundary.

The portal must wait for all relevant agent instances to acknowledge the desired
revision before reporting application or completed revocation. Ready allocation
status and successful API writes are not dataplane acknowledgements. Regional
activation stays disabled until same-node/cross-node, IPv4/IPv6, forged ACK,
fragment, UDP/ICMP reply, revocation, secondary NIC, NAT/FloatingIP, migration,
agent restart and map-capacity tests pass on the target kernel.

## Existing pull requests

The integration checkout starts from #37 (which includes the #27 Multus NIC
identity work and preceding #24/#25 development) and incorporates current main.
#24/#25 final branch patches were compared and are already included in #37;
#23/#26 document the operator/service attachment model. #38 is flow telemetry,
#39 owns CNI conflist cleanup and #40 orders tcx hooks; both minimal patches are
included without reverting the current-main egress fixes. #38 remains an independent
pending pull request; this feature must state its dependencies and must not
copy uncommitted changes from another checkout into its patch.

CRD deployments must install `deploy/boundary-authz.yaml` alongside the existing
sharing admission policies. The chart includes the same fail-closed policies.

### Related ICMP errors

ICMPv4 destination unreachable, time exceeded and parameter problem, and ICMPv6 error types 1 through 4 are admitted only when the quoted TCP, UDP or echo tuple matches an already authorized conntrack entry in the opposite direction of the same hook. Both VNI, policy revisions and identities must still match. No new grant or conntrack entry is created. Fragmented, option-bearing, extended or truncated quoted packets are rejected.
## Managed gateway and default group ownership

Portal-derived VPCGateways and default SecurityGroups carry
`app.kubernetes.io/managed-by: neosequentia-portal`. Creating, editing,
removing that marker, or deleting these objects requires `manage-boundary`
on the corresponding resource. Both aggregated storage and CRD admission
enforce this ownership; `/status` preserves the stored marker and spec.
Tenant-created groups retain their existing permissions. The datapath boundary
continues to limit them independently.

## Controller permissions

The merged VPN implementation from #37 realizes Deployments and StatefulSets in
tenant namespaces. Its shared controller identity therefore retains cluster-wide
workload write permissions; the release namespace Role for VPCGateway workloads
does not constrain those additional grants. This boundary feature does not remove
VPN behavior or claim namespace-scoped controller writes. Separating the VPN and
VPCGateway controller identities is a prerequisite to reducing those privileges.

## Local verification and remaining gates

Code generation, all root Go tests, vet, the separate KPR tests and Linux arm64
build pass. The required isolated kernel lane loads the real BPF programs and
checks boundary packets; its continuation stubs do not prove NAT, FloatingIP,
Geneve or KubeVirt routing on a cluster. Those target tests remain required before
regional activation and are not represented as mock successes.

The Go vulnerability scan after updating OpenTelemetry to 1.45.0 reports no
called vulnerability; three imported-package and three required-module findings
without calls remain reported. The local production image has no fixed
HIGH/CRITICAL finding under the integration portal's existing Trivy ignore list.

The full gosec 2.29.0 scan reports 256 findings: 244 pre-existing findings and
twelve generated conversion-gen unsafe casts. The ten numeric findings added by
this extension were fixed with checked VNI/mask ranges and typed ProgramArray
values. The twelve generated casts have matching recursive field layouts and
round-trip conversion checks. This is a reviewed feature delta, not a globally
clean static scan or a security certification of the inherited VPN code.
