# Network flow observability for cozyplane (L3/L4 verdicts, reasons, and DNS)

- **Title:** `Network flow observability for cozyplane (L3/L4 verdicts, reasons, and DNS)`
- **Author(s):** `@lfinmauritius`
- **Date:** `2026-08-25`
- **Status:** Implemented (kind verifier/dev-cluster validation pending)

## Overview

cozyplane is the eBPF CNI variant that replaces kube-ovn **and** kube-proxy **and**
Cilium in a Cozystack cluster (the `cozyplane` networking variant; the default
`kubeovn-cilium` variant keeps Cilium). A cluster that selects cozyplane
therefore has **no Cilium and no Hubble** — and today no per-flow network
visibility at all: the datapath exposes only four aggregate counters
(`sg_drops`, `np_drops`, `hf_drops`, `ns_denied`), two of the most important
drop sites are entirely silent, and the anti-spoof drop is indistinguishable
from a policy deny.

This proposal adds Hubble-parity **L3/L4** observability to cozyplane: per-flow
events carrying a verdict and a reason, streamed from the datapath through a
ring buffer, enriched with VPC/pod identity, queryable from a CLI, and
aggregated into bounded Prometheus series — plus DNS metrics from the resolver
cozyplane already runs. It deliberately stops at L4: HTTP/Kafka/gRPC L7 stays
with Cilium/Hubble (the `kubeovn-cilium` variant), which cozyplane never
coexists with.

## Scope and related proposals

- **`distributed-tracing`** (OTLP application tracing) operates at a different
  layer — spans inside managed apps, not datapath packets. No overlap: this
  proposal answers "who talked to whom, and why was it allowed or denied",
  distributed-tracing answers "which statement was slow".
- **`coroot-ebpf-observability`** adds Coroot as an observability *platform*
  (service maps, traces, profiling) via its own node-agent eBPF, observing
  syscalls/sockets. It is complementary, not overlapping: Coroot cannot see
  cozyplane's *policy* decisions — a SecurityGroup / NetworkPolicy / isolation
  verdict and its reason live only in the CNI datapath. This proposal surfaces
  exactly those (the "why was this denied, by which rule" that a
  connectivity/policy operator needs), plus per-VPC DNS; Coroot answers the
  application/service-map question. The two can run together.
- **Cilium/Hubble**: out of scope by construction — cozyplane and Cilium are
  mutually exclusive networking variants. A cluster wanting Hubble's L7 runs
  `kubeovn-cilium`; this proposal is the equivalent for the cozyplane variant,
  scoped to what an L3/L4 eBPF CNI can see natively.
- Builds on cozyplane's existing datapath, metering (`vpc_counters`), and the
  split-horizon resolver.

## Decisions

_None yet. Implementation decisions that diverge from this proposal will be
recorded under `decisions/NNNN-*.md`._

## Context

cozyplane's datapath (`bpf/overlay.c`) is a set of tc/eBPF programs
(`from_pod`, `to_pod`, `from_overlay`, `from_uplink`, plus tail-called
`lb_ingress`/`lb_dsr`/`hf_ingress`/`hf_egress`). Traffic is keyed by VNI
(network id), addresses are 128-bit (NAT64-mapped v4, native v6), and policy is
enforced across three layers (SecurityGroups, NetworkPolicy at net-0,
HostFirewall). The agent is a per-node hostNetwork DaemonSet that already serves
`vpc_counters` as Prometheus text on `:9411/metrics`, and runs a second
unprivileged container (`responder`) that is the split-horizon DNS resolver —
it sees every VPC pod's cluster-DNS query.

The stack-heavy programs (`from_pod` sits at ~496 of the verifier's 512-byte
combined-stack limit) constrain what new logic can run inline; this shapes the
design below.

## The problem

On a cozyplane cluster an operator debugging connectivity has only aggregate
counters and `bpftool map dump`. "My pod cannot reach X" or "which policy
dropped this" cannot be answered. The two isolation drops
(`from_pod`/`to_pod`) increment no counter at all; the anti-spoof (RPF) drop is
folded into `sg_drops`. There is no equivalent of `hubble observe`, no flow
logs, no per-reason drop metrics, no DNS visibility.

## Goals

- **Per-flow events** with a verdict (allow/deny) and a reason (which gate),
  covering the policy/routing drop sites — including the two that are silent
  today and the anti-spoof drop as a distinct reason.
- **Allow verdicts per flow, never per packet** (bounded overhead).
- An **operator CLI** (`flowctl observe`) with table/JSON/follow output.
- **Bounded-cardinality Prometheus metrics**: `cozyplane_flows_total`
  (verdict/reason/direction/proto), plus port/tcp-flags/icmp distribution
  series and DNS query/response series — scrapable by Prometheus and
  VictoriaMetrics.
- **Off by default** (matching Cozystack's Hubble-disabled-by-default posture),
  independently toggleable, and **byte-identical datapath behaviour when off**
  (one array lookup per emit site).
- **Operator-only** surface; no tenant-facing API in v1.

## Non-goals

- L7 HTTP/Kafka/gRPC metrics (Cilium/Hubble territory; the `kubeovn-cilium`
  variant provides them).
- Per-packet TCP-flag/retransmit accounting — events are per-flow, so
  `tcp_flags` reflects the trigger packet only.
- A tenant-facing flow API (the `/ports` precedent applies; deferred).
- Any cryptographic or payload inspection.

## Design

### Event transport

A `BPF_MAP_TYPE_RINGBUF` (`flow_events`, 4 MiB), the repo's first. Chosen over
a perf array for global ordering and for `bpf_ringbuf_reserve`, which hands back
ring memory to write into directly — so emission needs no event struct on the
BPF stack (decisive under the 512-byte limit). A full ring returns NULL; a
one-slot `flow_lost` PERCPU counter is bumped and the packet proceeds. **Loss of
an event, never of a packet.**

### The event

A fixed 64-byte record: timestamp, src/dst (128-bit), src/dst VNI, ports,
proto, verdict, reason, hook, north-south door, flags, and — filled only on
admitted flows — `tcp_flags`/`icmp_type`/`icmp_code`. Reasons enumerate every
policy/routing gate: SG ingress/egress/north-south, NetworkPolicy
ingress/egress, HostFirewall ingress/egress, isolation, anti-spoof, LB-closed,
LB-source-range, no-gateway.

### Allow verdicts, per flow

An LRU `flow_seen` keyed by the 5-tuple. An allow event is emitted on a fresh
TCP SYN or an LRU miss; subsequent packets cost one lookup. Emission happens
where sanctioned accounting already runs (`count_dir` in `to_pod`, `count_ns`
on the north-south paths), using stack-free helpers. Every emit site is guarded
by a `CFG_FLOW_ENABLED` params lookup — one array read when disabled.

### Userspace pipeline (agent)

The privileged agent (the only container that can reach the bpffs-pinned ring
FD) drains the ring, enriches each event — VNI→VPC via the VPC lister,
address→pod via the Port/FabricIP claim objects (never tenant-set metadata) —
keeps a bounded in-memory ring, and aggregates metrics. `direction`
(ingress/egress) is derived in userspace from the reason and hook, so it needs
no datapath change.

### Metrics (bounded cardinality)

```
cozyplane_flows_total{verdict, reason, direction, proto, vpc_namespace, vpc, node}
cozyplane_flow_port_distribution_total{port, proto, direction, ...}   # ephemeral bucketed; ≤128 ports/group then "other"
cozyplane_flow_tcp_flags_total{flag, direction, ...}                  # admitted flows, per-flow (SYN-dominated)
cozyplane_flow_icmp_total{family, type, code, direction, ...}         # ≤128 type/code per group then "other"
cozyplane_flow_events_lost_total{node}
```

No IP, pod, or raw ephemeral-port label. A per-`{proto,direction,vni}` cap of
128 distinct port (and ICMP type/code) series folds the rest into an `"other"`
bucket, so a tenant port-scan cannot mint unbounded series.

### DNS (the one L7 slice, no proxy)

The resolver already sees every steered VPC query. It counts, on its own
`:9413/metrics`:

```
cozyplane_dns_queries_total{qtype, vpc_namespace, vpc, node}
cozyplane_dns_responses_total{rcode, vpc_namespace, vpc, node}
```

qtype/rcode are bucketed to `"other"` for unknowns; **no domain name** appears
in any label. It sees only queries steered to the cluster DNS (the common k8s
case), not a pod dialing `8.8.8.8` directly.

## User-facing changes

- **CLI** `cozyplane-flowctl observe [--follow] [--vpc] [--namespace]
  [--verdict] [--reason] [--since] [--json] [--node]` — reads each node's raw
  flow endpoint (loopback-only) by `kubectl exec` into the agent (`pods/exec`,
  an operator verb).
- **New metric families** on `:9411/metrics` (agent) and `:9413/metrics`
  (resolver).
- **Chart values** (all off by default):
  ```yaml
  observability:
    flows: false       # flow events, /flows, cozyplane_flow_* on :9411
    dnsMetrics: false  # cozyplane_dns_* on :9413
  ```

## Upgrade and rollback compatibility

Off by default; enabling adds ~14 MiB of map memlock per node (the ring buffer
+ the dedup LRU), visible in `cozyplane_bpf_map_memlock_bytes`. The two new maps
are created cleanly through the existing map-ABI reconcile path — no migration.
Disabling is immediate and returns the datapath to byte-identical behaviour;
rollback is removing the two flags.

## Security

- **Operator-only.** The raw `/flows` endpoint carries cross-tenant addresses,
  so it is bound to the node loopback (`127.0.0.1:9412`) inside the hostNetwork
  agent's namespace — unreachable from any pod's own netns — and reached only
  by `kubectl exec` into the agent (`pods/exec` RBAC, which no tenant role
  holds). This rests on the standard platform invariant that tenants cannot
  schedule hostNetwork pods (they run restricted/baseline Pod Security).
- **Metrics carry no identity beyond VPC namespace/name**: no IP, no pod, no
  domain, and bounded cardinality (the 128/group cap) so a tenant scan cannot
  drive a metrics-cardinality DoS.
- **Enrichment is unforgeable**: identity comes from the allocator-written
  Port/FabricIP claim objects, never from tenant labels/annotations.
- No new tenant RBAC; the existing `cozyplane-tenant-{edit,view}` aggregates are
  untouched.

## Failure and edge cases

- **Ring full**: events lost and counted (`cozyplane_flow_events_lost_total`),
  never a packet drop, never a block.
- **Enrichment miss** (Port not yet synced): event served with empty
  identity, never dropped.
- **Verifier budget**: the L4 capture is confined to one function on the allow
  path; kind's 6.8 kernel verifier is the gate. Fallback is a tail-call slot.
- **Toggle off mid-flight**: emit sites short-circuit on the config lookup; the
  agent stops serving `/flows` and the flow metrics; connectivity unaffected.

## Testing

- **Unit**: 64-byte record decode/offset parity, direction derivation, the
  cardinality cap, DNS qtype/rcode bucketing.
- **e2e** (kind, real cluster): three pods across two VPCs (one dual-homed),
  internet egress, cross SSH, a SecurityGroup deny — asserting enriched allow
  flows, `reason=sg_ingress` and `reason=isolation` denies (the drop that is
  silent today becoming visible is the acceptance test), the direction label,
  the three distribution series with the cap saturating under a port scan, and
  the DNS series. Prometheus **and** VictoriaMetrics scrape and query all
  families.
- Verifier load on kind 6.8 is CI's gate.

## Rollout

1. Datapath: ring buffer, dedup LRU, reason enum, `CFG_FLOW_ENABLED`, emission
   at the policy/routing sites (denies first).
2. Agent pipeline: reader, enrichment, `/flows` loopback, `cozyplane_flows_total`.
3. Allow verdicts + the three distribution series (direction, port, tcp_flags,
   icmp) with the cardinality cap.
4. `flowctl`.
5. DNS metrics from the resolver.
6. Chart toggles + e2e, both off by default.

## Open questions

- Should a later increment add a **tenant-facing** "my drops" surface? It must
  be re-litigated against the dropped-`/ports` precedent (identity, not
  addresses) — likely per-SecurityGroup deny counters projected into the
  namespace, never a raw flow list.
- Per-packet `tcp_flags` (RST/retransmit view) would need a separate per-packet
  path; deferred unless demand appears.
- A central flow aggregator/relay (vs per-node exec fan-out) — a scale question
  for later.

## Alternatives considered

- **Perf event array instead of a ring buffer**: rejected — per-CPU ordering
  and no reserve-in-place API (the stack budget makes the latter decisive).
- **Run Cilium in chaining/observe-only mode alongside cozyplane just for
  Hubble**: rejected — it reintroduces the daemon cozyplane exists to remove,
  and defeats the lean posture; a cluster wanting Hubble picks `kubeovn-cilium`.
- **A transparent per-node Envoy for L7 (Cilium-style)**: rejected — violates
  cozyplane's "no box on the east-west fast path" tenet, carries a large
  xDS/verifier cost, and duplicates Cilium's mature work. L7, if a tenant needs
  it, is a steered appliance (see the site-connectivity backend proposal), not
  a datapath feature.
- **High-cardinality Hubble-style port labels**: rejected in favour of the
  bounded 128/group cap, preserving the "no unbounded tenant-driven series"
  property.
