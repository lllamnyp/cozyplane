# Flow observability — design (flow events, verdicts, reasons)

**Status: implemented in this branch — increments 1-4 are complete; increment 5 has chart and e2e coverage, with kind verifier/dev-cluster validation pending.**

cozyplane can say *that* it dropped and *how much* crossed, but never *what*: the
kernel's only outputs today are four aggregate counters (`sg_drops`,
`np_drops[dir]`, `hf_drops[dir]`, `vpc_counters.ns_denied[door]`), all scoped by
net or direction. Two of the most consequential drop sites are entirely silent —
the isolation checks in `from_pod` and `to_pod` count nothing at all — and the
anti-spoof drop is folded into `sg_drops`, indistinguishable from a policy deny.
Debugging is `bpftool map dump` plus `dmesg` (`docs/bringup-field-notes.md`).

This document adds **flow events**: a fixed-size record per flow decision —
allow or deny, with a reason — streamed from the datapath through a ring buffer
to the agent, enriched with VPC/pod identity, queryable from a CLI, and
aggregated into Prometheus series. Operator-facing only (§7).

## 0. Tenets, applied

1. **Observability never pays on the packet path.** Disabled, the feature is one
   array lookup per decision site (the `CFG_HF_ENABLED` idiom: "one array lookup
   when disabled; behaviour byte-identical to today"). Enabled, allow-verdicts
   are per-*flow*, never per-packet, and a full ring buffer loses *events*, never
   packets.
2. **The datapath states facts; userspace names them.** The kernel emits
   `{addresses, nets, verdict, reason}` — raw identity primitives. VPC names,
   namespaces, and pods are joined in the agent from the objects that already
   carry them (the `serveMetrics` VNI→VPC pattern, the responder's
   address→pod indexer pattern). An enrichment miss leaves fields empty; it
   never drops the event.
3. **Attribution extends, it does not replace.** The four existing counters and
   every `cozyplane_vpc_*` series keep their exact semantics. Flow events are a
   new signal beside them — including, at last, a signal for the drops that
   today have none.
4. **Identity, not addresses — and this surface is full of addresses.** So it is
   an *operator* surface, on the operator side of the R9 split, like
   `HostFirewall`. No tenant kind, no tenant endpoint, no tenant RBAC change.
   §7 records what a future tenant-facing increment must re-litigate.

## 1. The event

One record, 64 bytes, fixed layout — `struct flow_event` in `bpf/overlay.c`,
mirrored by `datapath/flowevent.go` (decoded at fixed offsets; a unit test pins
size and offsets):

```c
struct flow_event {
    __u64 ts;            // bpf_ktime_get_ns
    struct addr128 src;  // NAT64-mapped, as everywhere in the datapath
    struct addr128 dst;
    __u32 srcnet;        // VNI (0 = default/fabric network)
    __u32 dstnet;
    __u16 sport, dport;  // network order
    __u8  proto;
    __u8  verdict;       // 0 allow, 1 deny
    __u8  reason;        // enum flow_reason, below
    __u8  hook;          // which program observed it
    __u8  door;          // NS door when applicable, 0xff otherwise
    __u8  flags;         // bit0 SYN, bit1 forwarded (FWD_MARK), bit2 north-south (NS_MARK)
    __u8  tcp_flags;     // admitted flows only; trigger packet's raw flags
    __u8  icmp_type;     // admitted ICMP/ICMPv6 flows only
    __u8  icmp_code;
    __u8  _pad[3];       // explicit — ring memory is not zeroed on reserve
};
```

`door` is sized for growth: the VPN proposal (`docs/vpn.md` §6) adds an
`appliance` door; the event ABI must not need a rebuild for it.

**Reasons** — every deny names the gate that refused it:

```
FR_ALLOW        FR_SG_INGRESS   FR_SG_EGRESS   FR_SG_NS
FR_NP_INGRESS   FR_NP_EGRESS    FR_HF_INGRESS  FR_HF_EGRESS
FR_ISOLATION    FR_SPOOF        FR_LB_CLOSED   FR_LB_SRCRANGE
FR_NO_GATEWAY   (reserved: FR_MALFORMED, FR_INFRA — v2)
```

v1 instruments the ~20 policy/routing drop sites — every SecurityGroup gate
(east-west, egress, north-south), both NetworkPolicy gates, all three
HostFirewall gates, both silent isolation checks, the anti-spoof drop (finally
distinct from a policy deny), the closed LB door, LoadBalancer source-range
refusal, and the closed-island no-gateway drops. The ~30 malformed-packet and
encap-failure sites are deferred: less debugging value, partial context, real
noise potential.

## 2. Transport — the repo's first ring buffer

`flow_events`, a `BPF_MAP_TYPE_RINGBUF` of 4 MiB (~65k events), pinned at
`/sys/fs/bpf/cozyplane/flow_events` like every other map. Ring buffer over perf
array for three reasons: one buffer with global ordering instead of per-CPU
streams; a reservation API — `bpf_ringbuf_reserve` hands back ring memory to
write into directly, so emission needs **no event struct on the BPF stack**
(the 544 lesson made that a hard requirement in `from_pod`, which sits at 496
of 512 combined-stack bytes); and built-in backpressure — a full ring returns
NULL, we bump a one-slot `flow_lost` PERCPU counter and move on. Observability
never blocks or drops a packet.

Emission helpers follow the counter discipline exactly: `noinline
flow_emit_*()` twins of `count_dir`/`count_sg_drop` for `to_pod` and the
tail-called programs (which have callee budget), `__always_inline` variants
with pointer-direct stores for `from_pod`'s terminal paths (which host no
callee). Every site is guarded by `cfg(CFG_FLOW_ENABLED)` — params slot 11.

## 3. Allow verdicts — per flow, not per packet

A new `flow_seen` LRU_HASH (131072 entries) keyed
`{srcnet, dstnet, src, dst, proto, sport, dport}`. An allow event is emitted
when the packet is a TCP SYN (and not ACK), or when the tuple misses the LRU;
either way the tuple is (re)inserted. LRU eviction is the TTL — long-lived
flows re-announce themselves when evicted, which is a feature. Subsequent
packets of a known flow cost one LRU lookup.

Emission points are where sanctioned accounting already runs. v1 instruments
the `count_dir` delivery point in `to_pod` (east-west — every admitted tenant
flow, net-0-to-net-0 excluded like the meters exclude it) and the gateway-door
egress branch in `from_pod`. The EIP/NAT door allow-events follow with the e2e
that can actually exercise them (`test/e2e.sh`'s repair — those doors need an
external address to attract, which kind cannot). Denies always emit (drops are
rare by construction; no dedup).

Cost, honestly: enabled, one LRU lookup per packet on the counted paths plus a
reserve/submit on new flows; disabled, one array lookup. Memlock grows by
~14 MiB per node (ring 4 MiB + LRU ~10 MiB), visible where all map memory
already is — `cozyplane_bpf_map_memlock_bytes`. The chart default is therefore
**off** (`flows.enabled: false` → agent `--flows` → `SetFlowEnabled`).

## 4. Userspace — in the agent, nowhere else

The ring buffer FD lives behind the bpffs pin, so the reader runs in the
privileged agent container (the responder's unprivileged pattern cannot reach
it). New `cmd/agent/flows.go`:

- a `ringbuf.NewReader` goroutine (`cilium/ebpf` is already the module's core
  dependency — no new module; the `kpr/` separate-module bar is nowhere near
  met);
- enrichment from informers the agent already runs: VNI→`{vpc_namespace, vpc}`
  via the VPC lister (the `serveMetrics` pattern), address→pod via the
  `fabricIPIndex`/`podUIDIndex` indexers the responder already demonstrates
  (`cmd/responder/main.go`) — added to the agent's existing informers, zero new
  watches;
- a bounded in-memory ring of the last 4096 enriched flows;
- a **loopback-only** server, `127.0.0.1:9412`, serving `GET /flows` (JSON,
  filterable by `vpc`, `namespace`, `verdict`, `reason`, `since`) and
  `GET /flows/stream` (NDJSON, for `--follow`). It carries raw cross-tenant
  addresses, so it is bound to the node's loopback inside the hostNetwork
  agent's (== the node's) net namespace: no pod in its own netns can reach it.
  The operator reaches it by `kubectl exec` into the agent — which runs in that
  same netns — gated by `pods/exec` RBAC that no tenant role carries. This is
  what makes "unreachable from pods" a structural fact rather than an
  aspiration (§7). The **aggregate** `cozyplane_flows_total` is separate: it
  stays on the all-interfaces `:9411/metrics`, because it is bounded and
  address-free and a monitoring stack must scrape it.

## 5. Metrics — flows as Prometheus series

Aggregated in the agent from the event stream, served on the existing
`/metrics` (hand-rolled exposition, as ever):

```
cozyplane_flows_total{verdict, reason, direction, proto, vpc_namespace, vpc, node}
cozyplane_flow_port_distribution_total{port, proto, direction, vpc_namespace, vpc, node}
cozyplane_flow_tcp_flags_total{flag, direction, vpc_namespace, vpc, node}
cozyplane_flow_icmp_total{family, type, code, direction, vpc_namespace, vpc, node}
cozyplane_flow_events_lost_total{node}
```

Cardinality is bounded by construction — every label is a small fixed set
(verdict, reason, direction, proto, flag, ICMP family/type/code) or a
bucketed port, times the VPCs. **No IP, no pod, no raw ephemeral port.**
Fine-grained identity lives in events, not in series. Notes on the four
distribution families:

- **`direction`** (`ingress`/`egress`) is derived in userspace from the
  reason (which names the gate's side) and, where the reason is side-neutral
  (isolation, spoof, allow), from the observing hook — so it costs no datapath
  change.
- **`port`** is the destination port; a client ephemeral port (`>= 32768`)
  collapses to the bucket `"ephemeral"`. That alone does not bound a scan of
  *destination* ports, so a second guard caps the distinct port series per
  `{proto, direction, vni}` group at 128 — past it, new ports fold into an
  `"other"` bucket. A real workload touches a handful of service ports, far
  under the cap; only an adversary's port scan hits it, and it can then mint no
  new series at all (the count stops growing). The ICMP family is capped the
  same way on `{type, code}`. TCP/UDP only for the port series. (A prior
  revision emitted one series per low port; a security review proved a tenant
  port-scan could mint ~32k series into the shared scrape target — hence the
  cap.)
- **`tcp_flags`** and **`icmp`** carry L4 detail captured **only on admitted
  flows** (the allow path fills the event's `tcp_flags`/`icmp_type`/`icmp_code`
  from the trigger packet). Two honest limits: it is **per-flow, not
  per-packet** — the trigger is a SYN for a new TCP flow, so `tcp_flags` is
  SYN-dominated and is not Hubble's per-packet RST/retransmit view; and a
  **denied** flow carries no L4 detail (it is still counted in `flows_total`
  by `reason`). SYN+ACK collapses to one `syn-ack` series.

The silent-drop gaps close as `reason=isolation` and `reason=spoof` series;
the four BPF counters stay untouched as the historical source of the existing
metrics.

**DNS (the one L7 slice, from the resolver — §D).** cozyplane runs no L7 proxy
and deliberately does not chase Hubble's HTTP/Kafka/gRPC metrics: that is
Cilium's job, and a cluster wanting it runs Cozystack's `kubeovn-cilium`
variant (cozyplane and Cilium never coexist). The one exception is DNS, which
is nearly free: the split-horizon resolver (`internal/responder`) already sees
every steered VPC query. It serves, on its own `:9413/metrics` (a distinct
port — the agent holds `:9411`/`:9412` in the shared hostNetwork namespace):

```
cozyplane_dns_queries_total{qtype, vpc_namespace, vpc, node}
cozyplane_dns_responses_total{rcode, vpc_namespace, vpc, node}
```

Bounded (qtype and rcode are small fixed sets, bucketed to `"other"` for
unknowns), and **never a domain name** in a label. Limit: it counts only
queries steered to the cluster DNS — the common k8s case — not a pod dialing
`8.8.8.8` directly.

## 6. The CLI — `flowctl`

`cmd/flowctl`, built into the image (one Dockerfile line, one COPY) and
`make build`:

```
flowctl observe [--follow] [--vpc ns/name] [--namespace ns] [--verdict allow|deny]
                [--reason X] [--since 5m] [--node N] [--json]
```

With `--node`, it reads one agent; without, it fans out over the DaemonSet's
pods and merges by timestamp. It reaches each agent's loopback flow endpoint by
`kubectl exec`-ing a `wget` inside the agent container (the endpoint is not
network-reachable — §4), so it needs `pods/exec` in the agent namespace: the
operator's own verb, carried by no tenant role. Output is a table
(`TIME VERDICT REASON VPC SRC→DST PROTO PORT NODE`) or NDJSON. No relay, no
gRPC, no kubectl plugin in v1 — a central aggregator is a v2 question that
scale, not design, will answer.

## 7. Multi-tenancy

This surface shows raw addresses across tenants; per R9 it is operator-only,
like `HostFirewall`. R2 is untouched — no new kind, no tenant role change. The
raw endpoints are bound to the node loopback and reached only by `kubectl exec`
into the agent (`pods/exec`, an operator verb) — a pod in its own netns cannot
reach `127.0.0.1:9412` at all, so the surface is unreachable by construction,
not by policy. (This rests on the standard platform invariant that a tenant
cannot schedule a `hostNetwork` pod — one that could, sharing the node netns,
would reach the loopback endpoint; but such a tenant has already escaped VPC
isolation wholesale, of which the flow endpoint is a negligible part. Tenant
namespaces run `restricted`/`baseline` Pod Security, which forbids it.) (An earlier revision served it on the all-interfaces `:9411`; a
security review proved a default-network pod, and any VPC pod through its
gateway NAT, could read it — hence the loopback move. The aggregate
`cozyplane_flows_total` that remains on `:9411/metrics` is bounded and carries
no addresses.) The `/ports`
precedent (`docs/control-plane.md`: a tenant-facing address list is "a surface
we defend forever") applies in full to any future tenant-facing increment:
"show me my drops" will have to be argued in identity terms — most plausibly
per-SecurityGroup deny counters projected into the namespace — never as a raw
flow list. Out of scope here; recorded so nobody discovers it mid-review.

## 8. Increments

1. **[DONE] Datapath, denies first**: `flow_events` + `flow_seen` + reason enum +
   `CFG_FLOW_ENABLED` + `flow_lost`, emission at the ~20 policy/routing sites.
   Gate: the kind 6.8 verifier. Documented plan B if `from_pod`'s stack breaks:
   a fifth tail-call slot (`lb_prog` 4→5).
2. **[DONE] Agent pipeline**: reader, indexers, enrichment, memory ring, `/flows` +
   `/flows/stream`, `cozyplane_flows_total`.
3. **[DONE] Allow verdicts**: SYN/LRU dedup and L4 detail on admitted flows.
4. **[DONE] `flowctl`**: node-local access, filtering, follow mode and fan-out.
5. **[PARTIAL] Chart + e2e**: `flows.enabled` and a vpc-e2e phase asserting an
   enriched allow, a `reason=sg_ingress` deny, and the bounded Prometheus series
   are built. The kind verifier/dev-cluster run and an explicit
   `reason=isolation` assertion remain the merge gates.

Deferred to v2, explicitly: malformed/infra reasons, an aggregating relay, any
tenant-facing surface, sampling (params slot 12 reserved).

## 9. Risks

The verifier is the first risk and the reason denies land before allows:
`from_pod` emission must survive 6.8 with pointer-direct stores only, measured
in increment 1, with the tail-call escape hatch named in advance. Event loss
under a new-flow burst is accepted and counted, never blocking. New BPF code is
GPL-2.0 in `bpf/`, compiled object committed and `go:embed`'d via
`make generate`, as always. `flow_seen`/`flow_events` are new maps — clean
creation through the existing `MapSpec.Compatible` rebuild path, no migration,
one-release-gap rule applies as usual.
