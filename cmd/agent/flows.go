// Copyright 2026 The cozyplane Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Flow observability, the userspace half (docs/observability.md): a reader
// goroutine drains the flow_events ring buffer, enriches each raw record with
// VPC and pod identity from listers the agent already runs (VPCs by VNI; the
// Port name IS v<vni>.<ip>, the FabricIP name IS the escaped address — both
// O(1) Gets, no new watch, no indexer), keeps a bounded in-memory ring, and
// serves it on a loopback-only server (127.0.0.1:9412) as /flows (JSON) and
// /flows/stream (NDJSON). This runs in the agent — the ring buffer FD lives
// behind the bpffs pin, which only the privileged container reaches.
//
// This surface shows raw addresses across tenants: it is OPERATOR-facing (R9),
// bound to the node loopback so no pod can reach it, and read only by an
// operator exec-ing into the agent (cozyplane-flowctl). The aggregate
// cozyplane_flow_* series stay on the agent's :9411/metrics.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/labels"

	sdnnames "github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/datapath"
	locallisters "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/listers/localsdn/v1alpha1"
	sdnlisters "github.com/lllamnyp/cozyplane/pkg/generated/sdn/listers/sdn/v1alpha1"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
)

const (
	flowRingSize      = 4096 // enriched records kept for /flows
	flowSubBuffer     = 256  // per-subscriber channel depth; a slow reader loses events, never blocks the pipeline
	flowVNICacheTTL   = 2 * time.Second
	flowDefaultLimit  = 1000
	flowMaxSinceHours = 24
	// maxSeriesPerGroup hard-caps how many distinct port (or ICMP type/code)
	// series one {proto,direction,vni} group may mint. Past it, new values fold
	// into an "other" bucket — so a tenant port-scan (or a crafted ICMP flood)
	// cannot drive unbounded cardinality into the scrape target, and the
	// in-memory maps stay bounded. Real workloads touch a handful of service
	// ports, far under the cap; the cap only bites an adversary.
	maxSeriesPerGroup = 128
	// flowLoopbackAddr is where the RAW flow endpoints live: the node's own
	// loopback, in the hostNetwork agent's (== the node's) net namespace. A
	// tenant pod in its own netns cannot reach it — this is what makes the
	// surface "unreachable from pods by construction" true, not aspirational
	// (docs/observability.md §7; the security review that moved it here). The
	// operator reaches it by `kubectl exec` into the agent (pods/exec RBAC),
	// which runs in this same netns; cozyplane-flowctl does exactly that.
	// The AGGREGATE cozyplane_flows_total stays on :9411/metrics for scraping —
	// bounded cardinality, no raw addresses, safe for a monitoring surface.
	flowLoopbackAddr = "127.0.0.1:9412"
)

// flowPeer is one side of a flow, as served.
type flowPeer struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port,omitempty"`
	VNI  uint32 `json:"vni,omitempty"`
	VPC  string `json:"vpc,omitempty"` // namespace/name
	Pod  string `json:"pod,omitempty"` // namespace/name
}

// flowRecord is one enriched datapath flow event, the JSON the endpoints and
// flowctl speak.
type flowRecord struct {
	Time      time.Time `json:"time"`
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason"`
	Hook      string    `json:"hook"`
	Door      string    `json:"door,omitempty"`
	Proto     string    `json:"proto"`
	Src       flowPeer  `json:"src"`
	Dst       flowPeer  `json:"dst"`
	Direction string    `json:"direction"`
	SYN       bool      `json:"syn,omitempty"`
	Forwarded bool      `json:"forwarded,omitempty"`
	TCPFlags  []string  `json:"tcp_flags,omitempty"` // admitted TCP flows only (per-flow)
	ICMPType  *uint8    `json:"icmp_type,omitempty"` // admitted ICMP flows only
	ICMPCode  *uint8    `json:"icmp_code,omitempty"`
	Node      string    `json:"node"`
}

type flowMetricKey struct {
	verdict   string
	reason    string
	proto     string
	direction string
	vni       uint32
}

// portKey / tcpFlagKey / icmpKey are the bounded-cardinality distribution
// series (docs/observability.md §5). None carries a raw address.
type portKey struct {
	port      string // dport, or "ephemeral" for >=32768
	proto     string
	direction string
	vni       uint32
}
type tcpFlagKey struct {
	flag      string
	direction string
	vni       uint32
}
type icmpKey struct {
	family    string
	typ       string // ICMP type, or "other" once the per-group cap is hit
	code      string // ICMP code, or "other" likewise
	direction string
	vni       uint32
}

// seriesGroup identifies a cardinality-capped family of distribution series:
// the port distribution and the ICMP distribution each cap distinct values per
// {kind, proto/family, direction, vni}.
type seriesGroup struct {
	kind      string // "port" or "icmp"
	sub       string // proto (port) or family (icmp)
	direction string
	vni       uint32
}

type flowPipeline struct {
	mgr     *datapath.Manager
	vpcs    sdnlisters.VPCLister
	ports   sdnlisters.PortLister
	fabrics locallisters.FabricIPLister
	node    string
	log     *slog.Logger

	// bootWall anchors bpf_ktime_get_ns (CLOCK_MONOTONIC) to wall time.
	bootWall time.Time

	mu       sync.Mutex
	ring     []flowRecord
	head     int // next write position
	filled   bool
	metrics  map[flowMetricKey]uint64
	portDist map[portKey]uint64
	tcpFlags map[tcpFlagKey]uint64
	icmp     map[icmpKey]uint64
	groupN   map[seriesGroup]int // distinct series minted per group, for the cap
	subs     map[chan flowRecord]struct{}
	vniNames map[uint32]string
	vniAt    time.Time
}

func newFlowPipeline(mgr *datapath.Manager, vpcs sdnlisters.VPCLister, ports sdnlisters.PortLister,
	fabrics locallisters.FabricIPLister, node string, log *slog.Logger) *flowPipeline {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return &flowPipeline{
		mgr:      mgr,
		vpcs:     vpcs,
		ports:    ports,
		fabrics:  fabrics,
		node:     node,
		log:      log,
		bootWall: time.Now().Add(-time.Duration(ts.Nano())),
		ring:     make([]flowRecord, flowRingSize),
		metrics:  map[flowMetricKey]uint64{},
		portDist: map[portKey]uint64{},
		tcpFlags: map[tcpFlagKey]uint64{},
		icmp:     map[icmpKey]uint64{},
		groupN:   map[seriesGroup]int{},
		subs:     map[chan flowRecord]struct{}{},
	}
}

// run drains the ring buffer until ctx ends. Decode or enrichment trouble
// never drops the pipeline — a flow with empty identity beats no flow.
func (fp *flowPipeline) run(ctx context.Context) {
	rd, err := ringbuf.NewReader(fp.mgr.FlowEventsMap())
	if err != nil {
		fp.log.Error("flow reader init", "err", err)
		return
	}
	go func() {
		<-ctx.Done()
		_ = rd.Close()
	}()
	fp.log.Info("flow observability armed", "endpoints", "/flows /flows/stream")
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			fp.log.Warn("flow read", "err", err)
			continue
		}
		e, err := datapath.DecodeFlowEvent(rec.RawSample)
		if err != nil {
			fp.log.Warn("flow decode", "err", err)
			continue
		}
		fp.ingest(&e)
	}
}

func (fp *flowPipeline) ingest(e *datapath.FlowEvent) {
	dir := e.Direction()
	r := flowRecord{
		Time:      fp.bootWall.Add(time.Duration(e.TS)),
		Verdict:   e.VerdictName(),
		Reason:    e.ReasonName(),
		Hook:      e.HookName(),
		Door:      e.DoorName(),
		Proto:     protoName(e.Proto),
		Direction: dir,
		SYN:       e.Flags&datapath.FlowFlagSYN != 0,
		Forwarded: e.Flags&datapath.FlowFlagFwd != 0,
		TCPFlags:  e.TCPFlagNames(),
		Node:      fp.node,
		Src: flowPeer{
			IP:   e.Src.String(),
			Port: e.Sport,
			VNI:  e.SrcNet,
			VPC:  fp.vpcName(e.SrcNet),
			Pod:  fp.podName(e.SrcNet, e.Src.String()),
		},
		Dst: flowPeer{
			IP:   e.Dst.String(),
			Port: e.Dport,
			VNI:  e.DstNet,
			VPC:  fp.vpcName(e.DstNet),
			Pod:  fp.podName(e.DstNet, e.Dst.String()),
		},
	}
	isICMP := e.Proto == 1 || e.Proto == 58
	if isICMP && (e.ICMPType != 0 || e.ICMPCode != 0) {
		t, c := e.ICMPType, e.ICMPCode
		r.ICMPType, r.ICMPCode = &t, &c
	}

	// Attribute the metric to the tenant net: the destination's when it has
	// one, the source's otherwise — the same lean the deny counters have.
	vni := e.DstNet
	if vni == 0 {
		vni = e.SrcNet
	}
	k := flowMetricKey{verdict: r.Verdict, reason: r.Reason, proto: metricProto(e.Proto), direction: dir, vni: vni}

	fp.mu.Lock()
	fp.ring[fp.head] = r
	fp.head = (fp.head + 1) % len(fp.ring)
	if fp.head == 0 {
		fp.filled = true
	}
	fp.metrics[k]++
	// Distribution series — bounded cardinality, no addresses (§5). The port
	// and ICMP families are capped per group so a tenant scan cannot mint
	// unbounded series (see maxSeriesPerGroup).
	if e.Proto == 6 || e.Proto == 17 { // TCP/UDP: port distribution
		label := portLabel(e.Dport)
		if label != "ephemeral" { // ephemeral is already one bucket; don't cap it
			label = fp.capLabel(seriesGroup{kind: "port", sub: r.Proto, direction: dir, vni: vni},
				label, func() bool {
					_, ok := fp.portDist[portKey{port: label, proto: r.Proto, direction: dir, vni: vni}]
					return ok
				})
		}
		fp.portDist[portKey{port: label, proto: r.Proto, direction: dir, vni: vni}]++
	}
	for _, f := range r.TCPFlags {
		fp.tcpFlags[tcpFlagKey{flag: f, direction: dir, vni: vni}]++
	}
	if isICMP {
		typ, code := strconv.Itoa(int(e.ICMPType)), strconv.Itoa(int(e.ICMPCode))
		g := seriesGroup{kind: "icmp", sub: r.Proto, direction: dir, vni: vni}
		if fp.capLabel(g, typ+"/"+code, func() bool {
			_, ok := fp.icmp[icmpKey{family: r.Proto, typ: typ, code: code, direction: dir, vni: vni}]
			return ok
		}) == "other" {
			typ, code = "other", "other"
		}
		fp.icmp[icmpKey{family: r.Proto, typ: typ, code: code, direction: dir, vni: vni}]++
	}
	for ch := range fp.subs {
		select {
		case ch <- r:
		default: // a slow stream reader loses events, never blocks ingest
		}
	}
	fp.mu.Unlock()
}

// portLabel folds ephemeral ports (>=32768) into one bucket, so a client's
// source-port spread cannot blow up the series count on its own. Low ports are
// further capped per group by capLabel.
func portLabel(port uint16) string {
	if port >= 32768 {
		return "ephemeral"
	}
	return strconv.Itoa(int(port))
}

// capLabel enforces the per-group distinct-series cap. It returns the label
// unchanged while the group is under the cap (or the label is already a known
// series), and "other" once the group is full — so an adversary minting new
// values lands in a single bucket instead of a new series each. exists reports
// whether this exact label already has a series (which never counts against the
// cap). Caller holds fp.mu.
func (fp *flowPipeline) capLabel(g seriesGroup, label string, exists func() bool) string {
	if label == "other" || exists() {
		return label
	}
	if fp.groupN[g] >= maxSeriesPerGroup {
		return "other"
	}
	fp.groupN[g]++
	return label
}

// vpcName resolves a VNI to "namespace/name" through a briefly-cached view of
// the VPC lister (the serveMetrics pattern, amortized per event burst).
func (fp *flowPipeline) vpcName(vni uint32) string {
	if vni == 0 {
		return ""
	}
	fp.mu.Lock()
	if time.Since(fp.vniAt) > flowVNICacheTTL {
		names := map[uint32]string{}
		if all, err := fp.vpcs.List(labels.Everything()); err == nil {
			for _, v := range all {
				if v.Status.VNI != 0 {
					names[uint32(v.Status.VNI)] = v.Namespace + "/" + v.Name
				}
			}
		}
		fp.vniNames, fp.vniAt = names, time.Now()
	}
	n := fp.vniNames[vni]
	fp.mu.Unlock()
	return n
}

// podName resolves an address to its pod: by Port claim name inside a VPC, by
// FabricIP claim name on the default network. Identity comes from the claim
// objects the allocators wrote — never from anything a tenant can label.
func (fp *flowPipeline) podName(vni uint32, ip string) string {
	if vni != 0 {
		if p, err := fp.ports.Get(sdnnames.PortName(int32(vni), ip)); err == nil && p.Spec.PodName != "" {
			return p.Spec.PodNamespace + "/" + p.Spec.PodName
		}
		return ""
	}
	if f, err := fp.fabrics.Get(localv1alpha1.FabricIPName(ip)); err == nil && f.Spec.PodName != "" {
		return f.Spec.PodNamespace + "/" + f.Spec.PodName
	}
	return ""
}

// protoName renders a protocol for the /flows record — the real number for an
// exotic protocol, since the record is operator-only and ring-bounded.
func protoName(p uint8) string {
	if s := knownProto(p); s != "" {
		return s
	}
	return strconv.Itoa(int(p))
}

// metricProto renders a protocol for a METRIC label, folding anything outside
// the known set into "other" so a tenant emitting arbitrary IP-proto numbers
// cannot mint up to 256 distinct proto series in cozyplane_flows_total.
func metricProto(p uint8) string {
	if s := knownProto(p); s != "" {
		return s
	}
	return "other"
}

func knownProto(p uint8) string {
	switch p {
	case unix.IPPROTO_TCP:
		return "tcp"
	case unix.IPPROTO_UDP:
		return "udp"
	case unix.IPPROTO_ICMP:
		return "icmp"
	case unix.IPPROTO_ICMPV6:
		return "icmpv6"
	case unix.IPPROTO_SCTP:
		return "sctp"
	}
	return ""
}

// snapshot returns the ring's records in chronological order.
func (fp *flowPipeline) snapshot() []flowRecord {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	if !fp.filled {
		out := make([]flowRecord, fp.head)
		copy(out, fp.ring[:fp.head])
		return out
	}
	out := make([]flowRecord, len(fp.ring))
	n := copy(out, fp.ring[fp.head:])
	copy(out[n:], fp.ring[:fp.head])
	return out
}

// ---- HTTP ------------------------------------------------------------------

var flowTokenRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

type flowFilter struct {
	verdict, reason string
	vpc, namespace  string
	since           time.Duration
	limit           int
}

// parseFlowFilter validates every query parameter strictly: a malformed value
// is a 400, never a guess and never a panic.
func parseFlowFilter(q map[string][]string) (flowFilter, error) {
	f := flowFilter{limit: flowDefaultLimit}
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if v := get("verdict"); v != "" {
		if v != "allow" && v != "deny" {
			return f, fmt.Errorf("verdict must be allow or deny")
		}
		f.verdict = v
	}
	if v := get("reason"); v != "" {
		if !flowTokenRe.MatchString(v) {
			return f, fmt.Errorf("invalid reason")
		}
		f.reason = v
	}
	if v := get("vpc"); v != "" {
		if len(v) > 512 || strings.ContainsAny(v, "\n\r") {
			return f, fmt.Errorf("invalid vpc")
		}
		f.vpc = v
	}
	if v := get("namespace"); v != "" {
		if len(v) > 253 || strings.ContainsAny(v, "\n\r/") {
			return f, fmt.Errorf("invalid namespace")
		}
		f.namespace = v
	}
	if v := get("since"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 || d > flowMaxSinceHours*time.Hour {
			return f, fmt.Errorf("since must be a duration up to %dh", flowMaxSinceHours)
		}
		f.since = d
	}
	if v := get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > flowRingSize {
			return f, fmt.Errorf("limit must be 1..%d", flowRingSize)
		}
		f.limit = n
	}
	return f, nil
}

func (f *flowFilter) match(r *flowRecord, now time.Time) bool {
	if f.verdict != "" && r.Verdict != f.verdict {
		return false
	}
	if f.reason != "" && r.Reason != f.reason {
		return false
	}
	if f.vpc != "" && r.Src.VPC != f.vpc && r.Dst.VPC != f.vpc {
		return false
	}
	if f.namespace != "" {
		p := f.namespace + "/"
		if !strings.HasPrefix(r.Src.Pod, p) && !strings.HasPrefix(r.Dst.Pod, p) &&
			!strings.HasPrefix(r.Src.VPC, p) && !strings.HasPrefix(r.Dst.VPC, p) {
			return false
		}
	}
	if f.since > 0 && now.Sub(r.Time) > f.since {
		return false
	}
	return true
}

// serveLoopback runs the RAW flow endpoints on the node loopback only, so no
// pod can reach them over the network; the operator reaches them by exec-ing
// into the agent. This is a SEPARATE server from :9411 (which stays bound to
// all interfaces for metric scraping) — the two ports never share a bind.
func (fp *flowPipeline) serveLoopback(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/flows", fp.handleFlows)
	mux.HandleFunc("/flows/stream", fp.handleStream)
	srv := &http.Server{Addr: flowLoopbackAddr, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		fp.log.Info("serving raw flow endpoints (loopback, operator-only via exec)", "addr", flowLoopbackAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fp.log.Warn("flow endpoint server", "err", err)
		}
	}()
}

func (fp *flowPipeline) handleFlows(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	all := fp.snapshot()
	now := time.Now()
	out := make([]flowRecord, 0, min(len(all), f.limit))
	// Newest last; when over limit, keep the newest.
	for _, rec := range all {
		if f.match(&rec, now) {
			out = append(out, rec)
		}
	}
	if len(out) > f.limit {
		out = out[len(out)-f.limit:]
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (fp *flowPipeline) handleStream(w http.ResponseWriter, r *http.Request) {
	f, err := parseFlowFilter(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	ch := make(chan flowRecord, flowSubBuffer)
	fp.mu.Lock()
	fp.subs[ch] = struct{}{}
	fp.mu.Unlock()
	defer func() {
		fp.mu.Lock()
		delete(fp.subs, ch)
		fp.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/x-ndjson")
	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case rec := <-ch:
			if !f.match(&rec, time.Now()) {
				continue
			}
			if err := enc.Encode(rec); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// writeMetrics appends the flow-derived Prometheus series to the /metrics
// exposition. Cardinality is bounded by construction: every label set is
// verdict/reason/proto/direction/flag/family/type/bucketed-port × VPCs — no
// IP, no pod, no raw ephemeral port (docs/observability.md §5).
func (fp *flowPipeline) writeMetrics(b *strings.Builder, names map[uint32][2]string) {
	fp.mu.Lock()
	flows := make(map[flowMetricKey]uint64, len(fp.metrics))
	for k, v := range fp.metrics {
		flows[k] = v
	}
	ports := make(map[portKey]uint64, len(fp.portDist))
	for k, v := range fp.portDist {
		ports[k] = v
	}
	tcpf := make(map[tcpFlagKey]uint64, len(fp.tcpFlags))
	for k, v := range fp.tcpFlags {
		tcpf[k] = v
	}
	icmp := make(map[icmpKey]uint64, len(fp.icmp))
	for k, v := range fp.icmp {
		icmp[k] = v
	}
	fp.mu.Unlock()

	fmt.Fprintf(b, "# HELP cozyplane_flows_total Datapath flow events (one per flow, this node).\n# TYPE cozyplane_flows_total counter\n")
	for k, v := range flows {
		id := names[k.vni]
		fmt.Fprintf(b, "cozyplane_flows_total{verdict=%q,reason=%q,proto=%q,direction=%q,vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.verdict, k.reason, k.proto, k.direction, k.vni, id[0], id[1], fp.node, v)
	}

	fmt.Fprintf(b, "# HELP cozyplane_flow_port_distribution_total New flows by destination port (ephemeral ports bucketed, this node).\n# TYPE cozyplane_flow_port_distribution_total counter\n")
	for k, v := range ports {
		id := names[k.vni]
		fmt.Fprintf(b, "cozyplane_flow_port_distribution_total{port=%q,proto=%q,direction=%q,vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.port, k.proto, k.direction, k.vni, id[0], id[1], fp.node, v)
	}

	fmt.Fprintf(b, "# HELP cozyplane_flow_tcp_flags_total Admitted TCP flows by flag, from the trigger packet (per-flow, this node).\n# TYPE cozyplane_flow_tcp_flags_total counter\n")
	for k, v := range tcpf {
		id := names[k.vni]
		fmt.Fprintf(b, "cozyplane_flow_tcp_flags_total{flag=%q,direction=%q,vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.flag, k.direction, k.vni, id[0], id[1], fp.node, v)
	}

	fmt.Fprintf(b, "# HELP cozyplane_flow_icmp_total Admitted ICMP flows by type and code (this node).\n# TYPE cozyplane_flow_icmp_total counter\n")
	for k, v := range icmp {
		id := names[k.vni]
		fmt.Fprintf(b, "cozyplane_flow_icmp_total{family=%q,type=%q,code=%q,direction=%q,vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q} %d\n",
			k.family, k.typ, k.code, k.direction, k.vni, id[0], id[1], fp.node, v)
	}

	if lost, err := fp.mgr.FlowLostCount(); err == nil {
		fmt.Fprintf(b, "# HELP cozyplane_flow_events_lost_total Flow events dropped by a full ring buffer (this node).\n# TYPE cozyplane_flow_events_lost_total counter\n")
		fmt.Fprintf(b, "cozyplane_flow_events_lost_total{node=%q} %d\n", fp.node, lost)
	}
}
