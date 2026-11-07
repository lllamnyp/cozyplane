/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localapply "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/applyconfiguration/localsdn/v1alpha1"
	localclientset "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned"
	localinformers "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/informers/externalversions"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
)

// egressConfig is the agent's VPC egress tuning (docs/vpc-egress.md §4.2, §4.3).
type egressConfig struct {
	flowQuota     uint
	timeouts      datapath.NATTimeouts
	sweepEvery    time.Duration
	pressureEvery time.Duration
}

var egressCfg = egressConfig{
	flowQuota:     32768,
	timeouts:      datapath.DefaultNATTimeouts,
	sweepEvery:    30 * time.Second,
	pressureEvery: 2 * time.Second,
}

// bindEgressFlags registers the egress flags; called before flag.Parse.
func bindEgressFlags() {
	flag.UintVar(&egressCfg.flowQuota, "nat-vpc-flow-quota", egressCfg.flowQuota,
		"live NAT flows one VPC may hold on this node; 0 = no limit")
	flag.DurationVar(&egressCfg.timeouts.TCPEstablished, "nat-tcp-established-timeout", egressCfg.timeouts.TCPEstablished,
		"idle timeout of an established NAT TCP flow")
	flag.DurationVar(&egressCfg.timeouts.TCPTransitory, "nat-tcp-transitory-timeout", egressCfg.timeouts.TCPTransitory,
		"idle timeout of a NAT TCP flow that is opening or closing")
	flag.DurationVar(&egressCfg.timeouts.UDP, "nat-udp-timeout", egressCfg.timeouts.UDP,
		"idle timeout of a NAT UDP flow")
	flag.DurationVar(&egressCfg.timeouts.ICMP, "nat-icmp-timeout", egressCfg.timeouts.ICMP,
		"idle timeout of a NAT ICMP echo flow")
}

// ---- planning: pure functions of the objects --------------------------------

// vpcKey identifies a VPC by namespace and name.
type vpcKey struct{ ns, name string }

// canonicalCIDR returns a CIDR's canonical string, or "" if it does not parse.
func canonicalCIDR(c string) string {
	p, err := netip.ParsePrefix(c)
	if err != nil {
		return ""
	}
	return p.Masked().String()
}

// planRoutes compiles vpc_routes for the given tables (docs/vpc-egress.md §3.1):
// each table gets its VPC's local CIDR, the peer CIDRs, and its Routes. At equal
// prefix, local wins over a Route, and a Route over a peer route. A Route the
// controller has not resolved yet is programmed as unresolved, so its traffic
// never falls to a shorter route; a Conflict loser is not programmed.
func planRoutes(tables []*sdnv1alpha1.RouteTable, routes []*sdnv1alpha1.Route,
	vpcs map[vpcKey]*sdnv1alpha1.VPC, peerCIDRs map[uint32][]string,
	natgwID map[vpcKey]uint32) []datapath.Route {
	byTable := map[vpcKey][]*sdnv1alpha1.Route{}
	for _, r := range routes {
		k := vpcKey{r.Namespace, r.Spec.RouteTableRef.Name}
		byTable[k] = append(byTable[k], r)
	}
	var out []datapath.Route
	for _, t := range tables {
		vpc := vpcs[vpcKey{t.Namespace, t.Spec.VPCRef.Name}]
		if t.Status.ID <= 0 || vpc == nil || vpc.Status.VNI == 0 {
			continue
		}
		id := uint32(t.Status.ID)
		entries := map[string]datapath.Route{}
		for _, c := range peerCIDRs[uint32(vpc.Status.VNI)] {
			if cc := canonicalCIDR(c); cc != "" {
				entries[cc] = datapath.Route{Table: id, CIDR: cc, Kind: datapath.RoutePeer}
			}
		}
		for _, r := range byTable[vpcKey{t.Namespace, t.Name}] {
			cc := canonicalCIDR(r.Spec.Destination)
			if cc == "" || r.Status.State == sdnv1alpha1.RouteStateConflict {
				continue
			}
			e := datapath.Route{Table: id, CIDR: cc, Kind: datapath.RouteUnresolved}
			if r.Status.State == sdnv1alpha1.RouteStateActive {
				switch tg := r.Spec.Target; {
				case tg.NATGateway != nil:
					if gid := natgwID[vpcKey{r.Namespace, tg.NATGateway.Name}]; gid != 0 {
						e.Kind, e.NATGateway = datapath.RouteNAT, uint16(gid)
					}
				case tg.Internet != nil:
					e.Kind = datapath.RouteInternet
				case tg.Blackhole != nil:
					e.Kind = datapath.RouteBlackhole
				}
			}
			entries[cc] = e
		}
		// Only the first CIDR is operational (the networks map holds it alone).
		if len(vpc.Spec.CIDRs) > 0 {
			if cc := canonicalCIDR(vpc.Spec.CIDRs[0]); cc != "" {
				entries[cc] = datapath.Route{Table: id, CIDR: cc, Kind: datapath.RouteLocal}
			}
		}
		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, entries[k])
		}
	}
	return out
}

// portTableOf returns the route table id of a Port: the table its pod named,
// else the VPC's default table; 0 means none (docs/vpc-egress.md §2.4). A pod
// that names a missing table, or another VPC's, gets none.
func portTableOf(p *sdnv1alpha1.Port, tables []*sdnv1alpha1.RouteTable) uint32 {
	var mine []*sdnv1alpha1.RouteTable
	for _, t := range tables {
		if t.Namespace == p.Spec.VPCRef.Namespace && t.Spec.VPCRef.Name == p.Spec.VPCRef.Name {
			mine = append(mine, t)
		}
	}
	if name := p.Spec.RouteTable; name != "" {
		for _, t := range mine {
			if t.Name == name && t.Status.ID > 0 {
				return uint32(t.Status.ID)
			}
		}
		return 0
	}
	if d := sdnv1alpha1.EffectiveDefaultTable(mine, p.Spec.VPCRef.Name); d != nil && d.Status.ID > 0 {
		return uint32(d.Status.ID)
	}
	return 0
}

// natPlan is what the agent programs and does for NAT gateways.
type natPlan struct {
	gateways map[uint32]datapath.NATGateway
	owners   map[datapath.NATBlock]net.IP
	// ack lists the leases this node has not acked in its current boot.
	ack []string
	// activate lists this node's leases every Ready node has now acked, to be
	// marked active (sticky, docs/vpc-egress.md §4.3).
	activate map[string]bool
	// claim lists NAT gateways this node should claim one more block of.
	claim []*sdnv1alpha1.NATGateway
	// release lists this node's leases to delete.
	release []string
	// active counts this node's active blocks per NAT gateway id.
	active map[uint32]int
}

// natInputs are planNAT's inputs.
type natInputs struct {
	self      string
	natgws    []*sdnv1alpha1.NATGateway
	vpcs      map[vpcKey]*sdnv1alpha1.VPC
	leases    []*localv1alpha1.NATPortBlock
	ready     map[string]string        // Ready nodes -> boot ID ("" = unknown)
	selfBoot  string                   // this node's boot ID
	nodeIP    func(name string) net.IP // Geneve endpoint of a node, self included
	hosted    map[vpcKey]bool          // VPCs with a Port on this node
	more      map[uint32]bool          // NAT gateway ids under allocation pressure
	idleSince map[types.UID]time.Time  // when this node stopped hosting a NAT gateway's VPC
	pending   map[types.UID]time.Time  // claims made that the cache does not show yet
	live      map[datapath.NATBlock]bool
	// blockIdle is when each of this node's blocks last held no live flow.
	blockIdle map[datapath.NATBlock]time.Time
	now       time.Time
	idleGrace time.Duration
}

// extraBlockIdle is how long a block beyond a node's first must hold no live
// flow before the node releases it while still hosting the VPC.
const extraBlockIdle = 10 * time.Minute

// planNAT decides nat_gw, nat_blk_owner, and the lease work (docs/vpc-egress.md
// §4.3): every node programs every NAT gateway and every lease's owner; a node
// allocates only from its blocks that are active, which a block becomes once
// every Ready node has acked it in its current boot, and then stays.
func planNAT(in natInputs) natPlan {
	plan := natPlan{
		gateways: map[uint32]datapath.NATGateway{},
		owners:   map[datapath.NATBlock]net.IP{},
		activate: map[string]bool{},
		active:   map[uint32]int{},
	}
	byUID := map[types.UID]*sdnv1alpha1.NATGateway{}
	for _, g := range in.natgws {
		byUID[g.UID] = g
	}
	mine := map[types.UID][]*localv1alpha1.NATPortBlock{}
	for _, l := range in.leases {
		g := byUID[l.Spec.NATGatewayRef.UID]
		if g == nil || g.Status.ID <= 0 {
			continue
		}
		if ip := in.nodeIP(l.Spec.Node); ip != nil {
			plan.owners[datapath.NATBlock{NATGateway: uint32(g.Status.ID), Block: uint16(l.Spec.Block)}] = ip
		}
		acked := false
		for _, a := range l.Status.Acks {
			if a.Node == in.self && (in.selfBoot == "" || a.BootID == in.selfBoot) {
				acked = true
			}
		}
		if !acked && in.nodeIP(l.Spec.Node) != nil {
			plan.ack = append(plan.ack, l.Name)
		}
		if l.Spec.Node == in.self {
			mine[g.UID] = append(mine[g.UID], l)
		}
	}
	for _, g := range in.natgws {
		vpc := in.vpcs[vpcKey{g.Namespace, g.Spec.VPCRef.Name}]
		if g.Status.ID <= 0 || vpc == nil || vpc.Status.VNI == 0 || g.Status.BlockSize <= 0 {
			continue
		}
		id := uint32(g.Status.ID)
		leases := mine[g.UID]
		sort.Slice(leases, func(i, j int) bool { return leases[i].Spec.Block < leases[j].Spec.Block })
		var blocks []uint16
		for _, l := range leases {
			active := l.Status.Active
			if !active && ackedByAll(l, in.ready) {
				active = true
				plan.activate[l.Name] = true
			}
			if active && len(blocks) < datapath.NATGatewayBlocks {
				blocks = append(blocks, uint16(l.Spec.Block))
			}
		}
		plan.active[id] = len(blocks)
		plan.gateways[id] = datapath.NATGateway{
			V4: g.Status.Address, V6: g.Status.Address6,
			Net: uint32(vpc.Status.VNI), BlockSize: uint16(g.Status.BlockSize), Blocks: blocks,
		}
		hosted := in.hosted[vpcKey{g.Namespace, g.Spec.VPCRef.Name}]
		if at, ok := in.pending[g.UID]; ok && in.now.Sub(at) < claimSettle {
			continue // a claim is in flight; the cache has not shown it yet
		}
		switch {
		case hosted && len(leases) == 0:
			plan.claim = append(plan.claim, g)
		case hosted && in.more[id] && len(leases) < datapath.NATGatewayBlocks:
			plan.claim = append(plan.claim, g)
		case hosted:
			// Keep the first block; release extra ones that have held no
			// flow for extraBlockIdle, so a burst does not hold blocks
			// for good.
			for _, l := range leases[1:] {
				b := datapath.NATBlock{NATGateway: id, Block: uint16(l.Spec.Block)}
				at, ok := in.blockIdle[b]
				if c := l.CreationTimestamp.Time; c.After(at) {
					at = c // a block claimed afresh starts idle at its claim
				}
				if ok && !in.live[b] && in.now.Sub(at) >= extraBlockIdle {
					plan.release = append(plan.release, l.Name)
				}
			}
		case !hosted:
			since, ok := in.idleSince[g.UID]
			if !ok || in.now.Sub(since) < in.idleGrace {
				continue
			}
			for _, l := range leases {
				if !in.live[datapath.NATBlock{NATGateway: id, Block: uint16(l.Spec.Block)}] {
					plan.release = append(plan.release, l.Name)
				}
			}
		}
	}
	sort.Strings(plan.ack)
	sort.Strings(plan.release)
	return plan
}

// claimSettle is how long a claim waits for the informer to show it before the
// agent may claim again.
const claimSettle = 30 * time.Second

// ackedByAll reports whether every Ready node has acked a lease in its current
// boot. A node whose boot ID is unknown counts with an ack of any boot.
func ackedByAll(l *localv1alpha1.NATPortBlock, ready map[string]string) bool {
	acked := map[string]string{}
	for _, a := range l.Status.Acks {
		acked[a.Node] = a.BootID
	}
	for n, boot := range ready {
		got, ok := acked[n]
		if !ok || (boot != "" && got != boot) {
			return false
		}
	}
	return true
}

// freeBlock returns the lowest block of a NAT gateway no lease holds, or -1.
func freeBlock(g *sdnv1alpha1.NATGateway, leases []*localv1alpha1.NATPortBlock, skip map[int]bool) int {
	held := map[int]bool{}
	for _, l := range leases {
		if l.Spec.NATGatewayRef.UID == g.UID {
			held[int(l.Spec.Block)] = true
		}
	}
	for b := 0; b < localv1alpha1.NATBlocks(int(g.Status.BlockSize)); b++ {
		if !held[b] && !skip[b] {
			return b
		}
	}
	return -1
}

// ---- the watcher -------------------------------------------------------------

// egressMetricsSnapshot is what the metrics handler serves for VPC egress.
type egressMetricsSnapshot struct {
	natgwName  map[uint32][3]string // id -> {namespace, name, VPC}
	vpcName    map[uint32][2]string // net -> {namespace, name}
	flows      map[uint32]uint32
	active     map[uint32]int
	stats      map[uint32]map[string]uint64
	routeDrops map[uint32]map[string]uint64
}

var egressMetrics atomic.Pointer[egressMetricsSnapshot]

// egressWatcher programs route tables and NAT gateways and drives the leases.
type egressWatcher struct {
	mgr     *datapath.Manager
	lc      localclientset.Interface
	nodes   *nodePoolIndex
	nodeIPs *nodeIPIndex
	self    string
	selfIP  net.IP
	log     *slog.Logger

	sdn   sdninformers.SharedInformerFactory
	local localinformers.SharedInformerFactory

	kick chan struct{}

	mu      sync.Mutex
	live    map[datapath.NATBlock]bool
	flows   map[uint32]uint32 // natgw id -> live flows on this node
	pending map[types.UID]time.Time
	// pendingName is the lease each pending claim created, so the claim stops
	// holding back the next one as soon as the cache shows it.
	pendingName map[types.UID]string
	blockIdle   map[datapath.NATBlock]time.Time
	pressure    map[uint32]uint64 // natgw id -> deep+exhausted seen
	more        map[uint32]bool
	idleSince   map[types.UID]time.Time
	active      map[uint32]int
}

// watchEgress starts the VPC egress watcher (docs/vpc-egress.md §6).
func watchEgress(ctx context.Context, sdn sdninformers.SharedInformerFactory, local localinformers.SharedInformerFactory,
	lc localclientset.Interface, mgr *datapath.Manager, nodes *nodePoolIndex, nodeIPs *nodeIPIndex,
	self, selfIP string, log *slog.Logger) {
	w := &egressWatcher{
		mgr: mgr, lc: lc, nodes: nodes, nodeIPs: nodeIPs, self: self, selfIP: net.ParseIP(selfIP),
		log: log.With("component", "egress"), sdn: sdn, local: local,
		kick:        make(chan struct{}, 1),
		live:        map[datapath.NATBlock]bool{},
		pressure:    map[uint32]uint64{},
		more:        map[uint32]bool{},
		idleSince:   map[types.UID]time.Time{},
		pending:     map[types.UID]time.Time{},
		pendingName: map[types.UID]string{},
		blockIdle:   map[datapath.NATBlock]time.Time{},
	}
	if err := mgr.ClearLegacyVPCNAT(); err != nil {
		w.log.Warn("clear legacy VPC NAT maps", "err", err)
	}
	if err := mgr.SetNATFlowQuota(uint32(egressCfg.flowQuota)); err != nil {
		w.log.Error("set NAT flow quota", "err", err)
	}
	v := sdn.Sdn().V1alpha1()
	poke := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { w.poke() },
		UpdateFunc: func(_, _ any) { w.poke() },
		DeleteFunc: func(any) { w.poke() },
	}
	synced := []cache.InformerSynced{}
	for _, inf := range []cache.SharedIndexInformer{
		v.NATGateways().Informer(), v.RouteTables().Informer(), v.Routes().Informer(),
		v.VPCs().Informer(), v.VPCPeerings().Informer(), v.Ports().Informer(),
		local.Local().V1alpha1().NATPortBlocks().Informer(),
	} {
		_, _ = inf.AddEventHandler(poke)
		synced = append(synced, inf.HasSynced)
	}
	nodes.onChange(w.poke)
	local.Start(ctx.Done())

	go func() {
		if !cache.WaitForCacheSync(ctx.Done(), synced...) {
			return
		}
		sweep := time.NewTicker(egressCfg.sweepEvery)
		pressure := time.NewTicker(egressCfg.pressureEvery)
		defer sweep.Stop()
		defer pressure.Stop()
		w.resync(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.kick:
				w.resync(ctx)
			case <-sweep.C:
				w.sweep()
				w.resync(ctx)
			case <-pressure.C:
				if w.checkPressure() {
					w.resync(ctx)
				}
			}
		}
	}()
}

func (w *egressWatcher) poke() {
	select {
	case w.kick <- struct{}{}:
	default:
	}
}

func (w *egressWatcher) nodeIP(name string) net.IP {
	if name == w.self {
		return w.selfIP
	}
	return w.nodeIPs.get(name)
}

// resync programs the maps from the objects and does the lease work.
func (w *egressWatcher) resync(ctx context.Context) {
	v := w.sdn.Sdn().V1alpha1()
	natgws, err1 := v.NATGateways().Lister().List(labels.Everything())
	tables, err2 := v.RouteTables().Lister().List(labels.Everything())
	routes, err3 := v.Routes().Lister().List(labels.Everything())
	vpcList, err4 := v.VPCs().Lister().List(labels.Everything())
	peerings, err5 := v.VPCPeerings().Lister().List(labels.Everything())
	ports, err6 := v.Ports().Lister().List(labels.Everything())
	leases, err7 := w.local.Local().V1alpha1().NATPortBlocks().Lister().List(labels.Everything())
	for _, err := range []error{err1, err2, err3, err4, err5, err6, err7} {
		if err != nil {
			w.log.Error("list egress objects", "err", err)
			return
		}
	}

	vpcs := map[vpcKey]*sdnv1alpha1.VPC{}
	for _, vp := range vpcList {
		vpcs[vpcKey{vp.Namespace, vp.Name}] = vp
	}
	natgwID := map[vpcKey]uint32{}
	for _, g := range natgws {
		if g.Status.ID > 0 {
			natgwID[vpcKey{g.Namespace, g.Name}] = uint32(g.Status.ID)
		}
	}
	peerCIDRs := map[uint32][]string{}
	for _, l := range desiredPeerLinks(peerings, func(ns, name string) *sdnv1alpha1.VPC { return vpcs[vpcKey{ns, name}] }) {
		peerCIDRs[l.a] = append(peerCIDRs[l.a], l.cidrB)
		peerCIDRs[l.b] = append(peerCIDRs[l.b], l.cidrA)
	}

	// The VPCs this node hosts a Port of, and their Ports' tables.
	hosted := map[vpcKey]bool{}
	portTables := map[datapath.PortTable]uint32{}
	for _, p := range ports {
		if p.Spec.Node != w.self || !p.DeletionTimestamp.IsZero() {
			continue
		}
		k := vpcKey{p.Spec.VPCRef.Namespace, p.Spec.VPCRef.Name}
		vpc := vpcs[k]
		if vpc == nil || vpc.Status.VNI == 0 {
			continue
		}
		hosted[k] = true
		if t := portTableOf(p, tables); t != 0 {
			portTables[datapath.PortTable{Net: uint32(vpc.Status.VNI), IP: p.Spec.IP}] = t
		}
	}
	var hostedTables []*sdnv1alpha1.RouteTable
	for _, t := range tables {
		if hosted[vpcKey{t.Namespace, t.Spec.VPCRef.Name}] {
			hostedTables = append(hostedTables, t)
		}
	}
	if err := w.mgr.SyncRoutes(planRoutes(hostedTables, routes, vpcs, peerCIDRs, natgwID)); err != nil {
		w.log.Error("sync vpc_routes", "err", err)
	}
	if err := w.mgr.SyncPortTables(portTables); err != nil {
		w.log.Error("sync port_rt", "err", err)
	}

	w.mu.Lock()
	now := time.Now()
	// A claim the cache already shows no longer holds back the next one, so
	// under sustained pressure the agent claims a block per pressure poll
	// rather than one per claimSettle.
	seen := map[string]bool{}
	for _, l := range leases {
		seen[l.Name] = true
	}
	for uid, name := range w.pendingName {
		if seen[name] {
			delete(w.pending, uid)
			delete(w.pendingName, uid)
		}
	}
	for _, g := range natgws {
		if hosted[vpcKey{g.Namespace, g.Spec.VPCRef.Name}] {
			delete(w.idleSince, g.UID)
		} else if _, ok := w.idleSince[g.UID]; !ok {
			w.idleSince[g.UID] = now
		}
	}
	plan := planNAT(natInputs{
		self: w.self, natgws: natgws, vpcs: vpcs, leases: leases,
		ready: w.nodes.readyBoots(), selfBoot: w.nodes.bootID(w.self), nodeIP: w.nodeIP, hosted: hosted,
		more: w.more, idleSince: w.idleSince, pending: w.pending, live: w.live, blockIdle: w.blockIdle,
		now: now, idleGrace: egressCfg.timeouts.TCPEstablished,
	})
	w.active = plan.active
	for _, g := range plan.claim {
		delete(w.more, uint32(g.Status.ID))
	}
	w.mu.Unlock()

	// The owner table first: a lease is acked only once its owner is
	// programmed here, and a block is used only once every node has acked.
	if err := w.mgr.SyncNATBlockOwners(plan.owners); err != nil {
		w.log.Error("sync nat_blk_owner", "err", err)
		return
	}
	for _, g := range natgws {
		for _, a := range []string{g.Status.Address, g.Status.Address6} {
			if a == "" {
				continue
			}
			// The link that carries the address must run from_uplink, or the
			// replies never reach the reverse path.
			if err := w.mgr.EnsureFloatingUplink(a); err != nil {
				w.log.Warn("ensure NAT gateway uplink", "natgateway", g.Namespace+"/"+g.Name, "addr", a, "err", err)
			}
		}
	}
	if err := w.mgr.SyncNATGateways(plan.gateways); err != nil {
		w.log.Error("sync nat_gw", "err", err)
	}

	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	acked := map[string]bool{}
	for _, name := range plan.ack {
		w.ackLease(cctx, name, plan.activate[name] || leaseActive(leases, name))
		acked[name] = true
	}
	for name := range plan.activate {
		if !acked[name] {
			w.ackLease(cctx, name, true)
		}
	}
	for _, g := range plan.claim {
		w.claimBlock(cctx, g, leases)
	}
	for _, name := range plan.release {
		if err := w.lc.LocalV1alpha1().NATPortBlocks().Delete(cctx, name, metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			w.log.Error("release NAT port block", "lease", name, "err", err)
			continue
		}
		w.log.Info("released NAT port block", "lease", name)
	}
	w.publishMetrics(natgws, vpcList)
}

// leaseActive reports whether a lease is already marked active.
func leaseActive(leases []*localv1alpha1.NATPortBlock, name string) bool {
	for _, l := range leases {
		if l.Name == name {
			return l.Status.Active
		}
	}
	return false
}

// ackLease server-side-applies this node's ack (with its boot ID) into a lease,
// and for a lease this node holds, `active` once every Ready node has acked.
// Each apply carries every field this node's manager owns, or SSA would drop
// the ones left out.
func (w *egressWatcher) ackLease(ctx context.Context, name string, active bool) {
	st := localapply.NATPortBlockStatus().WithAcks(localapply.NATPortBlockAck().WithNode(w.self).WithBootID(w.nodes.bootID(w.self)))
	if active {
		st = st.WithActive(true)
	}
	cfg := localapply.NATPortBlock(name).WithStatus(st)
	_, err := w.lc.LocalV1alpha1().NATPortBlocks().ApplyStatus(ctx, cfg,
		metav1.ApplyOptions{FieldManager: "cozyplane-agent/" + w.self, Force: true})
	if err != nil && !apierrors.IsNotFound(err) {
		w.log.Error("ack NAT port block", "lease", name, "err", err)
	}
}

// claimBlock creates a lease on the lowest free block of a NAT gateway. The
// name is the claim: AlreadyExists means another node won it, so try the next.
func (w *egressWatcher) claimBlock(ctx context.Context, g *sdnv1alpha1.NATGateway, leases []*localv1alpha1.NATPortBlock) {
	skip := map[int]bool{}
	for range 8 {
		b := freeBlock(g, leases, skip)
		if b < 0 {
			w.log.Warn("no free NAT port block", "natgateway", g.Namespace+"/"+g.Name)
			return
		}
		lease := &localv1alpha1.NATPortBlock{
			ObjectMeta: metav1.ObjectMeta{
				Name: localv1alpha1.NATPortBlockName(g.UID, b),
				Labels: map[string]string{
					localv1alpha1.LabelNATGatewayUID: string(g.UID),
					localv1alpha1.LabelNATBlockNode:  w.self,
				},
			},
			Spec: localv1alpha1.NATPortBlockSpec{
				NATGatewayRef: localv1alpha1.NATGatewayReference{Namespace: g.Namespace, Name: g.Name, UID: g.UID},
				Block:         int32(b),
				Node:          w.self,
			},
		}
		_, err := w.lc.LocalV1alpha1().NATPortBlocks().Create(ctx, lease, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			// Ours already (the cache lags a claim this node made)?
			if got, gerr := w.lc.LocalV1alpha1().NATPortBlocks().Get(ctx, lease.Name, metav1.GetOptions{}); gerr == nil && got.Spec.Node == w.self {
				err = nil
			}
		}
		switch {
		case err == nil:
			w.mu.Lock()
			w.pending[g.UID] = time.Now()
			w.pendingName[g.UID] = lease.Name
			w.mu.Unlock()
			w.log.Info("claimed NAT port block", "natgateway", g.Namespace+"/"+g.Name, "block", b)
			return
		case apierrors.IsAlreadyExists(err):
			skip[b] = true
		default:
			w.log.Error("claim NAT port block", "natgateway", g.Namespace+"/"+g.Name, "block", b, "err", err)
			return
		}
	}
}

// sweep expires NAT flows (docs/vpc-egress.md §4.2).
func (w *egressWatcher) sweep() {
	natgws, err := w.sdn.Sdn().V1alpha1().NATGateways().Lister().List(labels.Everything())
	if err != nil {
		return
	}
	bs := map[uint32]int{}
	for _, g := range natgws {
		if g.Status.ID > 0 {
			bs[uint32(g.Status.ID)] = int(g.Status.BlockSize)
		}
	}
	res, err := w.mgr.SweepNAT(egressCfg.timeouts, bs)
	if err != nil {
		w.log.Error("sweep NAT flows", "err", err)
		return
	}
	if res.Expired > 0 {
		w.log.Debug("expired NAT flows", "count", res.Expired)
	}
	w.mu.Lock()
	w.live = res.LiveBlocks
	w.flows = res.FlowsByNATGateway
	now := time.Now()
	for b := range w.blockIdle {
		if _, known := bs[b.NATGateway]; !known || res.LiveBlocks[b] {
			delete(w.blockIdle, b)
		}
	}
	for id := range bs {
		for blk := 0; blk < localv1alpha1.NATBlocks(bs[id]); blk++ {
			b := datapath.NATBlock{NATGateway: id, Block: uint16(blk)}
			if _, ok := w.blockIdle[b]; !ok && !res.LiveBlocks[b] {
				w.blockIdle[b] = now
			}
		}
	}
	w.mu.Unlock()
	keep := map[uint32]bool{}
	for id := range bs {
		keep[id] = true
	}
	if err := w.mgr.PruneNATStats(keep); err != nil {
		w.log.Warn("prune NAT stats", "err", err)
	}
}

// checkPressure reports whether any NAT gateway's deep or failed allocations
// rose since the last poll, and marks those NAT gateways for one more block.
func (w *egressWatcher) checkPressure() bool {
	stats, err := w.mgr.NATStats()
	if err != nil {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	rose := false
	for id, s := range stats {
		n := s["deep"] + s["exhausted"]
		if prev, ok := w.pressure[id]; ok && n > prev {
			w.more[id] = true
			rose = true
		}
		w.pressure[id] = n
	}
	return rose
}

// publishMetrics refreshes the snapshot the metrics handler serves.
func (w *egressWatcher) publishMetrics(natgws []*sdnv1alpha1.NATGateway, vpcs []*sdnv1alpha1.VPC) {
	snap := &egressMetricsSnapshot{
		natgwName: map[uint32][3]string{},
		vpcName:   map[uint32][2]string{},
	}
	for _, g := range natgws {
		if g.Status.ID > 0 {
			snap.natgwName[uint32(g.Status.ID)] = [3]string{g.Namespace, g.Name, g.Spec.VPCRef.Name}
		}
	}
	for _, v := range vpcs {
		if v.Status.VNI != 0 {
			snap.vpcName[uint32(v.Status.VNI)] = [2]string{v.Namespace, v.Name}
		}
	}
	w.mu.Lock()
	snap.flows = w.flows
	snap.active = w.active
	w.mu.Unlock()
	snap.stats, _ = w.mgr.NATStats()
	snap.routeDrops, _ = w.mgr.RouteDrops()
	egressMetrics.Store(snap)
}

// writeEgressMetrics renders the egress metrics (docs/vpc-egress.md §8).
func writeEgressMetrics(b *strings.Builder, node string) {
	s := egressMetrics.Load()
	if s == nil {
		return
	}
	name := func(id uint32) [3]string { return s.natgwName[id] }
	fmt.Fprintf(b, "# HELP cozyplane_nat_flows Live NAT flows through a NAT gateway (this node).\n# TYPE cozyplane_nat_flows gauge\n")
	for id := range s.natgwName {
		n := name(id)
		fmt.Fprintf(b, "cozyplane_nat_flows{natgateway_namespace=%q,natgateway=%q,vpc=%q,node=%q} %d\n", n[0], n[1], n[2], node, s.flows[id])
	}
	fmt.Fprintf(b, "# HELP cozyplane_nat_blocks Active port blocks this node holds of a NAT gateway.\n# TYPE cozyplane_nat_blocks gauge\n")
	for id, c := range s.active {
		n := name(id)
		fmt.Fprintf(b, "cozyplane_nat_blocks{natgateway_namespace=%q,natgateway=%q,node=%q} %d\n", n[0], n[1], node, c)
	}
	fmt.Fprintf(b, "# HELP cozyplane_nat_drops_total NAT refusals by reason (this node).\n# TYPE cozyplane_nat_drops_total counter\n")
	fmt.Fprintf(b, "# HELP cozyplane_nat_allocation_deep_total NAT port allocations that needed more than 8 attempts (this node).\n# TYPE cozyplane_nat_allocation_deep_total counter\n")
	for id, counters := range s.stats {
		n := name(id)
		for reason, c := range counters {
			if reason == "deep" {
				fmt.Fprintf(b, "cozyplane_nat_allocation_deep_total{natgateway_namespace=%q,natgateway=%q,node=%q} %d\n", n[0], n[1], node, c)
				continue
			}
			fmt.Fprintf(b, "cozyplane_nat_drops_total{natgateway_namespace=%q,natgateway=%q,node=%q,reason=%q} %d\n", n[0], n[1], node, reason, c)
		}
	}
	fmt.Fprintf(b, "# HELP cozyplane_route_drops_total Packets a VPC's route table dropped, by reason (this node).\n# TYPE cozyplane_route_drops_total counter\n")
	for net, counters := range s.routeDrops {
		v := s.vpcName[net]
		for reason, c := range counters {
			fmt.Fprintf(b, "cozyplane_route_drops_total{vni=\"%d\",vpc_namespace=%q,vpc=%q,node=%q,reason=%q} %d\n", net, v[0], v[1], node, reason, c)
		}
	}
}
