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
	"net"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
)

func egVPC(name string, vni int32, cidr string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "t"},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{cidr}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

func egTable(name, vpc string, id int32, def bool, age time.Duration) *sdnv1alpha1.RouteTable {
	return &sdnv1alpha1.RouteTable{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "t", CreationTimestamp: metav1.NewTime(time.Unix(1e6, 0).Add(-age))},
		Spec:       sdnv1alpha1.RouteTableSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc}, Default: def},
		Status:     sdnv1alpha1.RouteTableStatus{ID: id},
	}
}

func egRoute(table, dst string, state sdnv1alpha1.RouteState, target sdnv1alpha1.RouteTarget) *sdnv1alpha1.Route {
	return &sdnv1alpha1.Route{
		ObjectMeta: metav1.ObjectMeta{Name: dst, Namespace: "t"},
		Spec:       sdnv1alpha1.RouteSpec{RouteTableRef: sdnv1alpha1.LocalRouteTableRef{Name: table}, Destination: dst, Target: target},
		Status:     sdnv1alpha1.RouteStatus{State: state},
	}
}

// planRoutes: local beats a Route at equal length, a Route beats a peer route,
// an unresolved or not-yet-resolved Route blackholes, a Conflict loser is absent.
func TestPlanRoutesPrecedence(t *testing.T) {
	vpcs := map[vpcKey]*sdnv1alpha1.VPC{{"t", "v"}: egVPC("v", 100, "10.0.0.0/16")}
	nat := sdnv1alpha1.RouteTarget{NATGateway: &sdnv1alpha1.LocalNATGatewayRef{Name: "egress"}}
	bh := sdnv1alpha1.RouteTarget{Blackhole: &sdnv1alpha1.RouteBlackholeTarget{}}
	routes := []*sdnv1alpha1.Route{
		egRoute("main", "0.0.0.0/0", sdnv1alpha1.RouteStateActive, nat),
		egRoute("main", "10.50.0.0/16", sdnv1alpha1.RouteStateActive, bh),    // same as the peer: the Route wins
		egRoute("main", "10.0.0.0/16", sdnv1alpha1.RouteStateUnresolved, bh), // same as local: local wins
		egRoute("main", "198.51.100.0/24", "", nat),                          // not resolved yet
		egRoute("main", "192.0.2.0/24", sdnv1alpha1.RouteStateConflict, bh),
	}
	got := planRoutes([]*sdnv1alpha1.RouteTable{egTable("main", "v", 7, true, 0)}, routes, vpcs,
		map[uint32][]string{100: {"10.50.0.0/16", "10.60.0.0/16"}}, map[vpcKey]uint32{{"t", "egress"}: 3})
	want := map[string]datapath.Route{
		"0.0.0.0/0":       {Table: 7, CIDR: "0.0.0.0/0", Kind: datapath.RouteNAT, NATGateway: 3},
		"10.0.0.0/16":     {Table: 7, CIDR: "10.0.0.0/16", Kind: datapath.RouteLocal},
		"10.50.0.0/16":    {Table: 7, CIDR: "10.50.0.0/16", Kind: datapath.RouteBlackhole},
		"10.60.0.0/16":    {Table: 7, CIDR: "10.60.0.0/16", Kind: datapath.RoutePeer},
		"198.51.100.0/24": {Table: 7, CIDR: "198.51.100.0/24", Kind: datapath.RouteUnresolved},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d routes %v, want %d", len(got), got, len(want))
	}
	for _, r := range got {
		if w, ok := want[r.CIDR]; !ok || w != r {
			t.Errorf("route %s = %+v, want %+v", r.CIDR, r, want[r.CIDR])
		}
	}
}

// A Port gets the table its pod named, else the VPC's (oldest) default; a
// named table that does not exist or belongs to another VPC gives none.
func TestPortTableOf(t *testing.T) {
	tables := []*sdnv1alpha1.RouteTable{
		egTable("public", "v", 5, false, 0),
		egTable("main", "v", 6, true, time.Hour),
		egTable("newer", "v", 7, true, 0),
		egTable("theirs", "other", 8, false, 0),
	}
	port := func(table string) *sdnv1alpha1.Port {
		return &sdnv1alpha1.Port{Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: "t", Name: "v"}, RouteTable: table,
		}}
	}
	for table, want := range map[string]uint32{"public": 5, "": 6, "missing": 0, "theirs": 0} {
		if got := portTableOf(port(table), tables); got != want {
			t.Errorf("table %q -> %d, want %d", table, got, want)
		}
	}
}

func egNATGW(name string, id int32) *sdnv1alpha1.NATGateway {
	return &sdnv1alpha1.NATGateway{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "t", UID: types.UID("uid-" + name)},
		Spec:       sdnv1alpha1.NATGatewaySpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: "v"}},
		Status:     sdnv1alpha1.NATGatewayStatus{ID: id, Address: "203.0.113.7", BlockSize: 1008},
	}
}

func egLease(gw string, block int32, node string, acks ...string) *localv1alpha1.NATPortBlock {
	l := &localv1alpha1.NATPortBlock{
		ObjectMeta: metav1.ObjectMeta{Name: "uid-" + gw + "." + string(rune('0'+block))},
		Spec: localv1alpha1.NATPortBlockSpec{
			NATGatewayRef: localv1alpha1.NATGatewayReference{Namespace: "t", Name: gw, UID: types.UID("uid-" + gw)},
			Block:         block, Node: node,
		},
	}
	for _, a := range acks {
		l.Status.Acks = append(l.Status.Acks, localv1alpha1.NATPortBlockAck{Node: a})
	}
	return l
}

func egInputs(leases ...*localv1alpha1.NATPortBlock) natInputs {
	return natInputs{
		self:   "b",
		natgws: []*sdnv1alpha1.NATGateway{egNATGW("egress", 3)},
		vpcs:   map[vpcKey]*sdnv1alpha1.VPC{{"t", "v"}: egVPC("v", 100, "10.0.0.0/16")},
		leases: leases,
		ready:  map[string]string{"a": "", "b": "", "c": ""},
		nodeIP: func(n string) net.IP {
			return map[string]net.IP{"a": net.IPv4(10, 0, 0, 1), "b": net.IPv4(10, 0, 0, 2), "c": net.IPv4(10, 0, 0, 3)}[n]
		},
		hosted:    map[vpcKey]bool{{"t", "v"}: true},
		more:      map[uint32]bool{},
		idleSince: map[types.UID]time.Time{},
		pending:   map[types.UID]time.Time{},
		live:      map[datapath.NATBlock]bool{},
		now:       time.Unix(1e6, 0),
		idleGrace: time.Hour,
		blockIdle: map[datapath.NATBlock]time.Time{},
	}
}

// A block is active only once every Ready node has acked it; every lease's
// owner is programmed on every node, acked or not (docs/vpc-egress.md §4.3).
func TestPlanNATActivationAndOwners(t *testing.T) {
	plan := planNAT(egInputs(
		egLease("egress", 1, "b", "a", "b", "c"), // acked by all: active
		egLease("egress", 2, "b", "a", "b"),      // c has not acked: not yet
		egLease("egress", 0, "a"),                // someone else's, unacked by b
	))
	g := plan.gateways[3]
	if g.Net != 100 || g.BlockSize != 1008 || len(g.Blocks) != 1 || g.Blocks[0] != 1 {
		t.Errorf("nat_gw = %+v, want net 100, block size 1008, active block [1]", g)
	}
	for b, want := range map[uint16]string{0: "10.0.0.1", 1: "10.0.0.2", 2: "10.0.0.2"} {
		if got := plan.owners[datapath.NATBlock{NATGateway: 3, Block: b}]; got.String() != want {
			t.Errorf("owner of block %d = %v, want %s", b, got, want)
		}
	}
	if len(plan.ack) != 1 || plan.ack[0] != "uid-egress.0" {
		t.Errorf("acks to send = %v, want only the lease b has not acked", plan.ack)
	}
	if len(plan.claim) != 0 {
		t.Errorf("claims = %d, want none: b holds blocks", len(plan.claim))
	}
}

// A hosting node with no lease claims one; a claim in flight suppresses another;
// pressure asks for one more.
func TestPlanNATClaims(t *testing.T) {
	in := egInputs()
	if got := planNAT(in).claim; len(got) != 1 {
		t.Errorf("claims with no lease = %d, want 1", len(got))
	}
	in.pending[types.UID("uid-egress")] = in.now.Add(-time.Second)
	if got := planNAT(in).claim; len(got) != 0 {
		t.Errorf("claims while one is in flight = %d, want 0", len(got))
	}
	in = egInputs(egLease("egress", 1, "b", "a", "b", "c"), egLease("egress", 2, "b", "a", "b", "c"))
	in.natgws[0].Status.Address = ""
	in.live[datapath.NATBlock{NATGateway: 3, Block: 2}] = true
	if plan := planNAT(in); len(plan.claim) != 0 || len(plan.release) != 1 || plan.release[0] != "uid-egress.1" {
		t.Errorf("claims %d, release %v for a NAT gateway without an address, want none and the flowless block 1", len(plan.claim), plan.release)
	}
	in = egInputs(egLease("egress", 1, "b", "a", "b", "c"))
	in.more[3] = true
	if got := planNAT(in).claim; len(got) != 1 {
		t.Errorf("claims under pressure = %d, want 1", len(got))
	}
}

// A node that stopped hosting the VPC releases its leases after the grace, but
// never a block that still holds a live flow.
func TestPlanNATRelease(t *testing.T) {
	in := egInputs(egLease("egress", 1, "b", "a", "b", "c"), egLease("egress", 2, "b", "a", "b", "c"))
	in.hosted = map[vpcKey]bool{}
	in.idleSince[types.UID("uid-egress")] = in.now.Add(-2 * time.Hour)
	in.live[datapath.NATBlock{NATGateway: 3, Block: 2}] = true
	plan := planNAT(in)
	if len(plan.release) != 1 || plan.release[0] != "uid-egress.1" {
		t.Errorf("release = %v, want only the idle block 1", plan.release)
	}
	in.idleSince[types.UID("uid-egress")] = in.now.Add(-time.Minute)
	if got := planNAT(in).release; len(got) != 0 {
		t.Errorf("release before the grace = %v, want none", got)
	}
}

// An ack from an earlier boot does not count: a rebooted node re-acks, and a
// block is not activated until it has. Once active, a block stays active
// whoever's ack goes stale (docs/vpc-egress.md §4.3).
func TestPlanNATBootScopedAcks(t *testing.T) {
	stale := egLease("egress", 1, "b", "a", "b", "c")
	stale.Status.Acks[0].BootID = "a-old"
	stale.Status.Acks[1].BootID = "b-old"
	in := egInputs(stale)
	in.ready = map[string]string{"a": "a-new", "b": "b-new", "c": ""}
	in.selfBoot = "b-new"
	plan := planNAT(in)
	if len(plan.ack) != 1 || plan.ack[0] != stale.Name {
		t.Errorf("acks to send = %v, want b to re-ack its stale lease", plan.ack)
	}
	if len(plan.gateways[3].Blocks) != 0 || len(plan.activate) != 0 {
		t.Errorf("blocks %v / activate %v, want none: a has not acked this boot", plan.gateways[3].Blocks, plan.activate)
	}

	stale.Status.Acks[0].BootID = "a-new"
	stale.Status.Acks[1].BootID = "b-new"
	plan = planNAT(in)
	if !plan.activate[stale.Name] || len(plan.gateways[3].Blocks) != 1 {
		t.Errorf("activate %v / blocks %v, want the fully acked lease activated", plan.activate, plan.gateways[3].Blocks)
	}

	stale.Status.Active = true
	stale.Status.Acks[0].BootID = "a-older"
	plan = planNAT(in)
	if len(plan.gateways[3].Blocks) != 1 || len(plan.activate) != 0 {
		t.Errorf("blocks %v / activate %v, want an active lease to stay active", plan.gateways[3].Blocks, plan.activate)
	}
}

// A hosting node keeps its first block and releases an extra one once it has
// held no flow for extraBlockIdle.
func TestPlanNATReleasesIdleExtraBlocks(t *testing.T) {
	in := egInputs(egLease("egress", 1, "b", "a", "b", "c"), egLease("egress", 2, "b", "a", "b", "c"))
	in.blockIdle[datapath.NATBlock{NATGateway: 3, Block: 1}] = in.now.Add(-time.Hour)
	in.blockIdle[datapath.NATBlock{NATGateway: 3, Block: 2}] = in.now.Add(-time.Minute)
	if got := planNAT(in).release; len(got) != 0 {
		t.Errorf("release = %v, want none: block 1 is the first, block 2 idle only a minute", got)
	}
	in.blockIdle[datapath.NATBlock{NATGateway: 3, Block: 2}] = in.now.Add(-extraBlockIdle)
	if got := planNAT(in).release; len(got) != 1 || got[0] != "uid-egress.2" {
		t.Errorf("release = %v, want the idle extra block 2", got)
	}
}

func TestFreeBlockSkipsHeld(t *testing.T) {
	g := egNATGW("egress", 3)
	leases := []*localv1alpha1.NATPortBlock{egLease("egress", 0, "a"), egLease("egress", 2, "c")}
	if b := freeBlock(g, leases, map[int]bool{1: true}); b != 3 {
		t.Errorf("free block = %d, want 3 (0 and 2 held, 1 skipped)", b)
	}
}
