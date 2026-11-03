package datapath

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

func TestBoundaryNoopDoesNotWriteFrozenMaps(t *testing.T) {
	f := newBoundaryPacketFixture(t, false)
	m := &Manager{objs: f.objects}
	_, cidr, err := net.ParseCIDR("10.60.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	desired := []Boundary{{Net: 1, Revision: 1, Identity: 1, Rules: []BoundaryRule{{Peer: 2, Protocol: 6, Port: 443}}, CIDRs: []*net.IPNet{cidr}}}
	known := []uint32{1, 2}
	primary := []PrimaryPort{{Net: 1, IP: f.a}}
	if err := m.SyncBoundaries(desired, known, primary); err != nil {
		t.Fatal(err)
	}
	// The optimization reads the real maps, so it must still repair actual drift.
	rule := overlayBoundaryRule{Revision: 1, Net: 1, Peer: 2, Proto: 6, Port: htons(443)}
	if err := f.objects.BoundaryRules.Put(rule, uint8(2)); err != nil {
		t.Fatal(err)
	}
	stale := rule
	stale.Revision = 99
	if err := f.objects.BoundaryRules.Put(stale, uint8(1)); err != nil {
		t.Fatal(err)
	}
	if err := f.objects.BoundaryPolicy.Put(uint32(1), overlayBoundaryPolicy{Revision: 1, Identity: 1, Internet: 1}); err != nil {
		t.Fatal(err)
	}
	address := boundaryPacketAddress(t, f.a)
	if err := f.objects.BoundaryPrimary.Delete(overlayLocalKey{Net: 1, Ip: address}); err != nil {
		t.Fatal(err)
	}
	if err := m.SyncBoundaries(desired, known, primary); err != nil {
		t.Fatalf("repair drift: %v", err)
	}
	var value uint8
	if err := f.objects.BoundaryRules.Lookup(rule, &value); err != nil || value != 1 {
		t.Fatalf("rule not repaired: value=%d err=%v", value, err)
	}
	if err := f.objects.BoundaryRules.Lookup(stale, &value); !isNotExist(err) {
		t.Fatalf("stale rule not removed: %v", err)
	}
	var policy overlayBoundaryPolicy
	if err := f.objects.BoundaryPolicy.Lookup(uint32(1), &policy); err != nil || policy.Internet != 0 {
		t.Fatalf("policy not repaired: %+v %v", policy, err)
	}
	if err := f.objects.BoundaryPrimary.Lookup(overlayLocalKey{Net: 1, Ip: address}, &value); err != nil || value != 1 {
		t.Fatalf("primary not restored: %d %v", value, err)
	}
	// Freezing is enforced by the real kernel: any redundant Put/Delete fails.
	for _, mp := range []*ebpf.Map{f.objects.BoundaryPolicy, f.objects.BoundaryRules, f.objects.BoundaryCidrs, f.objects.BoundaryPrimary} {
		if err := mp.Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if err := m.SyncBoundaries(desired, known, primary); err != nil {
			t.Fatalf("stable sync attempted a mutation: %v", err)
		}
	}
}

func TestBoundaryRuleMapSaturationDoesNotPublishPartialPolicy(t *testing.T) {
	f := newBoundaryPacketFixtureWithRuleCapacity(t, false, 1)
	m := &Manager{objs: f.objects}
	if err := f.objects.BoundaryPolicy.Delete(uint32(1)); err != nil {
		t.Fatal(err)
	}
	desired := []Boundary{{Net: 1, Revision: 2, Identity: 1, Internet: true, Rules: []BoundaryRule{{Peer: 2, Protocol: 6, Port: 443}, {Peer: 2, Protocol: 6, Port: 8443}}}}
	primary := []PrimaryPort{{Net: 1, IP: f.a}}
	if err := m.SyncBoundaries(desired, []uint32{1, 2}, primary); err == nil {
		t.Fatal("full private rule map accepted an incomplete policy")
	}
	var policy overlayBoundaryPolicy
	if err := f.objects.BoundaryPolicy.Lookup(uint32(1), &policy); err != nil || policy.Revision != 0 || policy.Identity != 1 || policy.Internet != 0 {
		t.Fatalf("new VPC did not remain closed: %+v err=%v", policy, err)
	}
	f.verdict(t, false, 1, boundaryPacket(f.a, f.world, 6, 42000, 443, 2), 2)
	desired[0].Revision = 3
	desired[0].Rules = desired[0].Rules[:1]
	if err := m.SyncBoundaries(desired, []uint32{1, 2}, primary); err != nil {
		t.Fatalf("complete policy after failed staging: %v", err)
	}
	if err := f.objects.BoundaryPolicy.Lookup(uint32(1), &policy); err != nil || policy.Revision != 3 || policy.Internet != 1 {
		t.Fatalf("complete policy not published: %+v err=%v", policy, err)
	}
	f.verdict(t, false, 1, boundaryPacket(f.a, f.world, 6, 42001, 443, 2), 0)
	previous := policy
	desired[0].Revision = 4
	desired[0].Internet = false
	desired[0].Rules = append(desired[0].Rules, BoundaryRule{Peer: 2, Protocol: 6, Port: 8443})
	if err := m.SyncBoundaries(desired, []uint32{1, 2}, primary); err == nil {
		t.Fatal("full private staging map accepted a replacement")
	}
	if err := f.objects.BoundaryPolicy.Lookup(uint32(1), &policy); err != nil || policy != previous {
		t.Fatalf("staging failure changed the active policy: %+v want=%+v err=%v", policy, previous, err)
	}
}
