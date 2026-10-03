package main

import (
	"net"
	"reflect"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func boundaryTestVPC(namespace, name, uid string, vni int32, cidrs ...string) *sdn.VPC {
	return &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name, UID: types.UID(uid)}, Spec: sdn.VPCSpec{CIDRs: cidrs}, Status: sdn.VPCStatus{VNI: vni}}
}
func boundaryTestPair() (*sdn.VPC, *sdn.VPC) {
	a := boundaryTestVPC("scope-a", "local", "identity-a", 200, "10.10.0.0/24", "fd00:10::/64")
	b := boundaryTestVPC("scope-b", "shared-name", "identity-b", 100, "10.20.0.0/24", "fd00:20::/64")
	a.Spec.Boundary = &sdn.VPCBoundary{Revision: 7, Internet: true, Peers: []sdn.VPCBoundaryRule{{PeerRef: sdn.VPCRef{Namespace: b.Namespace, Name: b.Name}, Direction: "egress", Protocol: "TCP", Ports: []int32{443}}}}
	return a, b
}
func boundaryInt(n int32) *int32 { return &n }

func TestCompileBoundariesPortsDirectionAndPeerIdentity(t *testing.T) {
	a, b := boundaryTestPair()
	homonym := boundaryTestVPC("scope-c", b.Name, "other-identity", 300, "10.30.0.0/24")
	a.Spec.Boundary.Peers = append(a.Spec.Boundary.Peers, sdn.VPCBoundaryRule{PeerRef: sdn.VPCRef{Namespace: b.Namespace, Name: b.Name}, Direction: "ingress", Protocol: "UDP", Ports: []int32{53, 5353}})
	a.Spec.Boundary.Peers[0].Ports = []int32{443, 8443}
	vpcs := []*sdn.VPC{a, homonym, b}
	compiled, known, primary, err := compileBoundaries(vpcs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || !reflect.DeepEqual(known, []uint32{200, 300, 100}) || len(primary) != 0 {
		t.Fatalf("unexpected compiled counts/networks: policies=%d known=%v primary=%d", len(compiled), known, len(primary))
	}
	policy := compiled[0]
	expected := []datapath.BoundaryRule{{Peer: 100, Protocol: 6, Port: 443}, {Peer: 100, Protocol: 6, Port: 8443}, {Peer: 100, Ingress: true, Protocol: 17, Port: 53}, {Peer: 100, Ingress: true, Protocol: 17, Port: 5353}}
	if policy.Net != 200 || policy.Identity == 0 || policy.Revision != 7 || !policy.Internet || !reflect.DeepEqual(policy.Rules, expected) {
		t.Fatalf("compiled policy=%+v, rules=%+v", policy, policy.Rules)
	}
	if len(policy.CIDRs) != 2 || policy.CIDRs[0].String() != "10.10.0.0/24" || policy.CIDRs[1].String() != "fd00:10::/64" {
		t.Fatal("compiled policy changed dual-stack CIDRs")
	}
	// Input order cannot resolve an identically named VPC from another namespace.
	again, _, _, err := compileBoundaries([]*sdn.VPC{homonym, b, a}, nil)
	if err != nil || !reflect.DeepEqual(compiled, again) {
		t.Fatal("compilation depends on unrelated VPC order")
	}
	repeat, _, _, err := compileBoundaries(vpcs, nil)
	if err != nil || !reflect.DeepEqual(compiled, repeat) {
		t.Fatal("repeated compilation is not deterministic")
	}
}

func TestCompileBoundariesICMPPreservesExplicitTypeAndCodeForBothFamilies(t *testing.T) {
	for _, pair := range [][2]int32{{8, 0}, {128, 0}, {3, 4}, {255, 255}} {
		a, b := boundaryTestPair()
		a.Spec.Boundary.Peers = []sdn.VPCBoundaryRule{{PeerRef: sdn.VPCRef{Namespace: b.Namespace, Name: b.Name}, Direction: "ingress", Protocol: "ICMP", ICMPType: boundaryInt(pair[0]), ICMPCode: boundaryInt(pair[1])}}
		got, _, _, err := compileBoundaries([]*sdn.VPC{a, b}, nil)
		if err != nil {
			t.Fatal(err)
		}
		packed := uint16(pair[0]<<8 | pair[1])
		want := []datapath.BoundaryRule{{Peer: 100, Ingress: true, Protocol: 1, Port: packed}, {Peer: 100, Ingress: true, Protocol: 58, Port: packed}}
		if !reflect.DeepEqual(got[0].Rules, want) {
			t.Fatalf("ICMP %v compiled=%+v", pair, got[0].Rules)
		}
	}
}

func TestCompileBoundariesDistinguishesVPCUIDAfterVNIReuse(t *testing.T) {
	a, b := boundaryTestPair()
	first, _, _, err := compileBoundaries([]*sdn.VPC{a, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	renamed := a.DeepCopy()
	renamed.Name = "renamed"
	same, _, _, err := compileBoundaries([]*sdn.VPC{renamed, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Identity != same[0].Identity {
		t.Fatal("stable VPC identity depends on its display name")
	}
	recycled := a.DeepCopy()
	recycled.UID = "replacement-identity"
	next, _, _, err := compileBoundaries([]*sdn.VPC{recycled, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if next[0].Identity == 0 || first[0].Identity == next[0].Identity {
		t.Fatal("a reused VNI inherited the prior VPC identity")
	}
}

func TestCompileBoundariesAbsentPolicyAndUnrealizedVNI(t *testing.T) {
	legacy := boundaryTestVPC("scope-a", "legacy", "identity-legacy", 10, "10.40.0.0/24")
	pending := boundaryTestVPC("scope-a", "pending", "identity-pending", 0, "10.50.0.0/24")
	pending.Spec.Boundary = &sdn.VPCBoundary{Revision: 2}
	got, known, ports, err := compileBoundaries([]*sdn.VPC{legacy, pending}, nil)
	if err != nil || len(got) != 0 || len(ports) != 0 || !reflect.DeepEqual(known, []uint32{10}) {
		t.Fatalf("legacy/pending compilation policy=%v known=%v error=%v", got, known, err)
	}
	legacy.Spec.Boundary = &sdn.VPCBoundary{Revision: 1}
	got, _, _, err = compileBoundaries([]*sdn.VPC{legacy}, nil)
	if err != nil || len(got) != 1 || got[0].Internet || len(got[0].Rules) != 0 {
		t.Fatal("empty managed policy does not remain closed")
	}
}

func TestCompileBoundariesRejectsInvalidConfigurationWithoutPartialOutput(t *testing.T) {
	cases := []struct {
		name   string
		change func(*sdn.VPC, *sdn.VPC)
	}{
		{"zero revision", func(a, b *sdn.VPC) { a.Spec.Boundary.Revision = 0 }},
		{"negative revision", func(a, b *sdn.VPC) { a.Spec.Boundary.Revision = -1 }},
		{"negative local VNI", func(a, b *sdn.VPC) { a.Status.VNI = -1 }},
		{"invalid CIDR", func(a, b *sdn.VPC) { a.Spec.CIDRs = []string{"invalid"} }},
		{"missing peer", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].PeerRef.Name = "absent" }},
		{"unrealized peer", func(a, b *sdn.VPC) { b.Status.VNI = 0 }},
		{"self peer", func(a, b *sdn.VPC) {
			a.Spec.Boundary.Peers[0].PeerRef = sdn.VPCRef{Namespace: a.Namespace, Name: a.Name}
		}},
		{"overlapping peer", func(a, b *sdn.VPC) { b.Spec.CIDRs = []string{"10.10.0.128/25"} }},
		{"overlapping IPv6 peer", func(a, b *sdn.VPC) { b.Spec.CIDRs = []string{"fd00:10::/80"} }},
		{"invalid direction", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Direction = "both" }},
		{"invalid protocol", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Protocol = "ANY" }},
		{"TCP ports absent", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Ports = nil }},
		{"TCP zero port", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Ports = []int32{0} }},
		{"TCP negative port", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Ports = []int32{-1} }},
		{"TCP high port", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Ports = []int32{65536} }},
		{"TCP port capacity", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Ports = make([]int32, 33) }},
		{"TCP ICMP type", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].ICMPType = boundaryInt(8) }},
		{"TCP ICMP code", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].ICMPCode = boundaryInt(0) }},
		{"UDP ports absent", func(a, b *sdn.VPC) { a.Spec.Boundary.Peers[0].Protocol = "UDP"; a.Spec.Boundary.Peers[0].Ports = nil }},
		{"UDP high port", func(a, b *sdn.VPC) {
			a.Spec.Boundary.Peers[0].Protocol = "UDP"
			a.Spec.Boundary.Peers[0].Ports = []int32{65536}
		}},
		{"ICMP with ports", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.ICMPType = boundaryInt(8)
			r.ICMPCode = boundaryInt(0)
		}},
		{"ICMP type absent", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPCode = boundaryInt(0)
		}},
		{"ICMP code absent", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(8)
		}},
		{"ICMP type negative", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(-1)
			r.ICMPCode = boundaryInt(0)
		}},
		{"ICMP type high", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(256)
			r.ICMPCode = boundaryInt(0)
		}},
		{"ICMP code negative", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(8)
			r.ICMPCode = boundaryInt(-1)
		}},
		{"ICMP code high", func(a, b *sdn.VPC) {
			r := &a.Spec.Boundary.Peers[0]
			r.Protocol = "ICMP"
			r.Ports = nil
			r.ICMPType = boundaryInt(8)
			r.ICMPCode = boundaryInt(256)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, b := boundaryTestPair()
			tc.change(a, b)
			valid := boundaryTestVPC("scope-c", "valid-first", "identity-valid", 300, "10.60.0.0/24")
			valid.Spec.Boundary = &sdn.VPCBoundary{Revision: 1}
			out, known, primary, err := compileBoundaries([]*sdn.VPC{valid, a, b}, nil)
			if err == nil || out != nil || known != nil || primary != nil {
				t.Fatalf("invalid configuration produced partial output: error=%v out=%v known=%v primary=%v", err, out, known, primary)
			}
		})
	}
}

func TestCompileBoundariesPrimaryPortsExcludeSecondaryDeletingAndUnrealized(t *testing.T) {
	a, b := boundaryTestPair()
	ref := sdn.VPCRef{Namespace: a.Namespace, Name: a.Name}
	now := metav1.Now()
	ports := []*sdn.Port{
		{Spec: sdn.PortSpec{VPCRef: ref, Primary: true, IP: "10.10.0.2"}},
		{Spec: sdn.PortSpec{VPCRef: ref, Primary: true, IP: "fd00:10::2"}},
		{Spec: sdn.PortSpec{VPCRef: ref, Primary: false, IP: "invalid"}},
		{ObjectMeta: metav1.ObjectMeta{DeletionTimestamp: &now}, Spec: sdn.PortSpec{VPCRef: ref, Primary: true, IP: "invalid"}},
		{Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "other-scope", Name: a.Name}, Primary: true, IP: "invalid"}},
	}
	got, _, primary, err := compileBoundaries([]*sdn.VPC{a, b}, ports)
	if err != nil || len(got) != 1 || len(primary) != 2 {
		t.Fatalf("primary compilation primary=%v error=%v", primary, err)
	}
	for i, ip := range []string{"10.10.0.2", "fd00:10::2"} {
		if primary[i].Net != 200 || !primary[i].IP.Equal(net.ParseIP(ip)) {
			t.Fatalf("primary %d=%+v", i, primary[i])
		}
	}
	b.Status.VNI = 0
	a.Spec.Boundary.Peers = nil
	ports = append(ports, &sdn.Port{Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: b.Namespace, Name: b.Name}, Primary: true, IP: "invalid"}})
	_, _, primary, err = compileBoundaries([]*sdn.VPC{a, b}, ports)
	if err != nil || len(primary) != 2 {
		t.Fatal("unrealized VPC supplied a primary port")
	}
	ports[0].Spec.IP = "invalid"
	out, known, primary, err := compileBoundaries([]*sdn.VPC{a, b}, ports)
	if err == nil || out != nil || known != nil || primary != nil {
		t.Fatal("invalid live primary Port did not fail closed")
	}
}

func TestBoundaryTransportCompleteRequiresEveryReciprocalPeer(t *testing.T) {
	a, b := boundaryTestPair()
	refs := map[sdn.VPCRef]*sdn.VPC{{Namespace: a.Namespace, Name: a.Name}: a, {Namespace: b.Namespace, Name: b.Name}: b}
	lookup := func(namespace, name string) *sdn.VPC { return refs[sdn.VPCRef{Namespace: namespace, Name: name}] }
	first := half(a.Namespace, "to-peer", a.Name, b.Namespace, b.Name)
	second := half(b.Namespace, "to-local", b.Name, a.Namespace, a.Name)
	if boundaryTransportComplete(a, refs, desiredPeerLinks([]*sdn.VPCPeering{first}, lookup)) {
		t.Fatal("one half acknowledged peer transport")
	}
	links := desiredPeerLinks([]*sdn.VPCPeering{first, second}, lookup)
	if len(links) != 1 || !boundaryTransportComplete(a, refs, links) {
		t.Fatal("reciprocal normalized peer transport was not acknowledged")
	}
	if boundaryTransportComplete(a, refs, []peerLink{{a: 100, b: 300}}) {
		t.Fatal("an unrelated pair acknowledged transport")
	}
	delete(refs, sdn.VPCRef{Namespace: b.Namespace, Name: b.Name})
	if boundaryTransportComplete(a, refs, links) {
		t.Fatal("missing peer retained a transport acknowledgement")
	}
	refs[sdn.VPCRef{Namespace: b.Namespace, Name: b.Name}] = b
	c := boundaryTestVPC("scope-c", "third", "identity-c", 300, "10.30.0.0/24")
	refs[sdn.VPCRef{Namespace: c.Namespace, Name: c.Name}] = c
	a.Spec.Boundary.Peers = append(a.Spec.Boundary.Peers, sdn.VPCBoundaryRule{PeerRef: sdn.VPCRef{Namespace: c.Namespace, Name: c.Name}, Direction: "egress", Protocol: "UDP", Ports: []int32{53}})
	if boundaryTransportComplete(a, refs, links) {
		t.Fatal("partial transport acknowledged all peers")
	}
	links = append(links, peerLink{a: 200, b: 300})
	if !boundaryTransportComplete(a, refs, links) {
		t.Fatal("complete peer transport was not acknowledged")
	}
	a.Spec.Boundary.Peers = nil
	if !boundaryTransportComplete(a, refs, nil) {
		t.Fatal("closed boundary requires nonexistent peer transport")
	}
}
