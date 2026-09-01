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
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	localv1alpha1 "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	localfake "github.com/lllamnyp/cozyplane/pkg/generated/localsdn/clientset/versioned/fake"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func TestPoolFor(t *testing.T) {
	const (
		v4        = "10.244.1.0/24"
		v6        = "fd00:10:244:1::/64"
		clusterV4 = "10.244.0.0/16"
		clusterV6 = "fd00:10:244::/56"
	)
	// The flat pool wins when the agent published one: a pod's address is drawn
	// from the whole cluster range, not from this node's slice of it.
	state := &datapath.AgentState{
		PodCIDR:         v4,
		PodCIDRs:        []string{v4, v6},
		ClusterPodCIDRs: []string{clusterV4, clusterV6},
	}
	if got := poolFor(state); !slices.Equal(got, []string{clusterV4, clusterV6}) {
		t.Fatalf("flat pool: got %v", got)
	}
	// Without one, fall back to the node's slice (pre-flat behaviour).
	state = &datapath.AgentState{PodCIDR: v4, PodCIDRs: []string{v4, v6}}
	if got := poolFor(state); !slices.Equal(got, []string{v4, v6}) {
		t.Fatalf("node-slice fallback: got %v", got)
	}
	state = &datapath.AgentState{PodCIDR: v4}
	if got := poolFor(state); !slices.Equal(got, []string{v4}) {
		t.Fatalf("single-CIDR fallback: got %v", got)
	}
}

func TestPoolOfFamily(t *testing.T) {
	const (
		v4 = "10.244.0.0/16"
		v6 = "fd00:10:244::/56"
	)
	if got := poolOfFamily([]string{v4, v6}, false); !slices.Equal(got, []string{v4}) {
		t.Fatalf("v4 wanted: got %v", got)
	}
	if got := poolOfFamily([]string{v4, v6}, true); !slices.Equal(got, []string{v6}) {
		t.Fatalf("v6 wanted: got %v", got)
	}
	// The decoupling stands: a v6 VPC on a v4-only cluster still gets a fabric
	// handle — east-west VPC traffic keys on the VPC IP, not the fabric IP.
	if got := poolOfFamily([]string{v4}, true); !slices.Equal(got, []string{v4}) {
		t.Fatalf("v6 VPC on a v4-only cluster must fall back: got %v", got)
	}
}

func TestClaimWalkIsAddressable(t *testing.T) {
	// addOffset must carry across octets, and must not overflow on a v6 pool
	// whose span (2^72 for a /56) does not fit a uint64.
	base := net.ParseIP("10.244.0.0")
	if got := addOffset(base, 258).String(); got != "10.244.1.2" {
		t.Fatalf("carry across octets: got %s", got)
	}
	v6 := net.ParseIP("fd00:10:244::")
	if got := addOffset(v6, 1).String(); got != "fd00:10:244::1" {
		t.Fatalf("v6 offset: got %s", got)
	}
	_, ipnet, _ := net.ParseCIDR("10.244.0.0/16")
	if !isReserved(ipnet, net.ParseIP("10.244.0.0")) || !isReserved(ipnet, net.ParseIP("10.244.0.1")) {
		t.Fatal("network address and the .1 gateway must stay out of the pool")
	}
	if isReserved(ipnet, net.ParseIP("10.244.0.2")) {
		t.Fatal("first usable address must be allocatable")
	}
}

// These tests use sdnfake.NewSimpleClientset (not the newer NewClientset): the
// server-side-apply-aware fake needs an OpenAPI schema for typed conversion that
// isn't wired for our generated types, so Create fails there. The simple tracker
// is the right fit for exercising plugin logic.

func TestParseVPCRef(t *testing.T) {
	cases := []struct {
		anno, podNS  string
		wantNS, want string
	}{
		// bare name: owner namespace defaults to the pod's namespace.
		{"tenant-a", "team-a", "team-a", "tenant-a"},
		// explicit owner namespace.
		{"shared/db", "team-a", "shared", "db"},
		// the pod's namespace is irrelevant once an owner is named.
		{"shared/db", "team-b", "shared", "db"},
		// only the first slash splits; the rest is the (unusual) name.
		{"a/b/c", "ns", "a", "b/c"},
	}
	for _, c := range cases {
		gotNS, got := parseVPCRef(c.anno, c.podNS)
		if gotNS != c.wantNS || got != c.want {
			t.Errorf("parseVPCRef(%q,%q) = (%q,%q), want (%q,%q)",
				c.anno, c.podNS, gotNS, got, c.wantNS, c.want)
		}
	}
}

func TestPortName(t *testing.T) {
	// Names are keyed by the globally-unique VNI so they stay unique across
	// namespaces; the IP's separators (v4 dots, v6 colons) become dashes so the
	// name is a valid DNS-1123 object name.
	if got := portName(100, "10.10.0.2"); got != "v100.10-10-0-2" {
		t.Fatalf("portName = %q, want v100.10-10-0-2", got)
	}
	if got := portName(100, "fd00:a::2"); got != "v100.fd00-a--2" {
		t.Fatalf("portName v6 = %q, want v100.fd00-a--2", got)
	}
}

func TestNextIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.0.0.1", "10.0.0.2"},
		{"10.0.0.255", "10.0.1.0"},
		{"10.0.255.255", "10.1.0.0"},
		// v6 must increment in the full 16-byte width, not collapse to an empty
		// address (the To4()-first bug: cloneIP(nil) is length-0, not nil).
		{"fd00:a::1", "fd00:a::2"},
		{"fd00:a::ffff", "fd00:a::1:0"},
		{"2001:db8::", "2001:db8::1"},
	}
	for _, c := range cases {
		if got := nextIP(net.ParseIP(c.in)).String(); got != c.want {
			t.Errorf("nextIP(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

func newVPC(ns, name string, vni int32, cidr string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{cidr}},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// res builds the resolved attachment attachPort now takes. Index 0 unless given.
func res(vpc *sdnv1alpha1.VPC, vpcNS string, opts ...func(*resolvedAttachment)) resolvedAttachment {
	_, cidr, err := net.ParseCIDR(vpc.Spec.CIDRs[0])
	if err != nil {
		panic(err)
	}
	r := resolvedAttachment{
		attachment: attachment{Index: 0, VPCNamespace: vpcNS, VPCName: vpc.Name, IfName: "eth0"},
		vpc:        vpc,
		cidr:       cidr,
	}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func withIP(ip string) func(*resolvedAttachment) {
	return func(r *resolvedAttachment) { r.IP = net.ParseIP(ip) }
}

func withIndex(i int) func(*resolvedAttachment) {
	return func(r *resolvedAttachment) { r.Index = i; r.IfName = defaultIfName(i) }
}

func withForwarding() func(*resolvedAttachment) {
	return func(r *resolvedAttachment) { r.forwarding = true }
}

func TestClaimIP_FirstAddressAndPortShape(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app-1", "uid-1", "", "")
	if err != nil {
		t.Fatalf("claimIP: %v", err)
	}
	// The first allocatable address is network+2 (.0 network, .1 reserved gw).
	if ip.String() != "10.10.0.2" {
		t.Fatalf("first IP = %s, want 10.10.0.2", ip)
	}
	if port.Name != "v100.10-10-0-2" {
		t.Errorf("port name = %q, want v100.10-10-0-2", port.Name)
	}
	if port.Spec.IP != "10.10.0.2" {
		t.Errorf("port spec ip = %q", port.Spec.IP)
	}
	if port.Spec.VPCRef != (sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "tenant-a"}) {
		t.Errorf("port vpcRef = %+v", port.Spec.VPCRef)
	}
	if port.Spec.Node != "node1" || port.Spec.NodeIP != "192.0.2.1" {
		t.Errorf("port node/nodeIP = %q/%q", port.Spec.Node, port.Spec.NodeIP)
	}
	for k, want := range map[string]string{
		sdnv1alpha1.LabelVPCNamespace: "team-a",
		sdnv1alpha1.LabelVPC:          "tenant-a",
		sdnv1alpha1.LabelPodNamespace: "team-a",
		sdnv1alpha1.LabelPodName:      "app-1",
		sdnv1alpha1.LabelPodUID:       "uid-1",
	} {
		if port.Labels[k] != want {
			t.Errorf("label %q = %q, want %q", k, port.Labels[k], want)
		}
	}
	// The sever finalizer is what makes revocation replayable: deletion waits
	// for the node agent's acknowledgement.
	if len(port.Finalizers) != 1 || port.Finalizers[0] != sdnv1alpha1.FinalizerSever {
		t.Errorf("finalizers = %v, want [%s]", port.Finalizers, sdnv1alpha1.FinalizerSever)
	}
}

func TestClaimIP_IPv6(t *testing.T) {
	// A v6 VPC CIDR must allocate natively: network+2 in the full 16-byte width,
	// a v6-safe Port name, and the v6 address (not a truncated/empty one) in spec.
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant6", 200, "fd00:a::/64")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app6", "uid-6", "", "")
	if err != nil {
		t.Fatalf("claimIP v6: %v", err)
	}
	if ip.String() != "fd00:a::2" {
		t.Fatalf("first v6 IP = %s, want fd00:a::2", ip)
	}
	if port.Name != "v200.fd00-a--2" {
		t.Errorf("port name = %q, want v200.fd00-a--2", port.Name)
	}
	// The fabric IP stays v4 (from the node pod CIDR underlay) even for a v6 pod.
	if port.Spec.IP != "fd00:a::2" {
		t.Errorf("port spec ip = %q", port.Spec.IP)
	}
}

func TestClaimIP_SkipsUsedAddresses(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app-1", "uid-1", "", ""); err != nil {
		t.Fatalf("first attachPort: %v", err)
	}
	ip, _, _, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app-2", "uid-2", "", "")
	if err != nil {
		t.Fatalf("second attachPort: %v", err)
	}
	if ip.String() != "10.10.0.3" {
		t.Fatalf("second IP = %s, want 10.10.0.3 (skipping the claimed .2)", ip)
	}
}

func TestClaimIP_RetriesOnNameCollision(t *testing.T) {
	// A Port already holds the name the first candidate (.2) would take, but
	// without the VPC labels and IP — i.e. a concurrent claimant that won the
	// name. attachPort must collide on AlreadyExists and advance to .3.
	collide := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-10-0-2"}}
	client := sdnfake.NewSimpleClientset(collide)
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app-1", "uid-1", "", "")
	if err != nil {
		t.Fatalf("claimIP: %v", err)
	}
	if ip.String() != "10.10.0.3" || port.Name != "v100.10-10-0-3" {
		t.Fatalf("after collision got %s / %q, want 10.10.0.3 / v100.10-10-0-3", ip, port.Name)
	}
}

func TestClaimIP_ExhaustionErrors(t *testing.T) {
	// /30 has only .2 allocatable after reserving .0/.1; pre-claim it and .3.
	mk := func(name, ip string) *sdnv1alpha1.Port {
		return &sdnv1alpha1.Port{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
				sdnv1alpha1.LabelVPCNamespace: "team-a",
				sdnv1alpha1.LabelVPC:          "tenant-a",
			}},
			Spec: sdnv1alpha1.PortSpec{IP: ip},
		}
	}
	client := sdnfake.NewSimpleClientset(mk("v200.10-0-0-2", "10.0.0.2"), mk("v200.10-0-0-3", "10.0.0.3"))
	vpc := newVPC("team-a", "tenant-a", 200, "10.0.0.0/30")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(t.Context(), client, res(vpc, "team-a"), state, "team-a", "app-1", "uid-1", "", ""); err == nil {
		t.Fatal("attachPort on exhausted VPC = nil error, want exhaustion error")
	}
}

func TestRequireVPCBinding(t *testing.T) {
	binding := func(ns, vpcNS, vpcName string) *sdnv1alpha1.VPCBinding {
		return &sdnv1alpha1.VPCBinding{
			ObjectMeta: metav1.ObjectMeta{Name: vpcName, Namespace: ns},
			Spec:       sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName}},
		}
	}

	cases := []struct {
		name              string
		objs              []*sdnv1alpha1.VPCBinding
		podNS, vNS, vName string
		wantAllow         bool
	}{
		{"no binding is denied", nil, "team-a", "team-a", "tenant-a", false},
		{"matching binding allows", []*sdnv1alpha1.VPCBinding{binding("team-a", "team-a", "tenant-a")}, "team-a", "team-a", "tenant-a", true},
		{"same-namespace still needs a binding", nil, "team-a", "team-a", "tenant-a", false},
		{"different VPC name is denied", []*sdnv1alpha1.VPCBinding{binding("team-a", "team-a", "other")}, "team-a", "team-a", "tenant-a", false},
		{"different owner namespace is denied", []*sdnv1alpha1.VPCBinding{binding("team-a", "shared", "tenant-a")}, "team-a", "team-a", "tenant-a", false},
		{"binding in another namespace does not count", []*sdnv1alpha1.VPCBinding{binding("team-b", "team-a", "tenant-a")}, "team-a", "team-a", "tenant-a", false},
		{"cross-namespace grant allows", []*sdnv1alpha1.VPCBinding{binding("team-a", "shared", "db")}, "team-a", "shared", "db", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := make([]runtime.Object, 0, len(c.objs))
			for _, o := range c.objs {
				objs = append(objs, o)
			}
			client := sdnfake.NewSimpleClientset(objs...)
			_, err := requireVPCBinding(t.Context(), client, c.podNS, c.vNS, c.vName)
			if c.wantAllow && err != nil {
				t.Fatalf("want allowed, got error: %v", err)
			}
			if !c.wantAllow && err == nil {
				t.Fatal("want denied, got nil error")
			}
		})
	}
}

// A rollback runs precisely when the operation went wrong, and the commonest way
// for it to go wrong is now the operation context expiring. If the release
// inherited that cancellation it would fail instantly and leak the claim it
// exists to return.
//
// The release is asserted through a RECORDED ACTION rather than by reading the
// store back, because client-go's fake does not implement DeleteCollection
// against its object tracker at all — measured: the object survives even with an
// empty selector. Reading the store would therefore have tested the fake, and
// tested it wrongly. What is under test is ours: that the call is still issued,
// with the right selector, against a context derived from a dead parent.
func TestReleaseFabricIPsRunsAfterTheOperationContextDied(t *testing.T) {
	client := localfake.NewSimpleClientset(&localv1alpha1.FabricIP{
		ObjectMeta: metav1.ObjectMeta{
			Name:   localv1alpha1.FabricIPName("10.244.0.7"),
			Labels: map[string]string{labelFabricPodUID: "uid-1"},
		},
		Spec: localv1alpha1.FabricIPSpec{Address: "10.244.0.7", PodUID: "uid-1"},
	})
	var issued []string
	client.PrependReactor("delete-collection", "fabricips",
		func(a k8stesting.Action) (bool, runtime.Object, error) {
			issued = append(issued, a.(k8stesting.DeleteCollectionActionImpl).ListRestrictions.Labels.String())
			return true, nil, nil
		})

	dead, cancel := context.WithCancel(t.Context())
	cancel() // the ADD blew its budget
	if dead.Err() == nil {
		t.Fatal("parent context should be cancelled")
	}

	cctx, ccancel := cleanupContext(dead)
	defer ccancel()
	if err := cctx.Err(); err != nil {
		t.Fatalf("cleanup context inherited the parent's cancellation: %v", err)
	}
	if _, ok := cctx.Deadline(); !ok {
		t.Fatal("cleanup context has no deadline: a rollback could hang forever")
	}

	releaseFabricIPs(cctx, client, "uid-1")

	if len(issued) != 1 {
		t.Fatalf("release issued %d delete-collection calls against a dead parent, want 1", len(issued))
	}
	if !strings.Contains(issued[0], "uid-1") {
		t.Errorf("release selector = %q, want it scoped to the pod UID", issued[0])
	}
}

// A requested address must be claimed EXACTLY. The whole point of the field is
// that a gateway, a resolver or a peer-configured database gets the address it
// was promised.
func TestAttachPortStaticIPClaimsExactly(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	ip, _, port, bound, err := attachPort(t.Context(), client,
		res(vpc, "team-a", withIP("10.10.0.42")), state, "team-a", "app-1", "uid-1", "", "")
	if err != nil {
		t.Fatalf("static claim: %v", err)
	}
	if bound {
		t.Error("a fresh claim is not a bind")
	}
	if ip.String() != "10.10.0.42" {
		t.Fatalf("got %s, want the requested 10.10.0.42", ip)
	}
	if port.Name != "v100.10-10-0-42" {
		t.Errorf("port name = %q, want v100.10-10-0-42 (the name IS the claim)", port.Name)
	}
}

// Taken is an ERROR, not a cue to walk on. Silently handing back a different
// address is the failure the field exists to remove.
func TestAttachPortStaticIPTakenIsHardError(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(t.Context(), client,
		res(vpc, "team-a", withIP("10.10.0.42")), state, "team-a", "app-1", "uid-1", "", ""); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	ip, _, _, _, err := attachPort(t.Context(), client,
		res(vpc, "team-a", withIP("10.10.0.42")), state, "team-a", "app-2", "uid-2", "", "")
	if err == nil {
		t.Fatalf("second claim of a taken address returned %s instead of failing", ip)
	}
}

func TestAttachPortStaticIPOutsideCIDRIsRefused(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	if _, _, _, _, err := attachPort(t.Context(), client,
		res(vpc, "team-a", withIP("10.99.0.1")), state, "team-a", "app-1", "uid-1", "", ""); err == nil {
		t.Fatal("an address outside the VPC CIDR must be refused")
	}
}

// The forwarding grant rides from the VPCBinding onto the Port, and it must land
// on Forwarding — never on Gateway, which is what desiredGateways reads to
// program gateways[vni]. A tenant firewall is not its VPC's door.
func TestAttachPortForwardingIsSeparateFromGateway(t *testing.T) {
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	client := sdnfake.NewSimpleClientset()
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	_, _, port, _, err := attachPort(t.Context(), client,
		res(vpc, "team-a", withForwarding()), state, "team-a", "fw", "uid-fw", "", "")
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if !port.Spec.Forwarding {
		t.Error("the grant did not reach Port.spec.forwarding")
	}
	if port.Spec.Gateway {
		t.Error("a forwarding port must NOT be marked Gateway: it is not the VPC's egress door")
	}

	client2 := sdnfake.NewSimpleClientset()
	_, _, plain, _, err := attachPort(t.Context(), client2,
		res(newVPC("team-a", "tenant-a", 100, "10.10.0.0/24"), "team-a"), state, "team-a", "app", "uid-a", "", "")
	if err != nil {
		t.Fatalf("attach plain: %v", err)
	}
	if plain.Spec.Forwarding {
		t.Error("an ungranted attachment must not be forwarding")
	}
}

// A multi-NIC VM has one persistent Port per interface. Selecting them by
// {vpc, vm-name} alone matches both and the first returned is arbitrary, so the
// VM's interfaces would swap addresses across restarts. The NIC index pins each.
func TestAttachPortMultiNICVMBindsThePortForItsInterface(t *testing.T) {
	vpc := newVPC("team-a", "tenant-a", 100, "10.10.0.0/24")
	state := &datapath.AgentState{NodeName: "node1", NodeIP: "192.0.2.1"}

	persistent := func(nic int, ip, mac string) *sdnv1alpha1.Port {
		return &sdnv1alpha1.Port{
			ObjectMeta: metav1.ObjectMeta{
				Name: "v100." + strings.ReplaceAll(ip, ".", "-"),
				Labels: map[string]string{
					labelVPCNamespace: "team-a",
					labelVPC:          "tenant-a",
					labelVMName:       "vm1",
					labelVMNIC:        strconv.Itoa(nic),
				},
			},
			Spec: sdnv1alpha1.PortSpec{
				VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "tenant-a"},
				IP:     ip, MAC: mac, Node: "node1", NodeIP: "192.0.2.1",
			},
		}
	}
	client := sdnfake.NewSimpleClientset(
		persistent(0, "10.10.0.10", "02:00:00:00:00:aa"),
		persistent(1, "10.10.0.11", "02:00:00:00:00:bb"),
	)

	for _, c := range []struct {
		nic             int
		wantIP, wantMAC string
	}{
		{0, "10.10.0.10", "02:00:00:00:00:aa"},
		{1, "10.10.0.11", "02:00:00:00:00:bb"},
	} {
		ip, mac, _, bound, err := attachPort(t.Context(), client,
			res(vpc, "team-a", withIndex(c.nic)), state, "team-a", "virt-launcher-vm1", "uid-l1", "vm1", "")
		if err != nil {
			t.Fatalf("nic %d: %v", c.nic, err)
		}
		if !bound {
			t.Fatalf("nic %d: should have BOUND the persistent Port, not claimed a fresh one", c.nic)
		}
		if ip.String() != c.wantIP || mac.String() != c.wantMAC {
			t.Errorf("nic %d bound %s/%s, want %s/%s", c.nic, ip, mac, c.wantIP, c.wantMAC)
		}
	}
}
