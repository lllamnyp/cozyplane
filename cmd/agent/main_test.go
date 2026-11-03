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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	corefake "k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
)

func TestSeverFinalizerRetainedOnCurrentPortLookupFailure(t *testing.T) {
	port := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "port-uid", DeletionTimestamp: new(metav1.Now()), Finalizers: []string{sdnv1alpha1.FinalizerSever}},
		Spec:       sdnv1alpha1.PortSpec{IP: "10.0.0.2", PodNamespace: "tenant", PodName: "workload"},
	}
	sdn := sdnfake.NewSimpleClientset(port)
	core := corefake.NewClientset()
	failedRead := false
	sdn.PrependReactor("get", "ports", func(clienttesting.Action) (bool, runtime.Object, error) {
		if failedRead {
			return false, nil, nil
		}
		failedRead = true
		return true, nil, fmt.Errorf("temporary API failure")
	})
	releaseSeveredPort(t.Context(), sdn, core, nil, port, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !failedRead || len(core.Actions()) != 0 {
		t.Fatal("failed current-Port confirmation continued cleanup")
	}
	latest, err := sdn.SdnV1alpha1().Ports().Get(t.Context(), port.Name, metav1.GetOptions{})
	if err != nil || len(latest.Finalizers) != 1 || latest.Finalizers[0] != sdnv1alpha1.FinalizerSever {
		t.Fatalf("sever finalizer lost after failed cleanup: port=%v err=%v", latest, err)
	}
	for _, action := range sdn.Actions() {
		if action.GetVerb() == "update" {
			t.Fatal("acknowledged an unsuccessful sever")
		}
	}
}

func TestSeverIgnoresEventForReplacedPortUID(t *testing.T) {
	old := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "old", DeletionTimestamp: new(metav1.Now()), Finalizers: []string{sdnv1alpha1.FinalizerSever}}, Spec: sdnv1alpha1.PortSpec{PodNamespace: "tenant", PodName: "pod"}}
	current := old.DeepCopy()
	current.UID = "current"
	sdn := sdnfake.NewSimpleClientset(current)
	core := corefake.NewClientset()
	releaseSeveredPort(t.Context(), sdn, core, nil, old, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(core.Actions()) != 0 {
		t.Fatal("stale event attempted to sever current sandbox")
	}
	got, err := sdn.SdnV1alpha1().Ports().Get(t.Context(), current.Name, metav1.GetOptions{})
	if err != nil || got.UID != current.UID || len(got.Finalizers) != 1 {
		t.Fatal("stale event changed replacement Port", got, err)
	}
}

func TestEnsureCNIConf(t *testing.T) {
	t.Run("disabled leaves CNI directory untouched", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "not-created")
		if _, err := configureCNIConf(dir, "10-cozyplane.conflist", 1450, false); err != nil {
			t.Fatalf("ensureCNIConf disabled: %v", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("disabled CNI writer created %q or returned an unexpected stat error: %v", dir, err)
		}
	})

	t.Run("enabled writes a valid standalone conflist", func(t *testing.T) {
		dir := t.TempDir()
		name := "10-cozyplane.conflist"
		if _, err := configureCNIConf(dir, name, 1400, true); err != nil {
			t.Fatalf("ensureCNIConf enabled: %v", err)
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read conflist: %v", err)
		}
		var conf struct {
			Plugins []struct {
				Type string `json:"type"`
				MTU  int    `json:"mtu"`
			} `json:"plugins"`
		}
		if err := json.Unmarshal(body, &conf); err != nil {
			t.Fatalf("decode conflist: %v", err)
		}
		if len(conf.Plugins) != 1 || conf.Plugins[0].Type != "cozyplane" || conf.Plugins[0].MTU != 1400 {
			t.Fatalf("unexpected conflist: %+v", conf)
		}
	})
}

func half(ns, name, localVPC, peerNS, peerVPC string) *sdnv1alpha1.VPCPeering {
	return &sdnv1alpha1.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.VPCPeeringSpec{
			VPCRef:  sdnv1alpha1.LocalVPCRef{Name: localVPC},
			PeerRef: sdnv1alpha1.VPCRef{Namespace: peerNS, Name: peerVPC},
		},
	}
}

// vpcTable returns a VPC lookup over "namespace/name" keys.
func vpcTable(m map[string]*sdnv1alpha1.VPC) func(namespace, name string) *sdnv1alpha1.VPC {
	return func(namespace, name string) *sdnv1alpha1.VPC {
		return m[namespace+"/"+name]
	}
}

func vpcWith(vni int32, cidrs ...string) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		Spec:   sdnv1alpha1.VPCSpec{CIDRs: cidrs},
		Status: sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

func gatewayPort(name, ip, node, nodeIP string, gateway bool) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       sdnv1alpha1.PortSpec{IP: ip, Node: node, NodeIP: nodeIP, Gateway: gateway},
	}
}

// The gateways-map contract: one entry per VNI with a gateway Port, local
// (nil nodeIP) when the Port is on this node, remote otherwise; non-gateway
// Ports and unparsable names contribute nothing.
func TestDesiredGateways(t *testing.T) {
	ports := []*sdnv1alpha1.Port{
		gatewayPort("v101.10-70-0-1", "10.70.0.1", "self", "10.4.0.1", true),
		gatewayPort("v102.10-71-0-1", "10.71.0.1", "other", "10.4.0.2", true),
		gatewayPort("v101.10-70-0-2", "10.70.0.2", "other", "10.4.0.2", false), // tenant port: ignored
		gatewayPort("bogus", "10.72.0.1", "self", "10.4.0.1", true),            // unparsable name: ignored
	}
	vpcs := []*sdnv1alpha1.VPC{vpcObj("tenant-a", "net-a", 101), vpcObj("tenant-a", "net-b", 102)}
	for _, p := range ports {
		p.Spec.VPCRef = sdnv1alpha1.VPCRef{Namespace: "tenant-a", Name: "net-a"}
	}
	ports[1].Spec.VPCRef.Name = "net-b"
	gws := []*sdnv1alpha1.VPCGateway{fallbackBoundary(vpcs[0], "10.70.0.0/24"), fallbackBoundary(vpcs[1], "10.71.0.0/24")}
	got := desiredGateways(ports, vpcs, gws, "self")
	if len(got) != 2 {
		t.Fatalf("got %d gateways, want 2: %+v", len(got), got)
	}
	if gw := got[101]; gw.nodeIP != nil || gw.ip.String() != "10.70.0.1" {
		t.Errorf("vni 101 = %+v, want local 10.70.0.1", gw)
	}
	if gw := got[102]; gw.nodeIP == nil || gw.nodeIP.String() != "10.4.0.2" {
		t.Errorf("vni 102 = %+v, want remote via 10.4.0.2", gw)
	}
}

// desiredFloating programs every floating IP whose target has a live Port
// ANYWHERE in the cluster — not just here (docs/floating-ha.md). The announcer
// must be able to resolve an address whose pod is on another node in order to
// forward to it, so the mapping is cluster-wide; what is node-specific is the
// announcement, not the mapping. An unassigned address, or a target with no live
// Port at all, still contributes nothing.
func TestDesiredFloating(t *testing.T) {
	ports := []*sdnv1alpha1.Port{
		vpcPort("v101.10-0-0-5", "team-a", "vpc-a", "10.0.0.5", "self"),
		vpcPort("v101.10-0-0-6", "team-a", "vpc-a", "10.0.0.6", "other"),
	}
	fips := []*sdnv1alpha1.FloatingIP{
		floatingIPObj("team-a", "web", "vpc-a", "10.0.0.5", "203.0.113.7"),   // target here
		floatingIPObj("team-a", "api", "vpc-a", "10.0.0.6", "203.0.113.8"),   // target elsewhere: still programmed
		floatingIPObj("team-a", "unset", "vpc-a", "10.0.0.7", ""),            // no address yet: skipped
		floatingIPObj("team-a", "nopod", "vpc-a", "10.0.0.9", "203.0.113.9"), // no live Port: skipped
	}
	got := desiredFloating(fips, ports, []*sdnv1alpha1.VPC{{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "vpc-a"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}})
	if len(got) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(got), got)
	}
	if v, ok := got["203.0.113.7"]; !ok || v.vpcIP != "10.0.0.5" || v.vni != 101 || v.node != "self" {
		t.Errorf("203.0.113.7 = %+v (ok=%v), want {10.0.0.5 101 self}", v, ok)
	}
	// The decisive one: a target on another node is programmed here too, and
	// carries that node — from_uplink needs it to forward over the overlay.
	if v, ok := got["203.0.113.8"]; !ok || v.vpcIP != "10.0.0.6" || v.node != "other" {
		t.Errorf("203.0.113.8 = %+v (ok=%v), want {10.0.0.6 101 other}", v, ok)
	}
}

func TestDesiredFloatingRejectsTerminatingTarget(t *testing.T) {
	port := vpcPort("v101.10-0-0-5", "tenant-a", "net", "10.0.0.5", "node-a")
	now := metav1.Now()
	port.DeletionTimestamp = &now
	fip := floatingIPObj("tenant-a", "public", "net", port.Spec.IP, "203.0.113.10")
	got := desiredFloating([]*sdnv1alpha1.FloatingIP{fip}, []*sdnv1alpha1.Port{port}, []*sdnv1alpha1.VPC{{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}})
	if len(got) != 0 {
		t.Fatalf("terminating target still published: %+v", got)
	}
}

func TestDesiredFloatingRequiresCurrentVPCClaim(t *testing.T) {
	for _, mutation := range []string{"old-vni", "wrong-address", "missing-vpc", "terminating-vpc", "terminating-fip"} {
		t.Run(mutation, func(t *testing.T) {
			port := vpcPort("v101.10-0-0-5", "tenant-a", "net", "10.0.0.5", "node-a")
			vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
			fip := floatingIPObj(vpc.Namespace, "public", vpc.Name, port.Spec.IP, "203.0.113.10")
			vpcs := []*sdnv1alpha1.VPC{vpc}
			switch mutation {
			case "old-vni":
				vpc.Status.VNI = 102
			case "wrong-address":
				port.Spec.IP = "10.0.0.99"
				fip.Spec.Target = port.Spec.IP
			case "missing-vpc":
				vpcs = nil
			case "terminating-vpc":
				now := metav1.Now()
				vpc.DeletionTimestamp = &now
			case "terminating-fip":
				now := metav1.Now()
				fip.DeletionTimestamp = &now
			}
			if got := desiredFloating([]*sdnv1alpha1.FloatingIP{fip}, []*sdnv1alpha1.Port{port}, vpcs); len(got) != 0 {
				t.Fatalf("stale target projected: %+v", got)
			}
		})
	}
}

func TestDesiredFloatingHonorsExclusiveTarget(t *testing.T) {
	for _, pendingWinner := range []bool{false, true} {
		t.Run(map[bool]string{false: "assigned-winner", true: "pending-winner"}[pendingWinner], func(t *testing.T) {
			port := vpcPort("v101.10-0-0-5", "tenant-a", "net", "10.0.0.5", "node-a")
			vpc := &sdnv1alpha1.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Status: sdnv1alpha1.VPCStatus{VNI: 101}}
			winner := floatingIPObj(vpc.Namespace, "a-winner", vpc.Name, port.Spec.IP, "203.0.113.10")
			loser := floatingIPObj(vpc.Namespace, "z-loser", vpc.Name, port.Spec.IP, "203.0.113.11")
			if pendingWinner {
				winner.Status.Address = ""
			}
			for _, fips := range [][]*sdnv1alpha1.FloatingIP{{winner, loser}, {loser, winner}} {
				got := desiredFloating(fips, []*sdnv1alpha1.Port{port}, []*sdnv1alpha1.VPC{vpc})
				if _, exists := got[loser.Status.Address]; exists {
					t.Fatalf("loser stale address projected: %+v", got)
				}
				if (pendingWinner && len(got) != 0) || (!pendingWinner && len(got) != 1) {
					t.Fatalf("invalid winner projection: %+v", got)
				}
			}
			// Deletion must promote the successor, independently of stale status.
			now := metav1.Now()
			winner.DeletionTimestamp = &now
			got := desiredFloating([]*sdnv1alpha1.FloatingIP{winner, loser}, []*sdnv1alpha1.Port{port}, []*sdnv1alpha1.VPC{vpc})
			if len(got) != 1 || got[loser.Status.Address].vni != 101 {
				t.Fatalf("successor not promoted: %+v", got)
			}
		})
	}
}

func vpcPort(name, ns, vpc, ip, node string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: sdnv1alpha1.PortSpec{
			VPCRef: sdnv1alpha1.VPCRef{Namespace: ns, Name: vpc},
			IP:     ip,
			Node:   node,
		},
	}
}

func floatingIPObj(ns, name, vpc, target, address string) *sdnv1alpha1.FloatingIP {
	return &sdnv1alpha1.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.FloatingIPSpec{
			VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc},
			Target: target,
		},
		Status: sdnv1alpha1.FloatingIPStatus{Address: address},
	}
}

func TestVNIFromPortName(t *testing.T) {
	cases := []struct {
		name string
		vni  uint32
		ok   bool
	}{
		{"v101.10-70-0-1", 101, true},
		{"v1.10-244-0-5", 0, false},
		{"bogus", 0, false},
		{"v.10-70-0-1", 0, false},
		{"vx.10-70-0-1", 0, false},
		{"v0.10-70-0-1", 0, false},
	}
	for _, tc := range cases {
		vni, ok := vniFromPortName(tc.name)
		if vni != tc.vni || ok != tc.ok {
			t.Errorf("vniFromPortName(%q) = (%d,%v), want (%d,%v)", tc.name, vni, ok, tc.vni, tc.ok)
		}
	}
}

// The datapath contract: a pair is programmed iff both halves exist, mutually
// reference each other, both VPCs have VNIs, and their CIDRs are disjoint.
// Everything else stays out of the peers map.
func TestDesiredPeerPairs(t *testing.T) {
	vnis := vpcTable(map[string]*sdnv1alpha1.VPC{
		"team-a/vpc-a": vpcWith(100, "10.10.0.0/24"),
		"team-b/vpc-b": vpcWith(101, "10.20.0.0/24"),
		"team-c/vpc-c": vpcWith(102, "10.30.0.0/24"),
		// vpc-d overlaps vpc-a: the two may coexist, but never peer.
		"team-d/vpc-d": vpcWith(103, "10.10.0.0/16"),
	})

	cases := []struct {
		name     string
		peerings []*sdnv1alpha1.VPCPeering
		want     map[[2]uint32]bool
	}{
		{
			name: "mutual match programs one normalized pair",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"), // higher VNI listed first
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
			},
			want: map[[2]uint32]bool{{100, 101}: true},
		},
		{
			name: "a lone half programs nothing (pending request)",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "non-reciprocal references do not match",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
				// team-b consents to vpc-c, not vpc-a.
				half("team-b", "to-c", "vpc-b", "team-c", "vpc-c"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "missing VNI keeps the pair unprogrammed",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-x", "vpc-a", "team-x", "vpc-x"), // vpc-x has no VNI
				half("team-x", "to-a", "vpc-x", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{},
		},
		{
			name: "duplicate grants collapse to one pair",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b-1", "vpc-a", "team-b", "vpc-b"),
				half("team-a", "to-b-2", "vpc-a", "team-b", "vpc-b"),
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{{100, 101}: true},
		},
		{
			name: "independent peerings program independent pairs",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
				half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
				half("team-b", "to-c", "vpc-b", "team-c", "vpc-c"),
				half("team-c", "to-b", "vpc-c", "team-b", "vpc-b"),
			},
			// Pairwise, non-transitive: a<->b and b<->c, never a<->c.
			want: map[[2]uint32]bool{{100, 101}: true, {101, 102}: true},
		},
		{
			name: "overlapping CIDRs never peer, even mutually matched",
			peerings: []*sdnv1alpha1.VPCPeering{
				half("team-a", "to-d", "vpc-a", "team-d", "vpc-d"),
				half("team-d", "to-a", "vpc-d", "team-a", "vpc-a"),
			},
			want: map[[2]uint32]bool{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			links := desiredPeerLinks(tc.peerings, vnis)
			got := map[[2]uint32]bool{}
			for _, l := range links {
				got[[2]uint32{l.a, l.b}] = true
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for pair := range tc.want {
				if !got[pair] {
					t.Errorf("missing pair %v (got %v)", pair, got)
				}
			}
		})
	}
}

// A live peering also programs delivery entries (each side's CIDR resolves to
// the other from its own scope) — the datapath fact that makes peered pods
// findable under net-scoped delivery.
func TestDesiredPeerLinksCarryCIDRs(t *testing.T) {
	vnis := vpcTable(map[string]*sdnv1alpha1.VPC{
		"team-a/vpc-a": vpcWith(100, "10.10.0.0/24"),
		"team-b/vpc-b": vpcWith(101, "10.20.0.0/24"),
	})
	links := desiredPeerLinks([]*sdnv1alpha1.VPCPeering{
		half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		half("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
	}, vnis)
	if len(links) != 1 {
		t.Fatalf("got %d links, want 1: %+v", len(links), links)
	}
	l := links[0]
	if l.a != 100 || l.b != 101 || len(l.cidrsA) != 1 || len(l.cidrsB) != 1 || l.cidrsA[0] != "10.10.0.0/24" || l.cidrsB[0] != "10.20.0.0/24" {
		t.Errorf("link = %+v, want {100 101 10.10.0.0/24 10.20.0.0/24}", l)
	}
}

// The chart passes "$(HOST_IP):9411" and the kubelet substitutes the node's
// primary InternalIP, which is IPv6 on a v6-first cluster. Unbracketed, that is
// not a parseable listen address, and the agent would come up healthy serving no
// metrics at all.
func TestNormalizeBindAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		// The v6 case this exists for, and the same address already correct.
		{"fd00:10:244::11:9411", "[fd00:10:244::11]:9411"},
		{"[fd00:10:244::11]:9411", "[fd00:10:244::11]:9411"},
		{"::1:9411", "[::1]:9411"},
		// v4 and port-only forms must be untouched.
		{"10.20.100.11:9411", "10.20.100.11:9411"},
		{":9411", ":9411"},
		// Not an address: handed through rather than mangled.
		{"fd00:10:244::11", "fd00:10:244::11"},
		{"localhost:9411", "localhost:9411"},
		{"9411", "9411"},
	} {
		if got := normalizeBindAddr(tc.in); got != tc.want {
			t.Errorf("normalizeBindAddr(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Whatever it returns for a v6 input must actually be listenable.
	addr := normalizeBindAddr("[::1]:0")
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("normalized %q is not listenable: %v", addr, err)
	}
	l.Close()
}

func TestDesiredPeerLinksCarryBothAddressFamilies(t *testing.T) {
	a, b := vpcWith(100, "10.10.0.0/24"), vpcWith(101, "10.20.0.0/24")
	a.Spec.CIDRs = append(a.Spec.CIDRs, "fd00:10::/64")
	b.Spec.CIDRs = append(b.Spec.CIDRs, "fd00:20::/64")
	links := desiredPeerLinks([]*sdnv1alpha1.VPCPeering{half("team-a", "to-b", "vpc-a", "team-b", "vpc-b"), half("team-b", "to-a", "vpc-b", "team-a", "vpc-a")}, vpcTable(map[string]*sdnv1alpha1.VPC{"team-a/vpc-a": a, "team-b/vpc-b": b}))
	networks := desiredPeerNetworks(links)
	if len(networks) != 4 {
		t.Fatalf("dual-stack peering omitted delivery entries: %+v", networks)
	}
	want := map[string]uint32{"10.10.0.0/24": 100, "fd00:10::/64": 100, "10.20.0.0/24": 101, "fd00:20::/64": 101}
	for _, entry := range networks {
		if want[entry.CIDR] != entry.Net || entry.Scope == entry.Net {
			t.Fatalf("wrong peer identity/scope: %+v", entry)
		}
		delete(want, entry.CIDR)
	}
	if len(want) != 0 {
		t.Fatalf("missing dual-stack routes: %+v", want)
	}
}

func TestSeverFinalizerCannotAcknowledgeAnotherNode(t *testing.T) {
	old := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", UID: "same-uid", DeletionTimestamp: new(metav1.Now()), Finalizers: []string{sdnv1alpha1.FinalizerSever}}, Spec: sdnv1alpha1.PortSpec{IP: "10.0.0.2", Node: "source", PodNamespace: "tenant", PodName: "workload"}}
	current := old.DeepCopy()
	current.Spec.Node = "target"
	sdn := sdnfake.NewSimpleClientset(current)
	core := corefake.NewClientset()
	releaseSeveredPort(t.Context(), sdn, core, nil, old, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if len(core.Actions()) != 0 {
		t.Fatal("old source attempted to sever target sandbox")
	}
	got, err := sdn.SdnV1alpha1().Ports().Get(t.Context(), old.Name, metav1.GetOptions{})
	if err != nil || len(got.Finalizers) != 1 {
		t.Fatal("source acknowledged target revocation", got, err)
	}
}
