package main

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type peeringLegacySink struct {
	mu      sync.Mutex
	peers   map[[2]uint32]bool
	rows    []datapath.PeerNet
	replays int
}

func TestDesiredPeerLinksRejectsEntireInvalidLegacyVPC(t *testing.T) {
	peerings := []*sdn.VPCPeering{half("tenant-a", "to-b", "net", "tenant-b", "net"), half("tenant-b", "to-a", "net", "tenant-a", "net")}
	for _, bad := range [][]string{{"invalid"}, {"10.1.0.0/24", "invalid"}, {strings.Repeat("x", 1<<20)}, make([]string, sdn.MaxVPCCIDRs+1)} {
		lookup := vpcTable(map[string]*sdn.VPC{"tenant-a/net": vpcWith(101, bad...), "tenant-b/net": vpcWith(102, "10.2.0.0/24")})
		if got := desiredPeerLinks(peerings, lookup); len(got) != 0 {
			t.Fatal("invalid full VPC spec admitted to peering", len(got))
		}
	}
	for _, cidr := range []string{"10.1.0.7/24", "::ffff:10.1.0.0/120", "2001:db8::/64"} {
		lookup := vpcTable(map[string]*sdn.VPC{"tenant-a/net": vpcWith(101, cidr), "tenant-b/net": vpcWith(102, "10.2.0.0/24")})
		if got := desiredPeerLinks(peerings, lookup); len(got) != 1 {
			t.Fatal("valid VPC syntax lost peering", cidr, len(got))
		}
	}
}

func (s *peeringLegacySink) Peers() (map[[2]uint32]bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := map[[2]uint32]bool{}
	for pair := range s.peers {
		copy[pair] = true
	}
	return copy, nil
}

func (s *peeringLegacySink) SetPeer(a, b uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[[2]uint32{a, b}] = true
	return nil
}

func (s *peeringLegacySink) DelPeer(a, b uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.peers, [2]uint32{a, b})
	return nil
}

func (s *peeringLegacySink) SyncPeerNetworks(rows []datapath.PeerNet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replays++
	// Like the real Manager's preflight, reject invalid input before replacing
	// the current partition. This exposes poison input emitted by the watcher.
	for _, row := range rows {
		if err := sdn.ValidateVPCCIDRs([]string{row.CIDR}); err != nil {
			return err
		}
	}
	s.rows = append([]datapath.PeerNet(nil), rows...)
	return nil
}

func TestPeeringReplayInvalidLegacyCannotRetainUnrelatedRoutes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	a := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.1.0.0/24"}}, Status: sdn.VPCStatus{VNI: 101}}
	b := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-b", Name: "net"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.2.0.0/24"}}, Status: sdn.VPCStatus{VNI: 102}}
	client := sdnfake.NewSimpleClientset(a, b, half(a.Namespace, "to-b", "net", b.Namespace, "net"), half(b.Namespace, "to-a", "net", a.Namespace, "net"))
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	// Old pinned rows from a revoked, unrelated pair must still be pruned.
	sink := &peeringLegacySink{peers: map[[2]uint32]bool{}, rows: []datapath.PeerNet{{Scope: 201, CIDR: "10.3.0.0/24", Net: 202}}}
	watchPeerings(ctx, factory, sink, slog.New(slog.NewTextHandler(io.Discard, nil)), func() {})
	// Introduce malformed legacy data before the complete initial list.
	a.Spec.CIDRs = []string{"invalid"}
	if _, err := client.SdnV1alpha1().VPCs(a.Namespace).Update(ctx, a, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		applied := sink.replays > 0
		sink.mu.Unlock()
		if applied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cache replay never ran")
		}
		time.Sleep(time.Millisecond)
	}
	sink.mu.Lock()
	if len(sink.rows) != 0 || len(sink.peers) != 0 {
		t.Errorf("invalid legacy input retained historical rows or published grant: rows=%v peers=%v", sink.rows, sink.peers)
	}
	sink.mu.Unlock()
	a.Spec.CIDRs = []string{"10.1.0.0/24"}
	if _, err := client.SdnV1alpha1().VPCs(a.Namespace).Update(ctx, a, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		recovered := len(sink.rows) == 2 && len(sink.peers) == 1
		sink.mu.Unlock()
		if recovered {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("corrected VPC did not restore peer delivery")
		}
		time.Sleep(time.Millisecond)
	}
}
