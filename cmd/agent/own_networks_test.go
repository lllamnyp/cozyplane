package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/datapath"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	sdninformers "github.com/lllamnyp/cozyplane/pkg/generated/sdn/informers/externalversions"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktesting "k8s.io/client-go/testing"
)

type ownNetworkTestKey struct {
	net  uint32
	cidr string
}

func TestOwnNetworksOversizedLegacyCannotBlockHealthyReplay(t *testing.T) {
	legacy := &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: make([]string, maxOwnNetworkInputs)}, Status: sdn.VPCStatus{VNI: 101}}
	for i := range legacy.Spec.CIDRs {
		legacy.Spec.CIDRs[i] = "10.1.0.0/24"
	}
	healthy := &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: []string{"10.2.0.0/24"}}, Status: sdn.VPCStatus{VNI: 102}}
	got, err := compileOwnNetworks(t.Context(), []*sdn.VPC{legacy, healthy})
	if err != nil || len(got) != 1 || got[0].Net != 102 {
		t.Fatal("oversized legacy VPC blocked healthy network replay", len(got), err)
	}
}

func TestVPCWatcherCounterScopesFollowObjectsRatherThanRoutes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	empty := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "empty"}, Status: sdn.VPCStatus{VNI: 101}}
	invalid := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "legacy"}, Spec: sdn.VPCSpec{CIDRs: []string{"invalid"}}, Status: sdn.VPCStatus{VNI: 102}}
	deleting := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "deleting", DeletionTimestamp: &metav1.Time{Time: time.Now()}}, Status: sdn.VPCStatus{VNI: 103}}
	client := sdnfake.NewSimpleClientset(empty, invalid, deleting)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &ownNetworkTestSink{rows: map[ownNetworkTestKey]uint32{}}
	watchVPCs(ctx, factory, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	waitScopes := func(want map[uint32]bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			sink.mu.Lock()
			match := sink.scopeCalls > 0 && len(sink.counterScopes) == len(want)
			for net := range want {
				match = match && sink.counterScopes[net]
			}
			sink.mu.Unlock()
			if match {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("complete counter scopes were not reconciled")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitScopes(map[uint32]bool{101: true, 102: true, 103: true})
	if err := client.SdnV1alpha1().VPCs(invalid.Namespace).Delete(ctx, invalid.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitScopes(map[uint32]bool{101: true, 103: true})
	for _, vpc := range []*sdn.VPC{empty, deleting} {
		if err := client.SdnV1alpha1().VPCs(vpc.Namespace).Delete(ctx, vpc.Name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	waitScopes(nil)
}

type ownNetworkTestSink struct {
	mu            sync.Mutex
	rows          map[ownNetworkTestKey]uint32
	reject        bool
	attempts      int
	counterFail   bool
	counterCalls  map[uint32]int
	counterScopes map[uint32]bool
	scopeCalls    int
}

func (s *ownNetworkTestSink) SyncVPCCounterScopes(scopes []uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scopeCalls++
	s.counterScopes = make(map[uint32]bool, len(scopes))
	for _, scope := range scopes {
		s.counterScopes[scope] = true
	}
	return nil
}

func (s *ownNetworkTestSink) SetNetwork(scope uint32, cidr string, net uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[ownNetworkTestKey{scope, cidr}] = net
	return nil
}

func (s *ownNetworkTestSink) DelNetwork(scope uint32, cidr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rows, ownNetworkTestKey{scope, cidr})
	return nil
}

func (s *ownNetworkTestSink) EnsureVPCCounter(net uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.counterCalls == nil {
		s.counterCalls = map[uint32]int{}
	}
	s.counterCalls[net]++
	if s.counterFail {
		return errors.New("counter map unavailable")
	}
	return nil
}

func (s *ownNetworkTestSink) SyncOwnNetworks(desired []datapath.PeerNet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts++
	if s.reject {
		return errors.New("shared capacity unavailable")
	}
	for key, value := range s.rows {
		if key.net == value {
			delete(s.rows, key)
		}
	}
	for _, entry := range desired {
		s.rows[ownNetworkTestKey{entry.Scope, entry.CIDR}] = entry.Net
	}
	return nil
}

func TestVPCWatcherCacheGateAndCapacityReleaseReplay(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.2.0.0/24"}}, Status: sdn.VPCStatus{VNI: 101}}
	client := sdnfake.NewSimpleClientset(vpc)
	var ready atomic.Bool
	client.PrependReactor("list", "vpcs", func(ktesting.Action) (bool, runtime.Object, error) {
		if !ready.Load() {
			return true, nil, errors.New("initial list unavailable")
		}
		return false, nil, nil
	})
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	old := ownNetworkTestKey{101, "10.1.0.0/24"}
	sink := &ownNetworkTestSink{rows: map[ownNetworkTestKey]uint32{old: 101}, reject: true}
	resync := watchVPCs(ctx, factory, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	time.Sleep(150 * time.Millisecond)
	sink.mu.Lock()
	if sink.attempts != 0 || sink.scopeCalls != 0 || sink.rows[old] != 101 {
		t.Error("incomplete cache touched pinned state", sink.attempts, sink.rows)
	}
	sink.mu.Unlock()
	ready.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for {
		sink.mu.Lock()
		attempts := sink.attempts
		sink.mu.Unlock()
		if attempts != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("complete cache was not replayed")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	sink.mu.Lock()
	if sink.rows[old] != 101 || sink.attempts > 2 {
		t.Error("failure discarded state or busy retried", sink.rows, sink.attempts)
	}
	sink.reject = false
	sink.mu.Unlock()
	// Successful peer reconciliation invokes this bounded notification when
	// stale peer rows release capacity; no further VPC event is required.
	for range 1000 {
		resync()
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		sink.mu.Lock()
		_, found := sink.rows[ownNetworkTestKey{101, vpc.Spec.CIDRs[0]}]
		attempts := sink.attempts
		sink.mu.Unlock()
		if found {
			if attempts > 4 {
				t.Fatal("notification burst was not coalesced", attempts)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("capacity release did not replay own state")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestOwnNetworkCompilerBoundsAndLegacyIsolation(t *testing.T) {
	healthy := &sdn.VPC{Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24", "2001:db8::/64"}}, Status: sdn.VPCStatus{VNI: 101}}
	bad := healthy.DeepCopy()
	bad.Spec.CIDRs = []string{"10.2.0.0/24", "bad"}
	large := healthy.DeepCopy()
	large.Spec.CIDRs = make([]string, maxOwnNetworkInputs+1)
	terminating := healthy.DeepCopy()
	stamp := metav1.Now()
	terminating.DeletionTimestamp = &stamp
	negative := healthy.DeepCopy()
	negative.Status.VNI = -1
	desired, err := compileOwnNetworks(t.Context(), []*sdn.VPC{bad, large, terminating, negative, nil, healthy})
	if err != nil || len(desired) != 2 || desired[0].CIDR != healthy.Spec.CIDRs[0] || desired[1].CIDR != healthy.Spec.CIDRs[1] {
		t.Fatal("legacy invalid input poisoned healthy VPC", desired, err)
	}
	full := healthy.DeepCopy()
	full.Spec.CIDRs = make([]string, sdn.MaxVPCCIDRs)
	for i := range full.Spec.CIDRs {
		full.Spec.CIDRs[i] = "10.0.0.0/24"
	}
	all := make([]*sdn.VPC, maxOwnNetworkInputs/sdn.MaxVPCCIDRs+1)
	for i := range all {
		all[i] = full
	}
	if desired, err := compileOwnNetworks(t.Context(), all); err == nil || desired != nil {
		t.Fatal("raw work budget not applied before expansion", len(desired), err)
	}
	full.Spec.CIDRs[len(full.Spec.CIDRs)-1] = "invalid"
	if desired, err := compileOwnNetworks(t.Context(), all); err == nil || desired != nil {
		t.Fatal("malformed prefixes escaped raw parse work budget", len(desired), err)
	}
	if desired, err := compileOwnNetworks(t.Context(), make([]*sdn.VPC, maxOwnNetworkInputs+1)); err == nil || desired != nil {
		t.Fatal("object budget not applied", len(desired), err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if desired, err := compileOwnNetworks(ctx, []*sdn.VPC{healthy}); !errors.Is(err, context.Canceled) || desired != nil {
		t.Fatal("cancelled snapshot produced routes", desired, err)
	}
}

func TestVPCWatcherCounterSeedLifetime(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}, Status: sdn.VPCStatus{VNI: 101}}
	client := sdnfake.NewSimpleClientset(vpc)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	sink := &ownNetworkTestSink{rows: map[ownNetworkTestKey]uint32{}, counterFail: true}
	resync := watchVPCs(ctx, factory, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	wait := func(condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			sink.mu.Lock()
			done := condition()
			sink.mu.Unlock()
			if done {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("counter worker did not settle")
	}
	wait(func() bool { return sink.counterCalls[101] == 1 })
	resync()
	wait(func() bool { return sink.counterCalls[101] == 2 })
	sink.mu.Lock()
	sink.counterFail = false
	sink.mu.Unlock()
	resync()
	wait(func() bool { return sink.counterCalls[101] == 3 })
	sink.mu.Lock()
	before := sink.attempts
	sink.mu.Unlock()
	for range 1000 {
		resync()
	}
	wait(func() bool { return sink.attempts > before })
	sink.mu.Lock()
	if sink.counterCalls[101] != 3 {
		t.Error("unchanged snapshots reread per-CPU counters", sink.counterCalls)
	}
	sink.mu.Unlock()
	if err := client.SdnV1alpha1().VPCs(vpc.Namespace).Delete(ctx, vpc.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return len(sink.rows) == 0 })
	if _, err := client.SdnV1alpha1().VPCs(vpc.Namespace).Create(ctx, vpc, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return sink.counterCalls[101] == 4 })
}

func TestVPCWatcherReplacesOwnCIDRsWithoutHistory(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	vpc := &sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "net"}, Spec: sdn.VPCSpec{CIDRs: []string{"10.1.0.0/24", "2001:db8:1::/64"}}, Status: sdn.VPCStatus{VNI: 101}}
	client := sdnfake.NewSimpleClientset(vpc)
	factory := sdninformers.NewSharedInformerFactory(client, 0)
	stale, peer := ownNetworkTestKey{101, "10.99.0.0/24"}, ownNetworkTestKey{102, "198.51.100.0/24"}
	sink := &ownNetworkTestSink{rows: map[ownNetworkTestKey]uint32{stale: 101, peer: 103}}
	watchVPCs(ctx, factory, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
	factory.Start(ctx.Done())
	defer func() { cancel(); factory.Shutdown() }()
	waitRow := func(key ownNetworkTestKey, present bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			sink.mu.Lock()
			_, found := sink.rows[key]
			sink.mu.Unlock()
			if found == present {
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatalf("row %#v presence did not become %v", key, present)
	}
	waitRow(ownNetworkTestKey{101, vpc.Spec.CIDRs[0]}, true)
	sink.mu.Lock()
	if _, found := sink.rows[stale]; found {
		t.Error("startup retained historical own prefix")
	}
	if _, found := sink.rows[ownNetworkTestKey{101, vpc.Spec.CIDRs[1]}]; !found {
		t.Error("second declared CIDR was not installed")
	}
	sink.mu.Unlock()
	for _, prefix := range []string{"10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"} {
		vpc.Spec.CIDRs = []string{prefix}
		if _, err := client.SdnV1alpha1().VPCs(vpc.Namespace).Update(ctx, vpc, metav1.UpdateOptions{}); err != nil {
			t.Fatal(err)
		}
		waitRow(ownNetworkTestKey{101, prefix}, true)
		sink.mu.Lock()
		if len(sink.rows) != 2 || sink.rows[peer] != 103 {
			t.Errorf("CIDR update retained history or removed peer: %v", sink.rows)
		}
		sink.mu.Unlock()
	}
	if err := client.SdnV1alpha1().VPCs(vpc.Namespace).Delete(ctx, vpc.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitRow(ownNetworkTestKey{101, vpc.Spec.CIDRs[0]}, false)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.rows) != 1 || sink.rows[peer] != 103 {
		t.Errorf("deletion retained obsolete own rows or removed peer: %v", sink.rows)
	}
}
