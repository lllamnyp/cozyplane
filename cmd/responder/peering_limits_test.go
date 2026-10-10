package main

import (
	"fmt"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

type countingPeeringIndex struct {
	cache.Indexer
	items int
	calls int
}

func (i *countingPeeringIndex) ByIndex(name, key string) ([]any, error) {
	objects, err := i.Indexer.ByIndex(name, key)
	i.items += len(objects)
	i.calls++
	return objects, err
}

func peeringLoadState(t testing.TB, n int, matched bool) (*informerState, *countingPeeringIndex, sdn.VPCRef) {
	t.Helper()
	local := sdn.VPCRef{Namespace: "tenant-a", Name: "net"}
	remote := sdn.VPCRef{Namespace: "tenant-b", Name: "net"}
	index := &countingPeeringIndex{Indexer: cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		localVPCIndex: func(obj any) ([]string, error) {
			p := obj.(*sdn.VPCPeering)
			return []string{p.Namespace + "/" + p.Spec.VPCRef.Name}, nil
		},
		peeringPairIndex: peeringPairIndexFunc,
	})}
	state := &informerState{peerings: index, vpcs: cache.NewIndexer(cache.MetaNamespaceKeyFunc, nil)}
	for i, ref := range []sdn.VPCRef{local, remote} {
		if err := state.vpcs.Add(&sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name, UID: "vpc-uid"}, Spec: sdn.VPCSpec{CIDRs: []string{fmt.Sprintf("10.%d.0.0/24", i+1)}}, Status: sdn.VPCStatus{VNI: int32(100 + i)}}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		for _, ref := range []sdn.VPCRef{local, remote} {
			peer := remote
			if ref == remote {
				peer = sdn.VPCRef{Namespace: "unrelated", Name: "net"}
			}
			p := &sdn.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: fmt.Sprintf("peer-%d", i)}, Spec: sdn.VPCPeeringSpec{VPCRef: sdn.LocalVPCRef{Name: ref.Name}, PeerRef: peer}, Status: sdn.VPCPeeringStatus{Phase: sdn.VPCPeeringPhaseReady}}
			if err := index.Add(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	if matched {
		if err := index.Add(&sdn.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: remote.Namespace, Name: "reciprocal"}, Spec: sdn.VPCPeeringSpec{VPCRef: sdn.LocalVPCRef{Name: remote.Name}, PeerRef: local}}); err != nil {
			t.Fatal(err)
		}
	}
	return state, index, local
}

func TestDNSPeeringDuplicateWorkAndRetention(t *testing.T) {
	for _, matched := range []bool{false, true} {
		t.Run(fmt.Sprint(matched), func(t *testing.T) {
			state, index, local := peeringLoadState(t, 5000, matched)
			peers := state.Peers(local)
			want := 0
			if matched {
				want = 1
			}
			if index.items > 65536 || index.calls > 2 || len(peers) != want {
				t.Fatalf("lookup work/retention: items=%d calls=%d peers=%d want=%d", index.items, index.calls, len(peers), want)
			}
			if matched {
				object, found, err := index.GetByKey("tenant-b/reciprocal")
				if err != nil || !found {
					t.Fatal("missing reciprocal", err)
				}
				if err := index.Delete(object); err != nil {
					t.Fatal(err)
				}
				if len(state.Peers(local)) != 0 {
					t.Fatal("reciprocal revocation retained cached authorization")
				}
			}
		})
	}
}

func TestDNSPeeringCIDRWorkBudgetAndRecovery(t *testing.T) {
	state, _, local := peeringLoadState(t, 1, true)
	for _, key := range []string{"tenant-a/net", "tenant-b/net"} {
		object, _, _ := state.vpcs.GetByKey(key)
		vpc := object.(*sdn.VPC).DeepCopy()
		cidr := vpc.Spec.CIDRs[0]
		for len(vpc.Spec.CIDRs) < 256 {
			vpc.Spec.CIDRs = append(vpc.Spec.CIDRs, cidr)
		}
		if err := state.vpcs.Update(vpc); err != nil {
			t.Fatal(err)
		}
	}
	if len(state.Peers(local)) != 0 {
		t.Fatal("oversized CIDR product authorized a partial view")
	}
	object, _, _ := state.vpcs.GetByKey("tenant-a/net")
	vpc := object.(*sdn.VPC).DeepCopy()
	vpc.Spec.CIDRs = vpc.Spec.CIDRs[:1]
	if err := state.vpcs.Update(vpc); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers(local)) != 1 {
		t.Fatal("bounded CIDR view did not recover")
	}
}

func TestDNSPeeringRetentionBudgetAndRecovery(t *testing.T) {
	state, index, local := peeringLoadState(t, 0, false)
	for i := 0; i <= maxDNSPeers; i++ {
		remote := sdn.VPCRef{Namespace: "tenant-b", Name: fmt.Sprintf("net-%d", i)}
		if err := state.vpcs.Add(&sdn.VPC{ObjectMeta: metav1.ObjectMeta{Namespace: remote.Namespace, Name: remote.Name}, Spec: sdn.VPCSpec{CIDRs: []string{"10.2.0.0/24"}}, Status: sdn.VPCStatus{VNI: int32(101 + i)}}); err != nil {
			t.Fatal(err)
		}
		for _, refs := range [][2]sdn.VPCRef{{local, remote}, {remote, local}} {
			p := &sdn.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: refs[0].Namespace, Name: fmt.Sprintf("pair-%d", i)}, Spec: sdn.VPCPeeringSpec{VPCRef: sdn.LocalVPCRef{Name: refs[0].Name}, PeerRef: refs[1]}, Status: sdn.VPCPeeringStatus{Phase: sdn.VPCPeeringPhaseReady}}
			if err := index.Add(p); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(state.Peers(local)) != 0 {
		t.Fatal("retention overflow returned partial authorization")
	}
	object, _, _ := index.GetByKey(fmt.Sprintf("tenant-a/pair-%d", maxDNSPeers))
	if err := index.Delete(object); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers(local)) != maxDNSPeers {
		t.Fatal("retention view did not recover at the limit")
	}
}

func BenchmarkDNSDuplicatePeerings(b *testing.B) {
	state, index, local := peeringLoadState(b, 5000, false)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if len(state.Peers(local)) != 0 {
			b.Fatal("unilateral peering authorized")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(index.items)/float64(b.N), "objects/op")
}
