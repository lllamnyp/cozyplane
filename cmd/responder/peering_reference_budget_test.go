package main

import (
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

func TestDNSPeeringReferenceIndexBudgetAndRecovery(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{localVPCIndex: peeringLocalIndexFunc, peeringPairIndex: peeringPairIndexFunc})
	p := &sdn.VPCPeering{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "to-b"}, Spec: sdn.VPCPeeringSpec{VPCRef: sdn.LocalVPCRef{Name: "net-a"}, PeerRef: sdn.VPCRef{Namespace: "tenant-b", Name: strings.Repeat("x", 128<<10)}}}
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{localVPCIndex, peeringPairIndex} {
		if keys := index.ListIndexFuncValues(name); len(keys) != 0 {
			t.Fatalf("invalid reference indexed: %s keys=%d", name, len(keys))
		}
	}
	p = p.DeepCopy()
	p.Spec.PeerRef.Name = "net-b"
	if err := index.Update(p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{localVPCIndex, peeringPairIndex} {
		if keys := index.ListIndexFuncValues(name); len(keys) != 1 || len(keys[0]) > 1024 {
			t.Fatalf("valid reference missing or unbounded: %s", name)
		}
	}
	p = p.DeepCopy()
	p.Spec.VPCRef.Name = "bad/name"
	if err := index.Update(p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{localVPCIndex, peeringPairIndex} {
		if keys := index.ListIndexFuncValues(name); len(keys) != 0 {
			t.Fatalf("old reference retained after invalid update: %s", name)
		}
	}
	if err := index.Delete(p); err != nil {
		t.Fatal(err)
	}
}
