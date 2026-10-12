package sdn

import (
	"context"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type peeringReferenceReads struct {
	client.Client
	lookups, lists int
}

func (c *peeringReferenceReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if _, ok := obj.(*sdn.VPC); ok {
		c.lookups++
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

func (c *peeringReferenceReads) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	c.lists++
	return c.Client.List(ctx, list, opts...)
}

func TestPeeringInvalidReferencesResolveNoTargetsOrRequests(t *testing.T) {
	p := peeringHalf("tenant-a", "to-b", "net-a", "tenant-b", strings.Repeat("x", 128<<10))
	p.Status.Phase = sdn.VPCPeeringPhaseReady
	p.Status.PeerVNI = 102
	c := &peeringReferenceReads{Client: peeringClient(t, p, nsVPCWithVNI("tenant-a", "net-a", 101))}
	r := &VPCPeeringReconciler{Client: c}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(p)}); err != nil {
		t.Fatal(err)
	}
	if requests := r.mapToReciprocal(t.Context(), p); len(requests) != 0 {
		t.Fatal("invalid references queued", len(requests))
	}
	if c.lookups != 0 || c.lists != 0 {
		t.Fatalf("invalid references reached lookup/list: %d/%d", c.lookups, c.lists)
	}
	got := &sdn.VPCPeering{}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(p), got); err != nil {
		t.Fatal(err)
	}
	if got.Status.Phase != sdn.VPCPeeringPhasePending || got.Status.PeerVNI != 0 {
		t.Fatal("legacy Ready status retained")
	}
}

func TestPeeringReferenceIndexBudgetAndRecovery(t *testing.T) {
	index := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		peeringPairIndex: func(obj any) ([]string, error) { return peeringPairKeys(obj.(client.Object)), nil },
		peeringVPCIndex:  func(obj any) ([]string, error) { return peeringVPCKeys(obj.(client.Object)), nil },
	})
	p := peeringHalf("tenant-a", "to-b", "net-a", "tenant-b", strings.Repeat("x", 128<<10))
	if err := index.Add(p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{peeringPairIndex, peeringVPCIndex} {
		if keys := index.ListIndexFuncValues(name); len(keys) != 0 {
			t.Fatalf("invalid legacy reference retained in %s: keys=%d bytes=%d", name, len(keys), len(keys[0]))
		}
	}
	p = p.DeepCopy()
	p.Spec.PeerRef.Name = "net-b"
	if err := index.Update(p); err != nil {
		t.Fatal(err)
	}
	if keys := index.ListIndexFuncValues(peeringVPCIndex); len(keys) != 2 {
		t.Fatal("valid reference did not recover", keys)
	}
	p = p.DeepCopy()
	p.Spec.PeerRef.Namespace = strings.Repeat("x", 128<<10)
	if err := index.Update(p); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{peeringPairIndex, peeringVPCIndex} {
		if keys := index.ListIndexFuncValues(name); len(keys) != 0 {
			t.Fatalf("obsolete/invalid keys retained in %s: %d", name, len(keys))
		}
	}
	if err := index.Delete(p); err != nil {
		t.Fatal(err)
	}
}
