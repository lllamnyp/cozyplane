package sdn

import (
	"context"
	"fmt"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type peeringListCounter struct {
	client.Client
	read int
}

func (c *peeringListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if list, ok := list.(*sdn.VPCPeeringList); ok {
		c.read += len(list.Items)
	}
	return nil
}

func TestPeeringLookupsCopyOnlyCurrentReferences(t *testing.T) {
	a := peeringHalf("tenant-a", "to-b", "net-a", "tenant-b", "net-b")
	b := peeringHalf("tenant-b", "to-a", "net-b", "tenant-a", "net-a")
	other := peeringHalf("tenant-b", "to-c", "net-b", "tenant-c", "net-c")
	objects := []client.Object{a, b, other}
	for i := range 1400 {
		objects = append(objects, peeringHalf("tenant-b", fmt.Sprintf("unrelated-%d", i), fmt.Sprintf("net-%d", i), "tenant-c", "net-c"))
	}
	c := &peeringListCounter{Client: peeringClient(t, objects...)}
	r := &VPCPeeringReconciler{Client: c}
	t.Run("Reciprocal", func(t *testing.T) {
		c.read = 0
		got, err := r.findReciprocal(t.Context(), a)
		if err != nil || got == nil || got.Name != b.Name || c.read != 1 {
			t.Fatalf("reciprocal copied=%d got=%v err=%v", c.read, got, err)
		}
	})
	t.Run("Half event", func(t *testing.T) {
		c.read = 0
		requests := r.mapToReciprocal(t.Context(), a)
		if c.read != 1 || len(requests) != 1 || requests[0].Name != b.Name {
			t.Fatalf("half copied=%d queued=%v", c.read, requests)
		}
	})
	t.Run("VPC event", func(t *testing.T) {
		c.read = 0
		requests := r.mapVPCToPeerings(t.Context(), nsVPCWithVNI("tenant-a", "net-a", 101))
		if c.read != 2 || len(requests) != 2 {
			t.Fatalf("VPC copied=%d queued=%v", c.read, requests)
		}
	})
}

func TestPeeringIndexesFollowCurrentReferencesAndRemoval(t *testing.T) {
	a := peeringHalf("tenant-a", "to-b", "net-a", "tenant-b", "net-b")
	b := peeringHalf("tenant-b", "to-a", "net-b", "tenant-a", "net-a")
	c := peeringClient(t, a, b)
	r := &VPCPeeringReconciler{Client: c}
	if got, err := r.findReciprocal(t.Context(), a); err != nil || got == nil {
		t.Fatal("initial consent missing", err)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(b), b); err != nil {
		t.Fatal(err)
	}
	// Storage-level updates also exercise cleanup of reference keys; the served
	// API forbids retargeting a peering spec.
	b.Spec.PeerRef.Name = "next"
	if err := c.Update(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if got, err := r.findReciprocal(t.Context(), a); err != nil || got != nil {
		t.Fatal("obsolete reciprocal consent retained", got, err)
	}
	if requests := r.mapVPCToPeerings(t.Context(), nsVPCWithVNI("tenant-a", "net-a", 101)); len(requests) != 1 || requests[0].Name != a.Name {
		t.Fatal("obsolete VPC reference retained", requests)
	}
	newVPC := nsVPCWithVNI("tenant-a", "next", 102)
	if len(r.mapVPCToPeerings(t.Context(), newVPC)) != 1 {
		t.Fatal("current VPC reference missing")
	}
	if len(r.mapVPCToPeerings(t.Context(), nsVPCWithVNI("tenant-c", "next", 103))) != 0 {
		t.Fatal("homonymous foreign namespace matched")
	}
	if err := c.Delete(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToPeerings(t.Context(), newVPC)) != 0 {
		t.Fatal("deleted reference retained")
	}
}
