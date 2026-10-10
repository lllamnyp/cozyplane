package sdn

import (
	"context"
	"strings"
	"testing"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type bindingNADReads struct {
	client.Client
	gets int
}

func (c *bindingNADReads) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	c.gets++
	return c.Client.Get(ctx, key, obj, opts...)
}

func TestBindingInvalidReferenceStopsBeforeNADWork(t *testing.T) {
	scheme := nadScheme(t)
	c := &bindingNADReads{Client: fake.NewClientBuilder().WithScheme(scheme).Build()}
	r := &VPCBindingReconciler{Client: c, Scheme: scheme, emitNAD: true}
	for _, target := range []string{"name", "namespace"} {
		for _, value := range []string{strings.Repeat("x", 128<<10), "bad/name"} {
			b := vpcBinding("tenant-a", "grant", "tenant-a", "net", true)
			if target == "name" {
				b.Spec.VPCRef.Name = value
			} else {
				b.Spec.VPCRef.Namespace = value
			}
			if err := r.reconcileNAD(t.Context(), b); err == nil || len(err.Error()) > 256 {
				t.Fatal("missing or oversized legacy diagnostic")
			}
			if c.gets != 0 {
				t.Fatal("invalid reference reached NAD lookup", c.gets)
			}
		}
	}
	valid := vpcBinding("tenant-a", "grant", "tenant-a", "net", true)
	valid.UID = "binding-uid"
	if err := r.reconcileNAD(t.Context(), valid); err != nil {
		t.Fatal(err)
	}
	if getNAD(t, c, "tenant-a", "net") == nil {
		t.Fatal("valid NAD recovery failed")
	}
}
