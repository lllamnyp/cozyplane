package sdn

import (
	"context"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type vpcStatusCounter struct {
	client.Client
	writes int
}

type countedVPCStatusWriter struct {
	client.SubResourceWriter
	counter *vpcStatusCounter
}

func (c *vpcStatusCounter) Status() client.SubResourceWriter {
	return &countedVPCStatusWriter{SubResourceWriter: c.Client.Status(), counter: c}
}

func (w *countedVPCStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if _, ok := obj.(*sdn.VPC); ok {
		w.counter.writes++
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestVPCReconcileDoesNotRewriteStableStatus(t *testing.T) {
	vpc := nsVPCWithVNI("tenant", "net", 101)
	vpc.Status.Phase = sdn.VPCPhasePending
	c := &vpcStatusCounter{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithStatusSubresource(&sdn.VPC{}).WithObjects(vpc).Build()}
	r := &VPCReconciler{Client: c}
	req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(vpc)}
	if _, err := r.Reconcile(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	if c.writes != 1 {
		t.Fatal("Pending to Ready transition not written", c.writes)
	}
	c.writes = 0
	for range 10 {
		if _, err := r.Reconcile(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	if c.writes != 0 {
		t.Fatal("stable Ready VPC still makes status API writes", c.writes)
	}
}
