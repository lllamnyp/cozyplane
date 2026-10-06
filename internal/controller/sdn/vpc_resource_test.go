package sdn

import (
	"context"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type countingStatusClient struct {
	client.Client
	updates int
}
type countingStatusWriter struct {
	client.SubResourceWriter
	owner *countingStatusClient
}

func (c *countingStatusClient) Status() client.SubResourceWriter {
	return &countingStatusWriter{SubResourceWriter: c.Client.Status(), owner: c}
}
func (w *countingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	w.owner.updates++
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

func TestVPCStableStatusSkipsWritesAndStillObservesACK(t *testing.T) {
	f := newBoundaryFixture()
	f.vpc.Namespace, f.vpc.Name, f.vpc.Generation, f.vpc.Status.VNI = "team-a", "private", 1, 100
	for i := range f.vpc.Status.BoundaryNodes {
		f.vpc.Status.BoundaryNodes[i].ObservedGeneration = 1
	}
	scheme := testScheme(t)
	if err := appsv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	objects := []client.Object{f.ds, f.vpc}
	for _, p := range f.pods {
		objects = append(objects, p)
	}
	base := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(&sdn.VPC{}).WithObjects(objects...).Build()
	c := &countingStatusClient{Client: base}
	r := &VPCReconciler{Client: c, AgentNamespace: f.namespace}
	key := types.NamespacedName{Namespace: f.vpc.Namespace, Name: f.vpc.Name}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	for i := 0; i < 5; i++ {
		reconcile()
	}
	if c.updates != 1 {
		t.Fatalf("stable reconciliations sent %d status writes, want 1", c.updates)
	}
	var live sdn.VPC
	if err := base.Get(context.Background(), key, &live); err != nil {
		t.Fatal(err)
	}
	for i := range live.Status.BoundaryNodes {
		live.Status.BoundaryNodes[i].TransportReady = true
	}
	if err := base.Status().Update(context.Background(), &live); err != nil {
		t.Fatal(err)
	}
	reconcile()
	reconcile()
	if c.updates != 2 {
		t.Fatalf("changed ACK followed by steady state sent %d writes, want 2", c.updates)
	}
}
