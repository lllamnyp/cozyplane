package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	sdncontroller "github.com/lllamnyp/cozyplane/internal/controller/sdn"
)

// Exercise the actual Kubernetes Lease implementation against a shared client:
// two processes compete, and only the elected one may allocate tenant identity.
func TestControllerLeaseSerializesTenantAllocation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	kube := kubefake.NewSimpleClientset()
	scheme := runtime.NewScheme()
	if err := sdnv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := coordinationv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	vpcs := []*sdnv1alpha1.VPC{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "net"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-b", Name: "net"}},
	}
	store := fake.NewClientBuilder().WithScheme(scheme).WithObjects(vpcs[0], vpcs[1]).WithStatusSubresource(&sdnv1alpha1.VPC{}).Build()
	started := make(chan string, 2)
	allocation := make(chan error, 2)
	var workers sync.WaitGroup
	for i := range 2 {
		identity := fmt.Sprintf("controller-%d", i)
		lock := &resourcelock.LeaseLock{LeaseMeta: metav1.ObjectMeta{Namespace: controllerLeaderElectionNamespace, Name: controllerLeaderElectionID}, Client: kube.CoordinationV1(), LockConfig: resourcelock.ResourceLockConfig{Identity: identity}}
		elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
			Lock: lock, LeaseDuration: 5 * time.Second, RenewDeadline: 3 * time.Second, RetryPeriod: 50 * time.Millisecond,
			Callbacks: leaderelection.LeaderCallbacks{
				OnStartedLeading: func(ctx context.Context) {
					started <- identity
					r := &sdncontroller.VPCReconciler{Client: store, Reader: store}
					for _, vpc := range vpcs {
						if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: vpc.Namespace, Name: vpc.Name}}); err != nil {
							allocation <- err
							return
						}
					}
					allocation <- nil
				},
				OnStoppedLeading: func() {},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		workers.Go(func() { elector.Run(ctx) })
	}
	t.Cleanup(func() { cancel(); workers.Wait() })
	select {
	case err := <-allocation:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("leader did not allocate")
	}
	<-started
	select {
	case second := <-started:
		t.Fatal("two active controller leaders", second)
	case <-time.After(300 * time.Millisecond):
	}
	lease, err := kube.CoordinationV1().Leases(controllerLeaderElectionNamespace).Get(t.Context(), controllerLeaderElectionID, metav1.GetOptions{})
	if err != nil || lease.Spec.HolderIdentity == nil {
		t.Fatal("no shared lease", lease, err)
	}
	var allocated []int32
	for _, vpc := range vpcs {
		got := &sdnv1alpha1.VPC{}
		if err := store.Get(t.Context(), types.NamespacedName{Namespace: vpc.Namespace, Name: vpc.Name}, got); err != nil {
			t.Fatal(err)
		}
		allocated = append(allocated, got.Status.VNI)
	}
	if allocated[0] == 0 || allocated[1] == 0 || allocated[0] == allocated[1] {
		t.Fatal("tenant network identities overlap", allocated)
	}
}
