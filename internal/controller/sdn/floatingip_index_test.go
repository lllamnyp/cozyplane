package sdn

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type floatingListCounter struct {
	client.Client
	read int
}

func (c *floatingListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if list, ok := list.(*sdnv1alpha1.FloatingIPList); ok {
		c.read += len(list.Items)
	}
	return nil
}

func TestFloatingEventsCopyOnlyTargetContendersIncludingReady(t *testing.T) {
	winner := floatingIP("tenant-a", "a-winner", "net", "fd00::5")
	winner.Status.Phase = sdnv1alpha1.FloatingIPPhaseReady
	loser := floatingIP("tenant-a", "z-loser", "net", "fd00:0:0:0:0:0:0:5")
	objects := []client.Object{winner, loser, floatingIP("tenant-b", "same-target", "net", "fd00::5")}
	for i := range 1400 {
		objects = append(objects, floatingIP("tenant-a", fmt.Sprintf("unrelated-%d", i), "net", fmt.Sprintf("fd01::%x", i+1)))
	}
	c := &floatingListCounter{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdnv1alpha1.FloatingIP{}, floatingTargetIndex, floatingTargetIndexKeys).WithObjects(objects...).Build()}
	r := &FloatingIPReconciler{Client: c}
	requests := r.mapTargetToFloatingIPs(t.Context(), floatingIP("tenant-a", "removed", "net", "fd00::5"))
	seen := map[string]bool{}
	for _, req := range requests {
		seen[req.Namespace+"/"+req.Name] = true
	}
	if c.read != 2 || len(requests) != 2 || !seen["tenant-a/a-winner"] || !seen["tenant-a/z-loser"] {
		t.Fatalf("event copied %d objects and queued %d contenders (Ready=%v, Pending=%v)", c.read, len(requests), seen["tenant-a/a-winner"], seen["tenant-a/z-loser"])
	}
	c.read = 0
	if got := r.conflictingFIP(t.Context(), loser); got != winner.Name || c.read != 2 {
		t.Fatalf("conflict copied unrelated bindings: read=%d winner=%q", c.read, got)
	}
	c.read = 0
	port := livePort(winner.Namespace, winner.Spec.VPCRef.Name, "fd00::5", "node-a")
	if requests := r.mapPortToFloatingIPs(t.Context(), port); len(requests) != 2 || c.read != 2 {
		t.Fatalf("Port event copied unrelated bindings: %d rows %d requests", c.read, len(requests))
	}
}

func TestFloatingRetargetEnqueuesOldAndNewReadyContenders(t *testing.T) {
	old := floatingIP("tenant-a", "moved", "net", "10.0.0.2")
	current := old.DeepCopy()
	current.Spec.Target = "10.0.0.3"
	a := floatingIP("tenant-a", "old-target-ready", "net", old.Spec.Target)
	a.Status.Phase = sdnv1alpha1.FloatingIPPhaseReady
	b := floatingIP("tenant-a", "new-target-ready", "net", current.Spec.Target)
	b.Status.Phase = sdnv1alpha1.FloatingIPPhaseReady
	c := &floatingListCounter{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdnv1alpha1.FloatingIP{}, floatingTargetIndex, floatingTargetIndexKeys).WithObjects(a, b).Build()}
	r := &FloatingIPReconciler{Client: c}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
	defer q.ShutDown()
	e := event.UpdateEvent{ObjectOld: old, ObjectNew: current}
	p := floatingContenderEvents()
	if !p.Update(e) {
		t.Fatal("retarget ignored")
	}
	handler.EnqueueRequestsFromMapFunc(r.mapTargetToFloatingIPs).Update(t.Context(), e, q)
	if q.Len() != 2 || c.read != 2 {
		t.Fatalf("retarget did not scope both targets: queued=%d copied=%d", q.Len(), c.read)
	}
	status := current.DeepCopy()
	status.Status.Phase = sdnv1alpha1.FloatingIPPhaseReady
	status.Status.Address = "203.0.113.10"
	if p.Update(event.UpdateEvent{ObjectOld: current, ObjectNew: status}) {
		t.Fatal("status-only event fans out to contenders")
	}
	deleting := current.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if !p.Update(event.UpdateEvent{ObjectOld: current, ObjectNew: deleting}) {
		t.Fatal("deletion start ignored")
	}
}
