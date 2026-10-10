package sdn

import (
	"testing"
	"time"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnstatus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

func TestVPNStatusReflectionDoesNotEnqueueAnotherPoll(t *testing.T) {
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "peer", UID: "peer-current"}}
	peer.Spec.GatewayRef.Name = "door"
	c := fake.NewClientBuilder().WithScheme(svcScheme(t)).WithStatusSubresource(peer).WithObjects(peer).Build()
	r := &VPNGatewayReconciler{Client: c}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
	defer q.ShutDown()
	p := vpnConnectionEvents()
	h := handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway)
	enqueued := 0
	for i := range 10 {
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
			t.Fatal(err)
		}
		old := peer.DeepCopy()
		snapshot := &vpnstatus.Snapshot{Backend: backendWireGuard, ObservedAt: time.Unix(1800000000+int64(i), 0), Connections: map[string]vpnstatus.Connection{peer.Name: {Up: true}}}
		if err := r.reflectConnectionStatus(t.Context(), []sdnv1alpha1.VPNConnection{*peer}, true, snapshot, nil); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(t.Context(), client.ObjectKeyFromObject(peer), peer); err != nil {
			t.Fatal(err)
		}
		if peer.Status.ObservedAt == nil || !peer.Status.ObservedAt.Time.Equal(snapshot.ObservedAt) {
			t.Fatal("fresh status observation lost")
		}
		e := event.UpdateEvent{ObjectOld: old, ObjectNew: peer.DeepCopy()}
		if p.Update(e) {
			h.Update(t.Context(), e, q)
		}
		if q.Len() > 0 {
			req, _ := q.Get()
			q.Done(req)
			enqueued++
		}
	}
	if enqueued != 0 {
		t.Fatalf("ten status observations immediately enqueue %d new polls", enqueued)
	}
}

func TestVPNConnectionEventsPreserveAuthorizationChanges(t *testing.T) {
	peer := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "peer", UID: "peer-current"}}
	peer.Spec.GatewayRef.Name = "old-door"
	p := vpnConnectionEvents()
	if !p.Create(event.CreateEvent{Object: peer}) || !p.Delete(event.DeleteEvent{Object: peer}) {
		t.Fatal("connection creation/deletion ignored")
	}
	for _, change := range []struct {
		name   string
		mutate func(*sdnv1alpha1.VPNConnection)
	}{
		{"routes", func(c *sdnv1alpha1.VPNConnection) { c.Spec.RemoteCIDRs = []string{"203.0.113.0/24"} }},
		{"credential", func(c *sdnv1alpha1.VPNConnection) {
			c.Spec.WireGuard = &sdnv1alpha1.VPNConnectionWireGuard{PresharedKeySecretRef: "new-key"}
		}},
		{"replacement", func(c *sdnv1alpha1.VPNConnection) { c.UID = "peer-replacement" }},
		{"termination", func(c *sdnv1alpha1.VPNConnection) { now := metav1.Now(); c.DeletionTimestamp = &now }},
	} {
		t.Run(change.name, func(t *testing.T) {
			updated := peer.DeepCopy()
			change.mutate(updated)
			if !p.Update(event.UpdateEvent{ObjectOld: peer, ObjectNew: updated}) {
				t.Fatal("authorization change ignored")
			}
		})
	}
	updated := peer.DeepCopy()
	updated.Spec.GatewayRef.Name = "new-door"
	e := event.UpdateEvent{ObjectOld: peer, ObjectNew: updated}
	if !p.Update(e) {
		t.Fatal("retarget ignored")
	}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
	defer q.ShutDown()
	r := &VPNGatewayReconciler{}
	handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway).Update(t.Context(), e, q)
	if q.Len() != 2 {
		t.Fatalf("retarget queued %d gateways instead of old and new", q.Len())
	}
	seen := map[string]bool{}
	for q.Len() > 0 {
		req, _ := q.Get()
		seen[req.Namespace+"/"+req.Name] = true
		q.Done(req)
	}
	if !seen["tenant-a/old-door"] || !seen["tenant-a/new-door"] {
		t.Fatal("retarget lost predecessor revocation", seen)
	}
}
