package sdn

import (
	"fmt"
	"strings"
	"testing"

	internalapi "github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	connectionregistry "github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpnconnection"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestVPNOversizedRetargetCannotAccumulateControllerRequests(t *testing.T) {
	r := &VPNGatewayReconciler{}
	h := handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway)
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	strategy := connectionregistry.NewStrategy(runtime.NewScheme())
	old := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "peer", UID: "peer-uid"}}
	old.Spec.GatewayRef.Name = "gateway"
	admitted := 0
	for i := range 32 {
		current := old.DeepCopy()
		current.Spec.GatewayRef.Name = fmt.Sprintf("target-%02d-", i) + strings.Repeat("a", 128<<10)
		input := &internalapi.VPNConnection{ObjectMeta: current.ObjectMeta}
		input.Spec.GatewayRef.Name = current.Spec.GatewayRef.Name
		previous := input.DeepCopy()
		previous.Spec.GatewayRef.Name = old.Spec.GatewayRef.Name
		if len(strategy.Validate(t.Context(), input)) == 0 || len(strategy.ValidateUpdate(t.Context(), input, previous)) == 0 {
			admitted++
		}
		h.Update(t.Context(), event.UpdateEvent{ObjectOld: old, ObjectNew: current}, q)
		old = current
	}
	queued, referenceBytes := q.Len(), 0
	for q.Len() > 0 {
		req, shutdown := q.Get()
		if shutdown {
			t.Fatal("queue shut down unexpectedly")
		}
		referenceBytes += len(req.Name)
		q.Done(req)
		q.Forget(req)
	}
	if admitted != 0 || queued != 1 || referenceBytes != len("gateway") {
		t.Fatalf("one object retargeted 32 times: invalid references admitted=%d, queued=%d, retained reference bytes=%d; want 0, 1, %d", admitted, queued, referenceBytes, len("gateway"))
	}
}

func TestVPNValidRetargetQueuesBothGateways(t *testing.T) {
	r := &VPNGatewayReconciler{}
	h := handler.EnqueueRequestsFromMapFunc(r.mapConnectionToGateway)
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[reconcile.Request]())
	defer q.ShutDown()
	old := &sdnv1alpha1.VPNConnection{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "peer", UID: "peer-uid"}}
	old.Spec.GatewayRef.Name = "old-gateway"
	current := old.DeepCopy()
	current.Spec.GatewayRef.Name = "new-gateway"
	h.Update(t.Context(), event.UpdateEvent{ObjectOld: old, ObjectNew: current}, q)
	if q.Len() != 2 {
		t.Fatalf("valid retarget queued=%d want=2", q.Len())
	}
	seen := map[string]bool{}
	for range 2 {
		req, shutdown := q.Get()
		if shutdown || req.Namespace != "tenant-a" {
			t.Fatal("valid target lost its namespace")
		}
		seen[req.Name] = true
		q.Done(req)
		q.Forget(req)
	}
	if !seen["old-gateway"] || !seen["new-gateway"] {
		t.Fatal("old or new gateway not notified")
	}
}
