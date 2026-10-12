package sdn

import (
	"context"
	"fmt"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

type routeGatewayListCounter struct {
	client.Client
	read int
}

func (c *routeGatewayListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if list, ok := list.(*sdnv1alpha1.VPCGatewayList); ok {
		c.read += len(list.Items)
	}
	return nil
}

func TestGatewayPodEventsCopyOnlyCandidateNamespacesAndMatchLabels(t *testing.T) {
	a := applianceGateway("tenant-a", "door", "net", map[string]string{"app": "router"})
	b := applianceGateway("tenant-b", "shared-door", "net", map[string]string{"app": "router"})
	b.Spec.Appliance.Namespace = "tenant-a"
	unselected := applianceGateway("tenant-a", "unselected", "net", map[string]string{"app": "other"})
	objects := []client.Object{a, b, unselected}
	for i := range 1400 {
		objects = append(objects, applianceGateway("foreign", fmt.Sprintf("unrelated-%d", i), "net", map[string]string{"app": "router"}))
	}
	c := &routeGatewayListCounter{Client: fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdnv1alpha1.VPCGateway{}, gatewayPodNamespaceIndex, gatewayPodNamespaceKeys).WithObjects(objects...).Build()}
	r := &VPCGatewayReconciler{Client: c}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-a", Name: "router", UID: "pod-current", Labels: map[string]string{"app": "router"}}}
	requests := r.mapPodToGateways(t.Context(), pod)
	seen := map[string]bool{}
	for _, req := range requests {
		seen[req.Namespace+"/"+req.Name] = true
	}
	if c.read != 3 || len(requests) != 2 || !seen["tenant-a/door"] || !seen["tenant-b/shared-door"] {
		t.Fatalf("Pod event copied=%d enqueued=%d current=%v shared=%v", c.read, len(requests), seen["tenant-a/door"], seen["tenant-b/shared-door"])
	}
	c.read = 0
	changed := pod.DeepCopy()
	changed.Labels = map[string]string{"app": "other"}
	q := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
	defer q.ShutDown()
	e := event.UpdateEvent{ObjectOld: pod, ObjectNew: changed}
	p := gatewayPodEvents()
	if !p.Update(e) {
		t.Fatal("label removal ignored")
	}
	handler.EnqueueRequestsFromMapFunc(r.mapPodToGateways).Update(t.Context(), e, q)
	if q.Len() != 3 || c.read != 6 {
		t.Fatalf("label update missed old/new selectors: queued=%d copied=%d", q.Len(), c.read)
	}
	status := pod.DeepCopy()
	status.Status.Phase = corev1.PodRunning
	if p.Update(event.UpdateEvent{ObjectOld: pod, ObjectNew: status}) {
		t.Fatal("ordinary status event triggers route projection")
	}
	completed := status.DeepCopy()
	completed.Status.Phase = corev1.PodSucceeded
	if !p.Update(event.UpdateEvent{ObjectOld: status, ObjectNew: completed}) {
		t.Fatal("terminal pod transition ignored")
	}
	deleting := status.DeepCopy()
	now := metav1.Now()
	deleting.DeletionTimestamp = &now
	if !p.Update(event.UpdateEvent{ObjectOld: status, ObjectNew: deleting}) {
		t.Fatal("deletion start ignored")
	}
}

func TestGatewayRouteNamespaceIndexFollowsSpecChanges(t *testing.T) {
	gw := applianceGateway("tenant-a", "door", "net", map[string]string{"app": "router"})
	gw.Spec.Appliance = nil
	gw.Spec.Routes = []sdnv1alpha1.VPCGatewayRoute{{Via: sdnv1alpha1.VPCGatewayVia{Namespace: "shared", PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "router"}}}}}
	c := fake.NewClientBuilder().WithScheme(gatewayScheme(t)).WithIndex(&sdnv1alpha1.VPCGateway{}, gatewayPodNamespaceIndex, gatewayPodNamespaceKeys).WithObjects(gw).Build()
	r := &VPCGatewayReconciler{Client: c}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "shared", Name: "router", Labels: map[string]string{"app": "router"}}}
	if requests := r.mapPodToGateways(t.Context(), pod); len(requests) != 1 {
		t.Fatal("explicit route namespace not indexed", requests)
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	gw.Spec.Routes[0].Via.Namespace = "next"
	if err := c.Update(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if requests := r.mapPodToGateways(t.Context(), pod); len(requests) != 0 {
		t.Fatal("obsolete namespace index retained", requests)
	}
	pod.Namespace = "next"
	if requests := r.mapPodToGateways(t.Context(), pod); len(requests) != 1 {
		t.Fatal("replacement namespace not indexed", requests)
	}
	if err := c.Delete(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if requests := r.mapPodToGateways(t.Context(), pod); len(requests) != 0 {
		t.Fatal("deleted gateway index retained", requests)
	}
}

func TestGatewayVPCEventsAndConflictCopyOnlyRelatedGateways(t *testing.T) {
	a := applianceGateway("tenant-a", "a-door", "net", map[string]string{"app": "router"})
	b := applianceGateway("tenant-a", "b-door", "net", map[string]string{"app": "router"})
	objects := []client.Object{a, b, applianceGateway("tenant-b", "foreign-door", "net", nil)}
	for i := range 1400 {
		objects = append(objects, applianceGateway("tenant-a", fmt.Sprintf("unrelated-%d", i), fmt.Sprintf("other-net-%d", i), nil))
	}
	c := &routeGatewayListCounter{Client: gwClient(t, objects...)}
	r := &VPCGatewayReconciler{Client: c}
	vpc := vpcWithCIDRs("tenant-a", "net", 101, "10.0.0.0/24")
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: vpc.Namespace, sdnv1alpha1.LabelVPC: vpc.Name}}, Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpc.Namespace, Name: vpc.Name}}}
	t.Run("Port", func(t *testing.T) {
		c.read = 0
		requests := r.mapPortToGateways(t.Context(), port)
		if c.read != 2 || len(requests) != 2 {
			t.Fatalf("Port event copied=%d queued=%d", c.read, len(requests))
		}
	})
	t.Run("VPC", func(t *testing.T) {
		c.read = 0
		requests := r.mapVPCToGateways(t.Context(), vpc)
		if c.read != 2 || len(requests) != 2 {
			t.Fatalf("VPC event copied=%d queued=%d", c.read, len(requests))
		}
	})
	t.Run("Conflict", func(t *testing.T) {
		c.read = 0
		winner, err := r.conflictingGateway(t.Context(), b)
		if err != nil {
			t.Fatal(err)
		}
		if c.read != 2 || winner != a.Name {
			t.Fatalf("conflict copied=%d winner=%s", c.read, winner)
		}
	})
}

func TestGatewayVPCIndexFollowsReferenceChangesAndDeletion(t *testing.T) {
	gw := applianceGateway("tenant-a", "door", "net", nil)
	c := gwClient(t, gw)
	r := &VPCGatewayReconciler{Client: c}
	oldVPC := vpcWithCIDRs(gw.Namespace, "net", 101, "10.0.0.0/24")
	newVPC := vpcWithCIDRs(gw.Namespace, "next", 102, "10.0.0.0/24")
	if len(r.mapVPCToGateways(t.Context(), oldVPC)) != 1 {
		t.Fatal("initial VPC missing from index")
	}
	if err := c.Get(t.Context(), client.ObjectKeyFromObject(gw), gw); err != nil {
		t.Fatal(err)
	}
	old := gw.DeepCopy()
	gw.Spec.VPCRef.Name = newVPC.Name
	if err := c.Update(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToGateways(t.Context(), oldVPC)) != 0 || len(r.mapVPCToGateways(t.Context(), newVPC)) != 1 {
		t.Fatal("index did not follow reference")
	}
	port := &sdnv1alpha1.Port{ObjectMeta: metav1.ObjectMeta{Name: "v101.10-0-0-2", Labels: map[string]string{sdnv1alpha1.LabelVPCNamespace: gw.Namespace, sdnv1alpha1.LabelVPC: old.Spec.VPCRef.Name}}}
	if len(r.mapPortToGateways(t.Context(), port)) != 0 {
		t.Fatal("unrelated old VPC Port still queues gateway")
	}
	port.Labels[sdnv1alpha1.LabelVPC] = newVPC.Name
	if len(r.mapPortToGateways(t.Context(), port)) != 1 {
		t.Fatal("current VPC Port does not queue gateway")
	}
	if err := c.Delete(t.Context(), gw); err != nil {
		t.Fatal(err)
	}
	if len(r.mapVPCToGateways(t.Context(), newVPC)) != 0 {
		t.Fatal("deleted gateway retained in index")
	}
}
