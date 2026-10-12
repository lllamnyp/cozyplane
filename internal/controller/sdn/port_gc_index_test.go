package sdn

import (
	"context"
	"fmt"
	"testing"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type gcPortListCounter struct {
	client.Client
	read int
}

func (c *gcPortListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if list, ok := list.(*sdn.PortList); ok {
		c.read += len(list.Items)
	}
	return nil
}

func TestPortGCEventsCopyOnlyAffectedPorts(t *testing.T) {
	port := func(name, node, ns, pod, uid string) *sdn.Port {
		return &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{sdn.LabelPodNamespace: ns, sdn.LabelPodName: pod, sdn.LabelPodUID: uid}}, Spec: sdn.PortSpec{Node: node}}
	}
	objects := []client.Object{port("current", "node", "tenant", "pod", "new"), port("predecessor", "node", "tenant", "pod", "old"), port("other-namespace", "other-node", "other", "pod", "new")}
	for i := range 1200 {
		objects = append(objects, port(fmt.Sprintf("foreign-%d", i), "other-node", "tenant", fmt.Sprintf("other-%d", i), "other"))
	}
	c := &gcPortListCounter{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).
		WithIndex(&sdn.Port{}, gcPortNodeIndex, gcPortNodeKeys).
		WithIndex(&sdn.Port{}, gcPortPodIndex, membershipPodKeys).WithObjects(objects...).Build()}
	r := &PortGCReconciler{Client: c}
	requests := r.mapNodeToPorts(t.Context(), &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node"}})
	if len(requests) != 2 || c.read != 2 {
		t.Errorf("one Node event copied %d Ports, enqueued %v", c.read, requests)
	}
	c.read = 0
	requests = r.mapPodToPorts(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "new"}})
	if len(requests) != 2 || c.read != 2 {
		t.Fatalf("one Pod event copied %d Ports, enqueued %v", c.read, requests)
	}
	c.read = 0
	requests = r.mapFabricIPToPorts(t.Context(), &local.FabricIP{Spec: local.FabricIPSpec{PodNamespace: "tenant", PodName: "pod"}})
	if len(requests) != 2 || c.read != 2 {
		t.Fatalf("one FabricIP event copied %d Ports, enqueued %v", c.read, requests)
	}
	c.read = 0
	if requests := r.mapFabricIPToPorts(t.Context(), &local.FabricIP{}); len(requests) != 0 || c.read != 0 {
		t.Fatal("unowned FabricIP triggered a Port scan", c.read, requests)
	}
}
