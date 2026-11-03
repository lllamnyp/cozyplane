package localsdn

import (
	"context"
	"fmt"
	"testing"

	local "github.com/lllamnyp/cozyplane/api/localsdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type fabricIPListCounter struct {
	client.Client
	read int
}

func (c *fabricIPListCounter) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	if list, ok := list.(*local.FabricIPList); ok {
		c.read += len(list.Items)
	}
	return nil
}

func TestFabricIPPodEventCopiesOnlyAffectedClaims(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := local.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	claim := func(name, ns, pod, uid string) *local.FabricIP {
		return &local.FabricIP{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: local.FabricIPSpec{PodNamespace: ns, PodName: pod, PodUID: uid}}
	}
	objects := []client.Object{claim("current", "tenant", "pod", "new"), claim("predecessor", "tenant", "pod", "old"), claim("other-namespace", "other", "pod", "new")}
	for i := range 1200 {
		objects = append(objects, claim(fmt.Sprintf("foreign-%d", i), "tenant", fmt.Sprintf("other-%d", i), "other"))
	}
	c := &fabricIPListCounter{Client: fake.NewClientBuilder().WithScheme(scheme).
		WithIndex(&local.FabricIP{}, fabricIPPodIndex, fabricIPPodKeys).WithObjects(objects...).Build()}
	r := &FabricIPReconciler{Client: c}
	requests := r.mapPodToFabricIPs(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod", UID: "new"}})
	if len(requests) != 2 || c.read != 2 {
		t.Fatalf("one Pod event copied %d claims, enqueued %v; want only both name-generation claims", c.read, requests)
	}
}
