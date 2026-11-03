package sdn

import (
	"context"
	"fmt"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func membershipClientBuilder(t *testing.T) *fake.ClientBuilder {
	t.Helper()
	return fake.NewClientBuilder().WithScheme(svcScheme(t)).
		WithIndex(&sdn.Port{}, membershipVPCIndex, membershipVPCKeys).
		WithIndex(&sdn.SecurityGroup{}, membershipVPCIndex, membershipVPCKeys).
		WithIndex(&sdn.Port{}, membershipPodIndex, membershipPodKeys)
}

type membershipListCounter struct {
	client.Client
	ports, groups int
}

func (c *membershipListCounter) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	if err := c.Client.List(ctx, list, options...); err != nil {
		return err
	}
	switch list := list.(type) {
	case *sdn.PortList:
		c.ports += len(list.Items)
	case *sdn.SecurityGroupList:
		c.groups += len(list.Items)
	}
	return nil
}

func TestMembershipWorkIsScopedToVPC(t *testing.T) {
	group := sg("tenant", "local", "net", time.Now())
	group.Status.ID = 1
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdn.LabelPodNamespace: "tenant", sdn.LabelPodName: "pod"}}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}}}
	objects := []client.Object{group, port}
	for i := range 1200 {
		objects = append(objects,
			&sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("foreign-%d", i)}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "other"}}},
			sg("tenant", fmt.Sprintf("foreign-%d", i), "other", time.Now()))
	}
	c := &membershipListCounter{Client: membershipClientBuilder(t).WithObjects(objects...).WithStatusSubresource(&sdn.Port{}).Build()}
	r := &PortMembershipReconciler{Client: c}
	requests := r.mapSGToPorts(t.Context(), group)
	if len(requests) != 1 || requests[0].Name != port.Name || c.ports != 1 {
		t.Errorf("one VPC group update read %d Ports and returned %v", c.ports, requests)
	}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}}); err != nil {
		t.Fatal(err)
	}
	if c.groups != 1 {
		t.Errorf("one Port resolution read %d unrelated groups", c.groups)
	}
	requests = r.mapPodToPorts(t.Context(), &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "tenant", Name: "pod"}})
	if len(requests) != 1 || requests[0].Name != port.Name || c.ports != 2 {
		t.Fatal("pod index lost its Port or copied unrelated Ports", requests, c.ports)
	}
}

func TestMembershipOversizedSelectorRetainsDenyAndRecovers(t *testing.T) {
	group := sg("tenant", "large", "net", time.Now())
	group.Status.ID = 1
	values := make([]string, 65537)
	for i := range values {
		values[i] = "member"
	}
	group.Spec.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "role", Operator: metav1.LabelSelectorOpIn, Values: values}}
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdn.LabelPodUID: "pod-uid"}, Annotations: map[string]string{sdn.AnnotationPodLabels: `{"role":"member"}`}}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}}}
	c := membershipClientBuilder(t).WithObjects(group, port).WithStatusSubresource(&sdn.Port{}).Build()
	r := &PortMembershipReconciler{Client: c}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: port.Name}}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(t.Context(), request); err != nil {
			t.Fatal(err)
		}
		if err := c.Get(t.Context(), request.NamespacedName, port); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 0 || len(port.Status.GroupRefs) != 0 {
		t.Fatalf("oversized selector resolved permissions: %+v", port.Status)
	}
	group.Spec.PodSelector.MatchExpressions[0].Values = []string{"member"}
	if err := c.Update(t.Context(), group); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 1 || len(port.Status.GroupRefs) != 1 {
		t.Fatal("bounded selector failed to recover", port.Status)
	}
	group.Spec.PodSelector.MatchExpressions[0].Operator = "invalid-legacy-operator"
	if err := c.Update(t.Context(), group); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 0 || len(port.Status.GroupRefs) != 0 {
		t.Fatal("malformed legacy selector became allow membership", port.Status)
	}
	group.Spec.PodSelector.MatchExpressions[0].Operator = metav1.LabelSelectorOpIn
	if err := c.Update(t.Context(), group); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 1 {
		t.Fatal("repaired selector did not recover", port.Status)
	}
}
