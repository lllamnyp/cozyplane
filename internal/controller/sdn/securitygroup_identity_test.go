package sdn

import (
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/sgidentity"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

func TestMembershipGroupRecreationAndPodRebind(t *testing.T) {
	group := sg("tenant", "group", "net", time.Now())
	group.Status.ID = 1
	group.Spec.PodSelector.MatchLabels = map[string]string{"role": "member"}
	port := &sdn.Port{ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2", Labels: map[string]string{sdn.LabelPodUID: "pod"}, Annotations: map[string]string{sdn.AnnotationPodLabels: `{"role":"member"}`}}, Spec: sdn.PortSpec{VPCRef: sdn.VPCRef{Namespace: "tenant", Name: "net"}, IP: "10.0.0.2"}}
	c := membershipClientBuilder(t).WithObjects(group, port).WithStatusSubresource(&sdn.Port{}, &sdn.SecurityGroup{}).Build()
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
	if got := sgidentity.NewIndex([]*sdn.SecurityGroup{group}).Bitmap(port); got != 2 || port.Status.GroupPodUID != "pod" {
		t.Fatal("current status proof was not published", port.Status, got)
	}
	if err := c.Delete(t.Context(), group); err != nil {
		t.Fatal(err)
	}
	replacement := group.DeepCopy()
	replacement.ResourceVersion = ""
	replacement.UID = "replacement-group"
	replacement.Spec.PodSelector.MatchLabels["role"] = "different"
	if err := c.Create(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	if got := sgidentity.NewIndex([]*sdn.SecurityGroup{replacement}).Bitmap(port); got != 1 {
		t.Fatal("stale status adopted replacement UID", got)
	}
	reconcile()
	if len(port.Status.Groups) != 0 || len(port.Status.GroupRefs) != 0 {
		t.Fatal("nonmember retained predecessor identity", port.Status)
	}
	replacement.Spec.PodSelector.MatchLabels["role"] = "member"
	if err := c.Update(t.Context(), replacement); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if sgidentity.NewIndex([]*sdn.SecurityGroup{replacement}).Bitmap(port) != 2 {
		t.Fatal("current replacement did not recover")
	}
	port.Labels[sdn.LabelPodUID] = "new-pod"
	if err := c.Update(t.Context(), port); err != nil {
		t.Fatal(err)
	}
	if sgidentity.NewIndex([]*sdn.SecurityGroup{replacement}).Bitmap(port) != 1 {
		t.Fatal("pod rebind reused predecessor membership")
	}
	reconcile()
	if sgidentity.NewIndex([]*sdn.SecurityGroup{replacement}).Bitmap(port) != 2 {
		t.Fatal("rebound pod did not recover after controller proof")
	}
	duplicate := sg("tenant", "duplicate", "net", time.Now())
	duplicate.Status.ID = replacement.Status.ID
	duplicate.Spec.PodSelector = replacement.Spec.PodSelector
	if err := c.Create(t.Context(), duplicate); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if len(port.Status.Groups) != 1 || port.Status.Groups[0] != 0 || len(port.Status.GroupRefs) != 0 {
		t.Fatal("ambiguous allocated ID acquired a status proof", port.Status)
	}
	if err := c.Delete(t.Context(), duplicate); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if sgidentity.NewIndex([]*sdn.SecurityGroup{replacement}).Bitmap(port) != 2 {
		t.Fatal("duplicate repair did not restore current UID proof")
	}
}
