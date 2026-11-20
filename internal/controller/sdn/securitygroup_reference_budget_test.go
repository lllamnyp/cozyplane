package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type unusableGroupReader struct {
	client.Client
	lists int
}

func (c *unusableGroupReader) List(context.Context, client.ObjectList, ...client.ListOption) error {
	c.lists++
	return fmt.Errorf("unusable reference must not expand an allocation scan")
}

func TestSecurityGroupUnusableLegacyAnchorDoesNotAllocateOrChurn(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 128<<10), "bad/name"} {
		group := &sdn.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant-a"}, Spec: sdn.SecurityGroupSpec{VPCRef: sdn.LocalVPCRef{Name: value}}, Status: sdn.SecurityGroupStatus{ID: 1, Phase: sdn.SecurityGroupPhaseReady}}
		base := fake.NewClientBuilder().WithScheme(svcScheme(t)).WithObjects(group).WithStatusSubresource(group).Build()
		c := &unusableGroupReader{Client: base}
		r := &SecurityGroupReconciler{Client: c}
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(group)}
		for i := range 25 {
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			current := &sdn.SecurityGroup{}
			if err := c.Get(t.Context(), req.NamespacedName, current); err != nil {
				t.Fatal(err)
			}
			if current.Status.ID != 0 || current.Status.Phase != sdn.SecurityGroupPhasePending || c.lists != 0 {
				t.Fatal("invalid legacy anchor retained ID or performed a scan", current.Status, c.lists)
			}
			if i > 0 && current.ResourceVersion != group.ResourceVersion {
				t.Fatal("unchanged Pending state churned status")
			}
			group = current
		}
	}
}
