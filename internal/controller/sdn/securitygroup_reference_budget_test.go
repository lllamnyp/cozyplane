package sdn

import (
	"context"
	"fmt"
	"strings"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestMembershipIndexRejectsUnusableVPCReferenceAndRecovers(t *testing.T) {
	group := &sdnv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant-a"}, Spec: sdnv1alpha1.SecurityGroupSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: strings.Repeat("x", 128<<10)}}}
	_, index := vpnObjectCache(t, group, &sdnv1alpha1.SecurityGroupList{ListMeta: metav1.ListMeta{ResourceVersion: "1"}, Items: []sdnv1alpha1.SecurityGroup{*group}}, membershipVPCIndex, membershipVPCKeys)
	for _, name := range index.ListIndexFuncValues("field:" + membershipVPCIndex) {
		if len(name) > 320 {
			t.Fatalf("real index retained a %d-byte unusable VPC key", len(name))
		}
	}
	group.Spec.VPCRef.Name = "net"
	if err := index.Update(group.DeepCopy()); err != nil {
		t.Fatal(err)
	}
	keys := membershipVPCKeys(group)
	if len(keys) != 1 || keys[0] != "tenant-a/net" {
		t.Fatal("valid reference did not recover", keys)
	}
	if err := index.Delete(group); err != nil {
		t.Fatal(err)
	}
	if len(index.ListIndexFuncValues("field:"+membershipVPCIndex)) != 0 {
		t.Fatal("deleted reference remains in the cache index")
	}
}

type unusableGroupReader struct {
	client.Client
	lists int
}

func (c *unusableGroupReader) List(ctx context.Context, out client.ObjectList, opts ...client.ListOption) error {
	c.lists++
	return fmt.Errorf("unusable reference must not expand an allocation scan")
}

func TestSecurityGroupUnusableLegacyAnchorDoesNotAllocateOrChurn(t *testing.T) {
	for _, value := range []string{strings.Repeat("x", 128<<10), "bad/name"} {
		group := &sdnv1alpha1.SecurityGroup{ObjectMeta: metav1.ObjectMeta{Name: "policy", Namespace: "tenant-a"}, Spec: sdnv1alpha1.SecurityGroupSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: value}}, Status: sdnv1alpha1.SecurityGroupStatus{ID: 1, Phase: sdnv1alpha1.SecurityGroupPhaseReady}}
		base := membershipClientBuilder(t).WithObjects(group).WithStatusSubresource(group).Build()
		c := &unusableGroupReader{Client: base}
		r := &SecurityGroupReconciler{Client: c}
		req := ctrl.Request{NamespacedName: client.ObjectKeyFromObject(group)}
		for i := range 25 {
			if _, err := r.Reconcile(t.Context(), req); err != nil {
				t.Fatal(err)
			}
			current := &sdnv1alpha1.SecurityGroup{}
			if err := c.Get(t.Context(), req.NamespacedName, current); err != nil {
				t.Fatal(err)
			}
			if current.Status.ID != 0 || current.Status.Phase != sdnv1alpha1.SecurityGroupPhasePending || c.lists != 0 {
				t.Fatal("invalid legacy anchor retained ID or performed a scan", current.Status, c.lists)
			}
			if i > 0 && current.ResourceVersion != group.ResourceVersion {
				t.Fatal("unchanged Pending state churned status")
			}
			group = current
		}
	}
}
