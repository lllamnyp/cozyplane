package sdn

import (
	"context"
	"fmt"
	"testing"
	"time"

	sdn "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type securityGroupPageReader struct {
	client.Reader
	pages  [][]sdn.SecurityGroup
	calls  int
	limits []int64
}

func (r *securityGroupPageReader) List(ctx context.Context, list client.ObjectList, options ...client.ListOption) error {
	groups, ok := list.(*sdn.SecurityGroupList)
	if !ok {
		return r.Reader.List(ctx, list, options...)
	}
	o := (&client.ListOptions{}).ApplyOptions(options)
	r.limits = append(r.limits, o.Limit)
	page := r.calls
	r.calls++
	if page >= len(r.pages) {
		return fmt.Errorf("unexpected extra page")
	}
	if page > 0 && o.Continue != fmt.Sprint(page) {
		return fmt.Errorf("missing continuation %d", page)
	}
	groups.Items = r.pages[page]
	groups.Continue = ""
	if page+1 < len(r.pages) {
		groups.Continue = fmt.Sprint(page + 1)
	}
	return nil
}

func TestGroupAllocationRequiresCompleteBoundedLiveScan(t *testing.T) {
	for _, test := range []struct {
		name          string
		initial, want int32
	}{{"new ID skips later-page claims", 0, 3}, {"duplicate repair finds older later-page claim", 2, 0}} {
		t.Run(test.name, func(t *testing.T) {
			a := sg("tenant", "a", "net", time.Now().Add(-time.Hour))
			b := sg("tenant", "b", "net", time.Now().Add(-time.Hour))
			current := sg("tenant", "current", "net", time.Now())
			a.Status.ID, b.Status.ID, current.Status.ID = 1, 2, test.initial
			c := membershipClientBuilder(t).WithObjects(current).WithStatusSubresource(&sdn.SecurityGroup{}).Build()
			reader := &securityGroupPageReader{Reader: c, pages: [][]sdn.SecurityGroup{{*a}, {*b}}}
			r := &SecurityGroupReconciler{Client: c, Reader: reader}
			request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: current.Namespace, Name: current.Name}}
			if _, err := r.Reconcile(t.Context(), request); err != nil {
				t.Fatal(err)
			}
			if err := c.Get(t.Context(), request.NamespacedName, current); err != nil {
				t.Fatal(err)
			}
			if current.Status.ID != test.want || reader.calls != 2 {
				t.Fatalf("ID=%d want=%d pages=%d", current.Status.ID, test.want, reader.calls)
			}
			for _, limit := range reader.limits {
				if limit != 128 {
					t.Fatal("live list did not bound page size", limit)
				}
			}
		})
	}
	current := sg("tenant", "current", "net", time.Now())
	c := membershipClientBuilder(t).WithObjects(current).WithStatusSubresource(&sdn.SecurityGroup{}).Build()
	reader := &securityGroupPageReader{Reader: c, pages: [][]sdn.SecurityGroup{make([]sdn.SecurityGroup, 129)}}
	r := &SecurityGroupReconciler{Client: c, Reader: reader}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: current.Namespace, Name: current.Name}}
	if _, err := r.Reconcile(t.Context(), request); err == nil {
		t.Fatal("oversized live page allocated an ID")
	}
	if err := c.Get(t.Context(), request.NamespacedName, current); err != nil || current.Status.ID != 0 {
		t.Fatal("failed scan published an allocation", current.Status, err)
	}
}
