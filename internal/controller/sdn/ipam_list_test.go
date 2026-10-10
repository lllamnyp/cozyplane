package sdn

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// controller-runtime's fake ignores Limit/Continue. Apply them to its actual
// object list so allocator tests exercise multiple pages instead of one list.
type pagedServiceVIPClient struct{ client.Client }

func (c pagedServiceVIPClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := c.Client.List(ctx, list, opts...); err != nil {
		return err
	}
	options := (&client.ListOptions{}).ApplyOptions(opts)
	if options.Limit == 0 {
		return nil
	}
	objects, err := meta.ExtractList(list)
	if err != nil {
		return err
	}
	sort.Slice(objects, func(i, j int) bool {
		a, b := objects[i].(metav1.Object), objects[j].(metav1.Object)
		return a.GetNamespace()+"/"+a.GetName() < b.GetNamespace()+"/"+b.GetName()
	})
	start := 0
	if options.Continue != "" {
		start, err = strconv.Atoi(options.Continue)
		if err != nil || start < 0 || start > len(objects) {
			return fmt.Errorf("invalid fake continuation")
		}
	}
	end := min(start+int(options.Limit), len(objects))
	if err := meta.SetList(list, objects[start:end]); err != nil {
		return err
	}
	list.SetContinue("")
	if end < len(objects) {
		list.SetContinue(fmt.Sprint(end))
	}
	return nil
}
