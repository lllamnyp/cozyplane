package main

import (
	"fmt"
	"sort"
	"strconv"
	"testing"

	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func paginateTestCNIClaims(t *testing.T, client *sdnfake.Clientset) {
	t.Helper()
	for _, resource := range []string{"ports", "servicevips"} {
		client.PrependReactor("list", resource, func(action k8stesting.Action) (bool, runtime.Object, error) {
			handled, object, err := k8stesting.ObjectReaction(client.Tracker())(action)
			if !handled || err != nil {
				return handled, object, err
			}
			options := action.(interface{ GetListOptions() metav1.ListOptions }).GetListOptions()
			if options.Limit == 0 {
				return handled, object, nil
			}
			items, err := meta.ExtractList(object)
			if err != nil {
				return true, nil, err
			}
			selector, err := labels.Parse(options.LabelSelector)
			if err != nil {
				return true, nil, err
			}
			filtered := items[:0]
			for _, item := range items {
				if selector.Matches(labels.Set(item.(metav1.Object).GetLabels())) {
					filtered = append(filtered, item)
				}
			}
			items = filtered
			sort.Slice(items, func(i, j int) bool { return items[i].(metav1.Object).GetName() < items[j].(metav1.Object).GetName() })
			start := 0
			if options.Continue != "" {
				start, err = strconv.Atoi(options.Continue)
				if err != nil || start < 0 || start > len(items) {
					return true, nil, fmt.Errorf("invalid fake continuation")
				}
			}
			end := min(start+int(options.Limit), len(items))
			if err := meta.SetList(object, items[start:end]); err != nil {
				return true, nil, err
			}
			list, err := meta.ListAccessor(object)
			if err != nil {
				return true, nil, err
			}
			list.SetContinue("")
			if end < len(items) {
				list.SetContinue(fmt.Sprint(end))
			}
			return true, object, nil
		})
	}
}
