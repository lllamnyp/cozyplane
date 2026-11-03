package sdn

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	sdnfake "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned/fake"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	quota "k8s.io/apiserver/pkg/quota/v1"
	"k8s.io/apiserver/pkg/quota/v1/generic"
	k8stesting "k8s.io/client-go/testing"
)

func TestQuotaListerPagesAndDoesNotRetainTenantPayloads(t *testing.T) {
	client := sdnfake.NewSimpleClientset()
	count, calls := 130, 0
	client.PrependReactor("list", "vpcs", func(action k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if action.GetNamespace() != "tenant" {
			t.Fatal("quota count escaped namespace")
		}
		opts := action.(k8stesting.ListActionImpl).GetListOptions()
		start, _ := strconv.Atoi(opts.Continue)
		end := count
		if opts.Limit != 0 && start+int(opts.Limit) < end {
			end = start + int(opts.Limit)
		}
		list := &sdnv1alpha1.VPCList{}
		for i := start; i < end; i++ {
			list.Items = append(list.Items, sdnv1alpha1.VPC{
				ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("vpc-%d", i), Namespace: "tenant", Annotations: map[string]string{"payload": "retained-annotation"}},
				Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}},
			})
		}
		if end < count {
			list.Continue = strconv.Itoa(end)
		}
		return true, list, nil
	})
	objects, err := listerFor(client, "vpcs")("tenant")
	if err != nil || len(objects) != count {
		t.Fatalf("complete quota count=%d err=%v", len(objects), err)
	}
	if calls != 2 {
		t.Fatalf("quota list was not paged at %d: calls=%d", ipam.ClaimPageSize, calls)
	}
	for i, object := range objects {
		identity, ok := object.(*metav1.PartialObjectMetadata)
		if !ok || identity.Name != fmt.Sprintf("vpc-%d", i) || identity.Namespace != "tenant" || len(identity.Annotations) != 0 {
			t.Fatalf("quota retained tenant payload rather than count identity: %T", object)
		}
	}
	resource := schema.GroupResource{Group: sdnv1alpha1.GroupName, Resource: "vpcs"}
	name := generic.ObjectCountQuotaResourceNameFor(resource)
	evaluator := generic.NewObjectCountEvaluator(resource, listerFor(client, "vpcs"), "")
	stats, err := evaluator.UsageStats(quota.UsageStatsOptions{Namespace: "tenant", Resources: []corev1.ResourceName{name}})
	used := stats.Used[name]
	if err != nil || used.Value() != int64(count) {
		t.Fatalf("generic quota evaluator count=%s err=%v", used.String(), err)
	}
}

func TestQuotaListerRejectsIncompleteCounts(t *testing.T) {
	for _, name := range []string{"list error", "second page error", "no continuation progress", "oversized page"} {
		t.Run(name, func(t *testing.T) {
			client := sdnfake.NewSimpleClientset()
			calls := 0
			client.PrependReactor("list", "vpcs", func(action k8stesting.Action) (bool, runtime.Object, error) {
				calls++
				if name == "list error" || name == "second page error" && calls == 2 {
					return true, nil, fmt.Errorf("API unavailable")
				}
				count := 1
				if name == "oversized page" {
					count = ipam.ClaimPageSize + 1
				}
				list := &sdnv1alpha1.VPCList{ListMeta: metav1.ListMeta{Continue: "same-token"}, Items: make([]sdnv1alpha1.VPC, count)}
				return true, list, nil
			})
			objects, err := listerFor(client, "vpcs")("tenant")
			if err == nil || objects != nil {
				t.Fatalf("incomplete scan published quota count: count=%d err=%v", len(objects), err)
			}
			if calls > 2 {
				t.Fatal("failed scan continued making requests", calls)
			}
		})
	}
	client := sdnfake.NewSimpleClientset()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	objects, err := listQuotaUsage(ctx, client, "vpcs", "tenant")
	if !errors.Is(err, context.Canceled) || objects != nil || len(client.Actions()) != 0 {
		t.Fatalf("cancelled scan continued: count=%d err=%v actions=%d", len(objects), err, len(client.Actions()))
	}
}

func TestQuotaCountPreservesEachKindAndNamespace(t *testing.T) {
	for _, test := range []struct {
		resource string
		object   runtime.Object
	}{
		{"vpcs", &sdnv1alpha1.VPC{}},
		{"vpcgateways", &sdnv1alpha1.VPCGateway{}},
		{"floatingips", &sdnv1alpha1.FloatingIP{}},
		{"securitygroups", &sdnv1alpha1.SecurityGroup{}},
		{"vpcpeerings", &sdnv1alpha1.VPCPeering{}},
		{"vpcbindings", &sdnv1alpha1.VPCBinding{}},
	} {
		t.Run(test.resource, func(t *testing.T) {
			var objects []runtime.Object
			for i, ns := range []string{"tenant", "tenant", "foreign"} {
				object := test.object.DeepCopyObject()
				identity, err := meta.Accessor(object)
				if err != nil {
					t.Fatal(err)
				}
				identity.SetNamespace(ns)
				identity.SetName(fmt.Sprintf("object-%d", i))
				objects = append(objects, object)
			}
			// GuessKindToResource pluralizes VPCGateway incorrectly in preloaded
			// fake fixtures. Store every fixture under the actual served resource.
			client := sdnfake.NewSimpleClientset()
			for _, object := range objects {
				identity, _ := meta.Accessor(object)
				if err := client.Tracker().Create(sdnv1alpha1.SchemeGroupVersion.WithResource(test.resource), object, identity.GetNamespace()); err != nil {
					t.Fatal(err)
				}
			}
			resource := schema.GroupResource{Group: sdnv1alpha1.GroupName, Resource: test.resource}
			name := generic.ObjectCountQuotaResourceNameFor(resource)
			evaluator := generic.NewObjectCountEvaluator(resource, listerFor(client, test.resource), "")
			stats, err := evaluator.UsageStats(quota.UsageStatsOptions{Namespace: "tenant", Resources: []corev1.ResourceName{name}})
			used := stats.Used[name]
			if err != nil || used.Value() != 2 {
				t.Fatalf("quota count=%s err=%v", used.String(), err)
			}
		})
	}
}
