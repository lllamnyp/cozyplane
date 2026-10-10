/*
Copyright 2026 The Cozyplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sdn

import (
	"context"
	"fmt"
	"time"

	"github.com/lllamnyp/cozyplane/internal/ipam"
	"k8s.io/apimachinery/pkg/api/meta"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	quota "k8s.io/apiserver/pkg/quota/v1"
	"k8s.io/apiserver/pkg/quota/v1/generic"
	"k8s.io/client-go/rest"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnclientset "github.com/lllamnyp/cozyplane/pkg/generated/sdn/clientset/versioned"
)

// The ceiling (docs/multitenancy.md R5).
//
// Isolation without a ceiling is not tenancy — it is tenancy until the first
// tenant that wants everything. Nothing bounded a tenant's VPCs (and so its VNIs),
// the addresses it drew from a pool it was granted, or its SecurityGroups; and
// `attach` is a *binary* grant, so holding it meant you could drain the pool.
//
// The object for this already exists, and it is not one of ours: Kubernetes'
// **ResourceQuota**, with the `count/<resource>.<group>` idiom. What was missing is
// that the kube-apiserver's quota admission cannot see an aggregated API's kinds —
// so *this* server has to enforce it, which is exactly what the quota Evaluator
// interface is for. An operator writes:
//
//	kind: ResourceQuota
//	spec:
//	  hard:
//	    count/vpcs.sdn.cozystack.io:        "3"
//	    count/floatingips.sdn.cozystack.io: "8"
//
// and a tenant's fourth VPC is refused by the same machinery, with the same error,
// as its eleventh ConfigMap. No new kind, no new vocabulary, no new thing to learn.
//
// NOT quota'd here, deliberately:
//   - `Port` — one per pod, created by the CNI. Pods are already the unit
//     Kubernetes quotas; a Port ceiling would be a second, weaker spelling of a
//     limit that already binds.
//   - `ServiceVIP` — one per attached Service, created by the controller. Same
//     argument: `count/services` already bounds it.
//
// Both are also cluster-scoped, so a namespaced ResourceQuota could not name them
// anyway — and that is a symptom, not an obstacle: a tenant does not create them,
// it creates the pod or the Service that causes them.

// quotableResources are the tenant-created, namespaced kinds a ResourceQuota may
// bound. Each becomes `count/<resource>.sdn.cozystack.io`.
var quotableResources = []string{
	"vpcs",        // and therefore VNIs — a globally-shared keyspace
	"vpcgateways", // each may hold NAT addresses (via owned LB Services)
	"floatingips", // each holds an address (via an owned LB Service)
	"securitygroups",
	"vpcpeerings",
	"vpcbindings",
}

// NewQuotaConfiguration returns the evaluators this server offers to the
// ResourceQuota admission plugin: one object-count evaluator per tenant-created
// kind.
//
// The stock admission plugin charges each create against ResourceQuota status;
// it does not invoke UsageStats on each request. The registered listers support
// explicit usage calculation with bounded live pages and retained identities.
func NewQuotaConfiguration(loopback *rest.Config) (quota.Configuration, error) {
	client, err := sdnclientset.NewForConfig(loopback)
	if err != nil {
		return nil, fmt.Errorf("quota loopback client: %w", err)
	}

	evaluators := make([]quota.Evaluator, 0, len(quotableResources))
	for _, resource := range quotableResources {
		gr := schema.GroupResource{Group: sdn.GroupName, Resource: resource}
		evaluators = append(evaluators, generic.NewObjectCountEvaluator(gr, listerFor(client, resource), ""))
	}
	return generic.NewConfiguration(evaluators, nil), nil
}

// listerFor returns the namespace lister the object-count evaluator uses to
// compute current usage.
const quotaScanTimeout = 30 * time.Second

func listerFor(client sdnclientset.Interface, resource string) generic.ListFuncByNamespace {
	return func(namespace string) ([]runtime.Object, error) {
		ctx, cancel := context.WithTimeout(context.Background(), quotaScanTimeout)
		defer cancel()
		return listQuotaUsage(ctx, client, resource, namespace)
	}
}

// Generic object-count evaluation needs identity only: discard tenant payloads
// before requesting the next page, and never return an incomplete count.
func listQuotaUsage(ctx context.Context, client sdnclientset.Interface, resource, namespace string) ([]runtime.Object, error) {
	var objects []runtime.Object
	err := ipam.WalkClaims(ctx, func(limit int64, token string) ([]runtime.Object, string, error) {
		list, err := quotaPage(ctx, client, resource, namespace, metav1.ListOptions{Limit: limit, Continue: token})
		if err != nil {
			return nil, "", err
		}
		if meta.LenList(list) > int(limit) {
			return nil, "", fmt.Errorf("quota list exceeds requested page size")
		}
		listMeta, err := meta.ListAccessor(list)
		if err != nil {
			return nil, "", err
		}
		page, err := meta.ExtractList(list)
		if err != nil {
			return nil, "", err
		}
		for i := range page {
			identity, err := meta.Accessor(page[i])
			if err != nil {
				return nil, "", err
			}
			page[i] = &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
				Name: identity.GetName(), Namespace: identity.GetNamespace(), UID: identity.GetUID(),
			}}
		}
		return page, listMeta.GetContinue(), nil
	}, func(object *runtime.Object) { objects = append(objects, *object) })
	if err != nil {
		return nil, err
	}
	return objects, nil
}

func quotaPage(ctx context.Context, client sdnclientset.Interface, resource, namespace string, opts metav1.ListOptions) (runtime.Object, error) {
	v1 := client.SdnV1alpha1()
	switch resource {
	case "vpcs":
		return v1.VPCs(namespace).List(ctx, opts)
	case "vpcgateways":
		return v1.VPCGateways(namespace).List(ctx, opts)
	case "floatingips":
		return v1.FloatingIPs(namespace).List(ctx, opts)
	case "securitygroups":
		return v1.SecurityGroups(namespace).List(ctx, opts)
	case "vpcpeerings":
		return v1.VPCPeerings(namespace).List(ctx, opts)
	case "vpcbindings":
		return v1.VPCBindings(namespace).List(ctx, opts)
	}
	return nil, fmt.Errorf("no quota lister for %q", resource)
}
