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
	"vpcgateways", // each may hold a NAT address out of a pool
	"floatingips", // each holds an address out of a pool
	"securitygroups",
	"vpcpeerings",
	"vpcbindings",
}

// NewQuotaConfiguration returns the evaluators this server offers to the
// ResourceQuota admission plugin: one object-count evaluator per tenant-created
// kind.
//
// Usage is counted by LISTing the namespace through the server's own loopback
// client — the same storage the create is about to write to. kube-apiserver's quota
// reads from shared informers instead, which is cheaper but stale, and staleness in
// a quota means over-admission. Creates here are rare (a tenant makes a VPC, not a
// VPC per request), so we buy exactness at a price nobody pays.
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
func listerFor(client sdnclientset.Interface, resource string) generic.ListFuncByNamespace {
	return func(namespace string) ([]runtime.Object, error) {
		ctx := context.TODO()
		opts := metav1.ListOptions{}
		v1 := client.SdnV1alpha1()

		switch resource {
		case "vpcs":
			l, err := v1.VPCs(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		case "vpcgateways":
			l, err := v1.VPCGateways(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		case "floatingips":
			l, err := v1.FloatingIPs(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		case "securitygroups":
			l, err := v1.SecurityGroups(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		case "vpcpeerings":
			l, err := v1.VPCPeerings(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		case "vpcbindings":
			l, err := v1.VPCBindings(namespace).List(ctx, opts)
			return items(l.Items, err, func(i int) runtime.Object { return &l.Items[i] }, len(l.Items))
		}
		return nil, fmt.Errorf("no quota lister for %q", resource)
	}
}

// items adapts a typed list to the []runtime.Object the evaluator wants. It is
// generic over nothing useful, so it takes an indexer instead.
func items[T any](_ []T, err error, at func(int) runtime.Object, n int) ([]runtime.Object, error) {
	if err != nil {
		return nil, err
	}
	out := make([]runtime.Object, 0, n)
	for i := range n {
		out = append(out, at(i))
	}
	return out, nil
}
