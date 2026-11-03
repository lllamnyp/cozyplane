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

package crdadmission

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lllamnyp/cozyplane/api/sdn"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func tenantResource(r string) schema.GroupVersionResource {
	return schema.GroupVersionResource{Group: sdn.GroupName, Version: "v1alpha1", Resource: r}
}
func testObject(kind, name, ns string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "sdn.cozystack.io/v1alpha1", "kind": kind, "metadata": map[string]any{"name": name}, "spec": spec}}
	if ns != "" {
		u.SetNamespace(ns)
	}
	return u
}

func testActualCollectionDelete(t *testing.T, ctx context.Context, d dynamic.Interface, ns string) {
	t.Helper()
	vpcs := d.Resource(tenantResource("vpcs")).Namespace(ns)
	for _, name := range []string{"collection-one", "collection-two"} {
		obj := testObject("VPC", name, ns, map[string]any{"cidrs": []any{"10.75.0.0/24"}})
		obj.SetLabels(map[string]string{"recipe-delete": "collection"})
		if _, err := vpcs.Create(ctx, obj, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if err := vpcs.DeleteCollection(ctx, metav1.DeleteOptions{}, metav1.ListOptions{LabelSelector: "recipe-delete=collection"}); err != nil {
		t.Fatalf("collection delete rejected: %v", err)
	}
	remaining, err := vpcs.List(ctx, metav1.ListOptions{LabelSelector: "recipe-delete=collection"})
	if err != nil || len(remaining.Items) != 0 {
		t.Fatalf("collection contents remain: %v", err)
	}
}
func testActualRBAC(t *testing.T, ctx context.Context, cfg *rest.Config, k kubernetes.Interface, d dynamic.Interface, ns string) {
	t.Helper()
	role, e := k.RbacV1().Roles(ns).Create(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "recipe-writer"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{sdn.GroupName}, Resources: []string{"vpcbindings", "vpcpeerings", "securitygroups", "securitygroups/status"}, Verbs: []string{"get", "create", "update", "patch", "delete"}}}}, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	principal := "crd-recipe-user-" + ns
	if _, e = k.RbacV1().RoleBindings(ns).Create(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: role.Name}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name}, Subjects: []rbacv1.Subject{{Kind: "User", Name: principal, APIGroup: rbacv1.GroupName}}}, metav1.CreateOptions{}); e != nil {
		t.Fatal(e)
	}
	imp := rest.CopyConfig(cfg)
	imp.Impersonate = rest.ImpersonationConfig{UserName: principal}
	caller, e := dynamic.NewForConfig(imp)
	if e != nil {
		t.Fatal(e)
	}
	// Wait on observed permission instead of assuming RBAC cache propagation.
	wait := func(verb, r string, allowed bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			sar, e := k.AuthorizationV1().SubjectAccessReviews().Create(ctx, &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{User: principal, ResourceAttributes: &authv1.ResourceAttributes{Namespace: ns, Verb: verb, Group: sdn.GroupName, Resource: r}}}, metav1.CreateOptions{})
			if e != nil {
				t.Fatal(e)
			}
			if sar.Status.Allowed == allowed {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("RBAC propagation: %s %s allowed=%v", verb, r, allowed)
	}
	wait("create", "vpcbindings", true)
	objects := []struct {
		resource string
		obj      *unstructured.Unstructured
	}{
		{"vpcbindings", testObject("VPCBinding", "rbac-binding", ns, map[string]any{"vpcRef": map[string]any{"name": "rbac-vpc"}})},
		{"vpcpeerings", testObject("VPCPeering", "rbac-peer", ns, map[string]any{"vpcRef": map[string]any{"name": "rbac-vpc"}, "peerRef": map[string]any{"namespace": ns, "name": "other-vpc"}})},
	}
	for _, obj := range objects {
		if _, e := caller.Resource(tenantResource(obj.resource)).Namespace(ns).Create(ctx, obj.obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); !apierrors.IsForbidden(e) && !apierrors.IsInvalid(e) {
			t.Fatalf("%s escalation not rejected by admission: %v", obj.resource, e)
		}
	}
	role.Rules = append(role.Rules, rbacv1.PolicyRule{APIGroups: []string{sdn.GroupName}, Resources: []string{"vpcs"}, Verbs: []string{"export", "peer"}})
	if _, e = k.RbacV1().Roles(ns).Update(ctx, role, metav1.UpdateOptions{}); e != nil {
		t.Fatal(e)
	}
	wait("export", "vpcs", true)
	wait("peer", "vpcs", true)
	for _, obj := range objects {
		if _, e := caller.Resource(tenantResource(obj.resource)).Namespace(ns).Create(ctx, obj.obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); e != nil {
			t.Fatalf("authorized %s rejected: %v", obj.resource, e)
		}
		data, e := json.Marshal(obj.obj.Object)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := caller.Resource(tenantResource(obj.resource)).Namespace(ns).Patch(ctx, obj.obj.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "crd-rbac-recipe", DryRun: []string{metav1.DryRunAll}}); e != nil {
			t.Fatalf("authorized SSA %s rejected: %v", obj.resource, e)
		}
	}
	sg := testObject("SecurityGroup", "rbac-managed", ns, map[string]any{"vpcRef": map[string]any{"name": "rbac-vpc"}, "podSelector": map[string]any{}})
	sg.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "neosequentia-portal"})
	admin := d.Resource(tenantResource("securitygroups")).Namespace(ns)
	created, e := admin.Create(ctx, sg, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		uid := created.GetUID()
		if e := admin.Delete(c, created.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); e != nil && !apierrors.IsNotFound(e) {
			t.Errorf("managed fixture cleanup: %v", e)
		}
	})
	sgc := caller.Resource(tenantResource("securitygroups")).Namespace(ns)
	if e := sgc.Delete(ctx, created.GetName(), metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}}); !apierrors.IsForbidden(e) {
		t.Fatalf("managed delete not forbidden: %v", e)
	}
	changed := created.DeepCopy()
	changed.SetLabels(nil)
	if _, e := sgc.Update(ctx, changed, metav1.UpdateOptions{}); !apierrors.IsForbidden(e) && !apierrors.IsInvalid(e) {
		t.Fatalf("managed ownership not rejected by admission: %v", e)
	}
	unchanged, e := admin.Get(ctx, created.GetName(), metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if unchanged.GetResourceVersion() != created.GetResourceVersion() || unchanged.GetLabels()["app.kubernetes.io/managed-by"] != "neosequentia-portal" {
		t.Fatal("denied update was persisted")
	}
	status := created.DeepCopy()
	status.SetLabels(nil)
	status.Object["spec"] = map[string]any{"vpcRef": map[string]any{"name": "forged-vpc"}}
	status.Object["status"] = map[string]any{"id": int64(12)}
	updated, e := sgc.UpdateStatus(ctx, status, metav1.UpdateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	ref, _, _ := unstructured.NestedString(updated.Object, "spec", "vpcRef", "name")
	if ref != "rbac-vpc" || updated.GetLabels()["app.kubernetes.io/managed-by"] != "neosequentia-portal" {
		t.Fatal("status crossed ownership/spec boundary")
	}
}

func testActualDistributionGuard(t *testing.T, ctx context.Context, d dynamic.Interface) {
	t.Helper()
	c := d.Resource(schema.GroupVersionResource{Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices"})
	local, e := c.Get(ctx, "v1alpha1.sdn.cozystack.io", metav1.GetOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if _, found, _ := unstructured.NestedMap(local.Object, "spec", "service"); found {
		t.Fatal("fixture already uses a remote tenant APIService")
	}
	patch := []byte(`{"spec":{"service":{"namespace":"b195-crd","name":"cozyplane-admission","port":443}}}`)
	if _, e := c.Patch(ctx, local.GetName(), types.MergePatchType, patch, metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); !apierrors.IsForbidden(e) {
		t.Fatalf("remote tenant APIService patch not denied: %v", e)
	}
	if _, e := c.Patch(ctx, local.GetName(), types.MergePatchType, []byte(`{"metadata":{"annotations":{"recipe":"local-update"}}}`), metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}}); e != nil {
		t.Fatalf("local autoregistration update rejected: %v", e)
	}
	other := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "apiregistration.k8s.io/v1", "kind": "APIService", "metadata": map[string]any{"name": "v1alpha1.crd-recipe.invalid"}, "spec": map[string]any{"group": "crd-recipe.invalid", "version": "v1alpha1", "groupPriorityMinimum": int64(100), "versionPriority": int64(10), "service": map[string]any{"namespace": "b195-crd", "name": "cozyplane-admission", "port": int64(443)}}}}
	if _, e := c.Create(ctx, other, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); e != nil {
		t.Fatalf("unrelated remote APIService rejected: %v", e)
	}
}

func testActualQuota(t *testing.T, ctx context.Context, k kubernetes.Interface, d dynamic.Interface, ns string) {
	t.Helper()
	quota, e := k.CoreV1().ResourceQuotas(ns).Create(ctx, &corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "recipe-zero-vpcs"}, Spec: corev1.ResourceQuotaSpec{Hard: corev1.ResourceList{corev1.ResourceName("count/vpcs.sdn.cozystack.io"): resource.MustParse("0")}}}, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, done := context.WithTimeout(context.Background(), 15*time.Second)
		defer done()
		uid := quota.UID
		if e := k.CoreV1().ResourceQuotas(ns).Delete(c, quota.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); e != nil {
			t.Errorf("quota cleanup: %v", e)
		}
	})
	obj := testObject("VPC", "quota-vpc", ns, map[string]any{"cidrs": []any{"10.73.0.0/24"}})
	if _, e := d.Resource(tenantResource("vpcs")).Namespace(ns).Create(ctx, obj, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); !apierrors.IsForbidden(e) {
		t.Fatalf("zero resource quota not enforced: %v", e)
	}
}

func testActualIPv6Names(t *testing.T, ctx context.Context, d dynamic.Interface, ns string) {
	for _, ip := range []string{"::2", "fd00:1::"} {
		port := testObject("Port", sdn.PortName(4194301, ip), "", map[string]any{"vpcRef": map[string]any{"name": "ipv6-vpc", "namespace": ns}, "ip": ip, "node": "test-node", "nodeIP": "192.0.2.2"})
		if _, e := d.Resource(tenantResource("ports")).Create(ctx, port, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); e != nil {
			t.Fatalf("IPv6 edge claim %s rejected: %v", ip, e)
		}
	}
}
