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

// These tests require an explicitly selected disposable CRD regional cluster.
package crdadmission

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestActualTenantCRDAdmission(t *testing.T) {
	path := os.Getenv("CRD_RECIPE_KUBECONFIG")
	if path == "" {
		t.Skip("CRD_RECIPE_KUBECONFIG must explicitly select a disposable cluster")
	}
	cfg, e := clientcmd.BuildConfigFromFlags("", path)
	if e != nil {
		t.Fatal("test kubeconfig unavailable")
	}
	cfg.Timeout = 15 * time.Second
	d, e := dynamic.NewForConfig(cfg)
	if e != nil {
		t.Fatal(e)
	}
	k, e := kubernetes.NewForConfig(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	// Fail before writes when this is not the isolated test distribution.
	mode, e := k.CoreV1().ConfigMaps(fixtureNamespace()).Get(ctx, "cozyplane-api-mode", metav1.GetOptions{})
	if e != nil || mode.Data["mode"] != "crd" {
		t.Fatal("disposable CRD fixture marker absent")
	}
	ns, e := k.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "b195-crd-recipe-"}}, metav1.CreateOptions{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, c := context.WithTimeout(context.Background(), 60*time.Second)
		defer c()
		uid := ns.UID
		if e := k.CoreV1().Namespaces().Delete(cleanup, ns.Name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); e != nil {
			t.Errorf("namespace cleanup: %v", e)
			return
		}
		for {
			_, err := k.CoreV1().Namespaces().Get(cleanup, ns.Name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				break
			}
			if err != nil || cleanup.Err() != nil {
				t.Errorf("namespace did not finish cleanup: %v", err)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	nodeLabel := "cozyplane.io/crd-recipe-node"
	nodes, e := k.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: nodeLabel + "=" + ns.Name})
	if e != nil || len(nodes.Items) != 0 {
		t.Fatal("HostFirewall fixture selector must match no node")
	}
	vpcRef := map[string]any{"namespace": ns.Name, "name": "test-object"}
	cases := []struct {
		resource, kind, name string
		cluster, status      bool
		spec                 map[string]any
	}{
		{"vpcs", "VPC", "test-object", false, true, map[string]any{"cidrs": []any{"10.71.0.0/24", "fd00:71::/64"}, "mtu": int64(1450)}},
		{"vpcbindings", "VPCBinding", "test-object", false, false, map[string]any{"vpcRef": vpcRef}},
		{"vpcpeerings", "VPCPeering", "test-object", false, true, map[string]any{"vpcRef": map[string]any{"name": "test-object"}, "peerRef": map[string]any{"namespace": ns.Name, "name": "test-peer"}}},
		{"vpcgateways", "VPCGateway", "test-object", false, true, map[string]any{"vpcRef": map[string]any{"name": "test-object"}}},
		{"securitygroups", "SecurityGroup", "test-object", false, true, map[string]any{"vpcRef": map[string]any{"name": "test-object"}, "podSelector": map[string]any{}}},
		{"floatingips", "FloatingIP", "test-object", false, true, map[string]any{"vpcRef": map[string]any{"name": "test-object"}, "target": "10.71.0.2"}},
		{"ports", "Port", "v4194300.10-71-0-2", true, true, map[string]any{"vpcRef": vpcRef, "ip": "10.71.0.2", "node": "test-node", "nodeIP": "192.0.2.2"}},
		{"servicevips", "ServiceVIP", "sv4194300.10-71-0-3", true, true, map[string]any{"vpcRef": vpcRef, "ip": "10.71.0.3", "serviceRef": map[string]any{"namespace": ns.Name, "name": "test-service"}, "ports": []any{map[string]any{"protocol": "TCP", "port": int64(80)}}}},
		{"hostfirewalls", "HostFirewall", "test-crd-firewall", true, true, map[string]any{"nodeSelector": map[string]any{"matchLabels": map[string]any{nodeLabel: ns.Name}}}},
		{"vpngateways", "VPNGateway", "test-object", false, true, map[string]any{"vpcRef": map[string]any{"name": "test-object"}, "externalAddress": map[string]any{}}},
		{"vpnconnections", "VPNConnection", "test-object", false, true, map[string]any{"gatewayRef": map[string]any{"name": "test-object"}, "remoteCIDRs": []any{"10.72.0.0/24"}}},
	}
	for _, tc := range cases {
		t.Run(tc.resource, func(t *testing.T) {
			gvr := schema.GroupVersionResource{Group: "sdn.cozystack.io", Version: "v1alpha1", Resource: tc.resource}
			var client dynamic.ResourceInterface = d.Resource(gvr)
			if !tc.cluster {
				client = d.Resource(gvr).Namespace(ns.Name)
			}
			obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "sdn.cozystack.io/v1alpha1", "kind": tc.kind, "metadata": map[string]any{"name": tc.name}, "spec": tc.spec}}
			if !tc.cluster {
				obj.SetNamespace(ns.Name)
			}
			if _, e := client.Create(ctx, obj.DeepCopy(), metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}}); e != nil {
				t.Fatalf("dry-run: %v", e)
			}
			if _, e := client.Get(ctx, tc.name, metav1.GetOptions{}); !apierrors.IsNotFound(e) {
				t.Fatalf("dry-run persisted or preexisting fixture: %v", e)
			}
			// Unknown fields must be pruned by the structural schema.
			obj.Object["spec"].(map[string]any)["unknownRecipeField"] = "must-be-pruned"
			created, e := client.Create(ctx, obj, metav1.CreateOptions{FieldManager: "crd-recipe"})
			if e != nil {
				t.Fatalf("create: %v", e)
			}
			t.Cleanup(func() {
				clean, c := context.WithTimeout(context.Background(), 15*time.Second)
				defer c()
				uid := created.GetUID()
				if e := client.Delete(clean, tc.name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); e != nil && !apierrors.IsNotFound(e) {
					t.Errorf("resource cleanup: %v", e)
				}
			})
			if _, found, _ := unstructured.NestedFieldNoCopy(created.Object, "spec", "unknownRecipeField"); found {
				t.Fatal("unknown spec field retained")
			}
			if _, e := client.Create(ctx, obj, metav1.CreateOptions{}); !apierrors.IsAlreadyExists(e) {
				t.Fatalf("duplicate not typed AlreadyExists: %v", e)
			}
			watched, e := client.Watch(ctx, metav1.ListOptions{FieldSelector: "metadata.name=" + tc.name, ResourceVersion: created.GetResourceVersion()})
			if e != nil {
				t.Fatal(e)
			}
			defer watched.Stop()
			patched, e := client.Patch(ctx, tc.name, types.MergePatchType, []byte(`{"metadata":{"labels":{"recipe":"patched"}}}`), metav1.PatchOptions{})
			if e != nil {
				t.Fatalf("patch: %v", e)
			}
			select {
			case ev := <-watched.ResultChan():
				observed, ok := ev.Object.(*unstructured.Unstructured)
				if ev.Type != watch.Modified || !ok || observed.GetUID() != created.GetUID() || observed.GetLabels()["recipe"] != "patched" {
					t.Fatal("watch did not observe the expected Modified object")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("watch did not observe patch")
			}
			if tc.status {
				originalSpec := patched.DeepCopy().Object["spec"]
				originalLabels := patched.GetLabels()
				patched.Object["spec"] = map[string]any{"malicious": "must-not-persist"}
				patched.SetLabels(map[string]string{"app.kubernetes.io/managed-by": "forged-status"})
				patched.Object["status"] = map[string]any{}
				updated, e := client.UpdateStatus(ctx, patched, metav1.UpdateOptions{})
				if e != nil {
					t.Fatalf("status: %v", e)
				}
				if !reflect.DeepEqual(updated.Object["spec"], originalSpec) || !reflect.DeepEqual(updated.GetLabels(), originalLabels) {
					t.Fatal("status changed spec or ownership metadata")
				}
			}
			apply := obj.DeepCopy()
			delete(apply.Object["spec"].(map[string]any), "unknownRecipeField")
			data, e := json.Marshal(apply)
			if e != nil {
				t.Fatal(e)
			}
			if _, e := client.Patch(ctx, tc.name, types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "crd-recipe", Force: ptr(true)}); e != nil {
				t.Fatalf("SSA: %v", e)
			}
			if tc.resource == "ports" {
				vip := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "sdn.cozystack.io/v1alpha1", "kind": "ServiceVIP", "metadata": map[string]any{"name": "sv4194300.10-71-0-2"}, "spec": map[string]any{"vpcRef": vpcRef, "ip": "10.71.0.2", "serviceRef": map[string]any{"namespace": ns.Name, "name": "test-service"}}}}
				if _, e := d.Resource(schema.GroupVersionResource{Group: gvr.Group, Version: gvr.Version, Resource: "servicevips"}).Create(ctx, vip, metav1.CreateOptions{}); !apierrors.IsConflict(e) {
					t.Fatalf("cross-kind conflict lost across kube-apiserver: %v", e)
				}
				current, e := client.Get(ctx, tc.name, metav1.GetOptions{})
				if e != nil {
					t.Fatal(e)
				}
				current.Object["status"] = map[string]any{"groups": []any{int64(63)}}
				if _, e := client.UpdateStatus(ctx, current, metav1.UpdateOptions{}); !apierrors.IsInvalid(e) {
					t.Fatalf("hostile World status accepted: %v", e)
				}
			}
		})
	}
	t.Run("RBAC-export-peer-managed-status", func(t *testing.T) { testActualRBAC(t, ctx, cfg, k, d, ns.Name) })
	t.Run("native-quota", func(t *testing.T) { testActualQuota(t, ctx, k, d, ns.Name) })
	t.Run("IPv6-edge-claims", func(t *testing.T) { testActualIPv6Names(t, ctx, d, ns.Name) })
	t.Run("persistent-distribution-guard", func(t *testing.T) { testActualDistributionGuard(t, ctx, d) })
	t.Run("collection-delete", func(t *testing.T) { testActualCollectionDelete(t, ctx, d, ns.Name) })
	t.Run("webhook-outage-bootstrap-recovery", func(t *testing.T) { testActualWebhookOutage(t, ctx, k, d, ns.Name) })
}
func ptr[T any](v T) *T { return &v }

func fixtureNamespace() string {
	if namespace := os.Getenv("CRD_RECIPE_NAMESPACE"); namespace != "" {
		return namespace
	}
	return "b195-crd"
}
