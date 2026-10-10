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
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// Stop only the marked disposable fixture's webhook Deployment. Changing a
// Service selector alone leaves existing kube-apiserver TLS connections alive.
// This tests actual failurePolicy without reading TLS keys.
func testActualWebhookOutage(t *testing.T, ctx context.Context, k kubernetes.Interface, d dynamic.Interface, ns string) {
	t.Helper()
	vpcs := d.Resource(tenantResource("vpcs")).Namespace(ns)
	obj := testObject("VPC", "outage-target", ns, map[string]any{"cidrs": []any{"10.73.0.0/24"}})
	created, err := vpcs.Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		uid := created.GetUID()
		if err := vpcs.Delete(clean, created.GetName(), metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid}}); err != nil && !apierrors.IsNotFound(err) {
			t.Errorf("outage object cleanup: %v", err)
		}
	})
	deployments := k.AppsV1().Deployments(fixtureNamespace())
	deployment, err := deployments.Get(ctx, "cozyplane-admission", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	original := deployment.DeepCopy()
	restored := false
	restore := func() {
		if restored {
			return
		}
		clean, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		current, err := deployments.Get(clean, deployment.Name, metav1.GetOptions{})
		if err != nil || current.UID != original.UID {
			t.Errorf("outage Deployment identity changed or unavailable: %v", err)
			return
		}
		current.Spec.Replicas = original.Spec.Replicas
		if _, err = deployments.Update(clean, current, metav1.UpdateOptions{}); err != nil {
			t.Errorf("restore admission Deployment: %v", err)
			return
		}
		restored = true
	}
	// Registered last so restoration precedes fixture object/namespace cleanup.
	t.Cleanup(restore)
	deployment.Spec.Replicas = ptr(int32(0))
	if _, err = deployments.Update(ctx, deployment, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		pods, err := k.CoreV1().Pods(fixtureNamespace()).List(ctx, metav1.ListOptions{LabelSelector: "app=cozyplane-admission"})
		if err != nil {
			t.Fatal(err)
		}
		if len(pods.Items) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission Pods did not stop")
		}
		time.Sleep(100 * time.Millisecond)
	}
	waitEndpoints := func(wantReady bool) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			slices, err := k.DiscoveryV1().EndpointSlices(fixtureNamespace()).List(ctx, metav1.ListOptions{LabelSelector: "kubernetes.io/service-name=cozyplane-admission"})
			if err != nil {
				t.Fatal(err)
			}
			ready := false
			for _, slice := range slices.Items {
				for _, endpoint := range slice.Endpoints {
					if len(endpoint.Addresses) > 0 && (endpoint.Conditions.Ready == nil || *endpoint.Conditions.Ready) {
						ready = true
					}
				}
			}
			if ready == wantReady {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("admission endpoints ready=%v not observed", wantReady)
	}
	waitEndpoints(false)
	reject := func(op string, err error) {
		t.Helper()
		if !apierrors.IsInternalError(err) {
			t.Fatalf("%s must fail closed on webhook unavailability: %v", op, err)
		}
	}
	create := obj.DeepCopy()
	create.SetName("outage-new")
	_, err = vpcs.Create(ctx, create, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	reject("create", err)
	update := created.DeepCopy()
	update.SetLabels(map[string]string{"outage": "must-not-persist"})
	_, err = vpcs.Update(ctx, update, metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
	reject("update", err)
	_, err = vpcs.UpdateStatus(ctx, created.DeepCopy(), metav1.UpdateOptions{DryRun: []string{metav1.DryRunAll}})
	reject("status", err)
	reject("delete", vpcs.Delete(ctx, created.GetName(), metav1.DeleteOptions{DryRun: []string{metav1.DryRunAll}}))
	if _, err = vpcs.Get(ctx, created.GetName(), metav1.GetOptions{}); err != nil {
		t.Fatalf("tenant read unavailable during outage: %v", err)
	}
	fabric := testObject("FabricIP", "f-198-18-195-250", "", map[string]any{"address": "198.18.195.250", "node": "test-node"})
	fabric.SetAPIVersion("local.sdn.cozystack.io/v1alpha1")
	_, err = d.Resource(schema.GroupVersionResource{Group: "local.sdn.cozystack.io", Version: "v1alpha1", Resource: "fabricips"}).Create(ctx, fabric, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		t.Fatalf("FabricIP bootstrap blocked by tenant outage: %v", err)
	}
	_, err = k.CoreV1().ConfigMaps(ns).Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: "outage-bootstrap"}}, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
	if err != nil {
		t.Fatalf("core bootstrap blocked by tenant outage: %v", err)
	}
	restore()
	if !restored {
		t.Fatal("admission Deployment restoration failed")
	}
	waitEndpoints(true)
	// EndpointSlice readiness precedes kube-proxy/informer propagation. Observe
	// successful real admission, rather than assuming the Service is instant.
	deadline = time.Now().Add(15 * time.Second)
	for {
		_, err = vpcs.Create(ctx, create, metav1.CreateOptions{DryRun: []string{metav1.DryRunAll}})
		if err == nil {
			break
		}
		if !apierrors.IsInternalError(err) || time.Now().After(deadline) {
			t.Fatalf("tenant admission did not recover: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
