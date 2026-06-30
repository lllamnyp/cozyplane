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
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func vpcBinding(ns, name, vpcNS, vpcName string, withFinalizer bool) *sdnv1alpha1.VPCBinding {
	b := &sdnv1alpha1.VPCBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       sdnv1alpha1.VPCBindingSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName}},
	}
	if withFinalizer {
		b.Finalizers = []string{vpcBindingFinalizer}
	}
	return b
}

func portFor(name, vpcNS, vpcName, podNS string) *sdnv1alpha1.Port {
	return &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{
			sdnv1alpha1.LabelVPCNamespace: vpcNS,
			sdnv1alpha1.LabelVPC:          vpcName,
			sdnv1alpha1.LabelPodNamespace: podNS,
		}},
		Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: vpcNS, Name: vpcName}, PodNamespace: podNS},
	}
}

func TestVPCBindingReconcileAddsFinalizer(t *testing.T) {
	scheme := testScheme(t)
	b := vpcBinding("team-b", "use-shared", "shared", "db", false)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(b).Build()
	r := &VPCBindingReconciler{Client: c, Scheme: scheme}

	key := types.NamespacedName{Namespace: "team-b", Name: "use-shared"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.VPCBinding{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Finalizers) == 0 || got.Finalizers[0] != vpcBindingFinalizer {
		t.Fatalf("finalizer not added: %v", got.Finalizers)
	}
}

func TestVPCBindingReapsPortsOnDelete(t *testing.T) {
	scheme := testScheme(t)
	b := vpcBinding("team-b", "use-shared", "shared", "db", true)
	// Two of this consumer's ports on the VPC, plus one unrelated port that must
	// survive (different consumer namespace).
	p1 := portFor("v100.10-0-0-2", "shared", "db", "team-b")
	p2 := portFor("v100.10-0-0-3", "shared", "db", "team-b")
	other := portFor("v100.10-0-0-9", "shared", "db", "team-c")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(b, p1, p2, other).Build()
	r := &VPCBindingReconciler{Client: c, Scheme: scheme}

	ctx := context.Background()
	if err := c.Delete(ctx, b); err != nil {
		t.Fatalf("delete: %v", err)
	}
	key := types.NamespacedName{Namespace: "team-b", Name: "use-shared"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The binding's two ports are gone.
	for _, n := range []string{"v100.10-0-0-2", "v100.10-0-0-3"} {
		err := c.Get(ctx, types.NamespacedName{Name: n}, &sdnv1alpha1.Port{})
		if !apierrors.IsNotFound(err) {
			t.Errorf("port %s: expected NotFound, got %v", n, err)
		}
	}
	// The unrelated consumer's port survives.
	if err := c.Get(ctx, types.NamespacedName{Name: "v100.10-0-0-9"}, &sdnv1alpha1.Port{}); err != nil {
		t.Errorf("unrelated port should survive, got %v", err)
	}
	// Finalizer removed => binding fully deleted.
	if err := c.Get(ctx, key, &sdnv1alpha1.VPCBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("binding should be gone, got %v", err)
	}
}

func TestVPCBindingKeepsPortsWhenAnotherGrantExists(t *testing.T) {
	scheme := testScheme(t)
	// Two bindings in the same namespace authorize the same VPC.
	b1 := vpcBinding("team-b", "use-shared-1", "shared", "db", true)
	b2 := vpcBinding("team-b", "use-shared-2", "shared", "db", true)
	p1 := portFor("v100.10-0-0-2", "shared", "db", "team-b")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(b1, b2, p1).Build()
	r := &VPCBindingReconciler{Client: c, Scheme: scheme}

	ctx := context.Background()
	if err := c.Delete(ctx, b1); err != nil {
		t.Fatalf("delete: %v", err)
	}
	key := types.NamespacedName{Namespace: "team-b", Name: "use-shared-1"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// The port survives because b2 still authorizes the VPC.
	if err := c.Get(ctx, types.NamespacedName{Name: "v100.10-0-0-2"}, &sdnv1alpha1.Port{}); err != nil {
		t.Errorf("port should survive while another binding grants access, got %v", err)
	}
	// b1 is still released.
	if err := c.Get(ctx, key, &sdnv1alpha1.VPCBinding{}); !apierrors.IsNotFound(err) {
		t.Errorf("b1 should be gone, got %v", err)
	}
}
