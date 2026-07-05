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
	"time"

	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := sdnv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("add to scheme: %v", err)
	}
	return s
}

func vpcWithVNI(name string, vni int32) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni},
	}
}

// Overlapping VPC CIDRs coexist: both get a VNI and go Ready (isolation is by
// overlay, not address space — stage 2). Only *peering* them is refused,
// elsewhere.
func TestVPCsWithOverlappingCIDRsBothReady(t *testing.T) {
	first := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "team-a"},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: 100, Phase: sdnv1alpha1.VPCPhaseReady},
	}
	second := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "second", Namespace: "team-b"},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}}, // identical CIDR
	}
	scheme := testScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(first, second).
		WithStatusSubresource(&sdnv1alpha1.VPC{}).Build()
	r := &VPCReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()

	key := types.NamespacedName{Namespace: "team-b", Name: "second"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.VPC{}
	if err := c.Get(ctx, key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.VNI == 0 || got.Status.Phase != sdnv1alpha1.VPCPhaseReady {
		t.Errorf("a VPC overlapping another should still be Ready with a VNI, got vni=%d phase=%q",
			got.Status.VNI, got.Status.Phase)
	}
	if got.Status.VNI == first.Status.VNI {
		t.Errorf("overlapping VPCs must get distinct VNIs, both got %d", got.Status.VNI)
	}
}

func TestAllocateVNI(t *testing.T) {
	cases := []struct {
		name string
		used []int32
		want int32
	}{
		{"none allocated starts at firstVNI", nil, firstVNI},
		{"lowest free above the run", []int32{100, 101}, 102},
		{"fills a gap", []int32{100, 102}, 101},
		// VNIs are unique cluster-wide even across namespaces.
		{"ignores zero (unallocated)", []int32{0, 100}, 101},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			objs := make([]client.Object, 0, len(c.used))
			for i, v := range c.used {
				objs = append(objs, vpcWithVNI(string(rune('a'+i)), v))
			}
			r := &VPCReconciler{Client: fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(objs...).Build()}
			got, err := r.allocateVNI(context.Background())
			if err != nil {
				t.Fatalf("allocateVNI: %v", err)
			}
			if got != c.want {
				t.Fatalf("allocateVNI = %d, want %d", got, c.want)
			}
		})
	}
}

func TestVPCReconcileAssignsVNIAndReady(t *testing.T) {
	scheme := testScheme(t)
	vpc := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a", Namespace: "team-a"},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.10.0.0/24"}},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(vpc).
		WithStatusSubresource(&sdnv1alpha1.VPC{}).
		Build()
	r := &VPCReconciler{Client: c, Scheme: scheme}

	key := types.NamespacedName{Namespace: "team-a", Name: "tenant-a"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	got := &sdnv1alpha1.VPC{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status.VNI < firstVNI {
		t.Errorf("VNI = %d, want >= %d", got.Status.VNI, firstVNI)
	}
	if got.Status.Phase != sdnv1alpha1.VPCPhaseReady {
		t.Errorf("phase = %q, want %q", got.Status.Phase, sdnv1alpha1.VPCPhaseReady)
	}
}

// A duplicate VNI (two VPCs sharing a network id) is a cross-tenant isolation
// break — it could arise before allocation read the API server live (the
// informer cache lagged the reconciler's own status writes). Repair is
// deterministic: the younger claim (creationTimestamp, then namespace/name)
// yields and reallocates; the older keeps its id. Reconciling the winner is a
// no-op, so the pair converges without fighting.
func TestVPCDuplicateVNIRepair(t *testing.T) {
	scheme := testScheme(t)
	older := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "older", Namespace: "team-b",
			CreationTimestamp: metav1.Date(2026, 7, 5, 6, 38, 24, 0, time.UTC)},
		Spec:   sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}},
		Status: sdnv1alpha1.VPCStatus{VNI: 101, Phase: sdnv1alpha1.VPCPhaseReady},
	}
	younger := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "younger", Namespace: "team-a",
			CreationTimestamp: metav1.Date(2026, 7, 5, 6, 38, 25, 0, time.UTC)},
		Spec:   sdnv1alpha1.VPCSpec{CIDRs: []string{"10.1.0.0/24"}},
		Status: sdnv1alpha1.VPCStatus{VNI: 101, Phase: sdnv1alpha1.VPCPhaseReady},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(older, younger).
		WithStatusSubresource(&sdnv1alpha1.VPC{}).Build()
	r := &VPCReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()

	// The younger duplicate yields and reallocates.
	ykey := types.NamespacedName{Namespace: "team-a", Name: "younger"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: ykey}); err != nil {
		t.Fatalf("reconcile younger: %v", err)
	}
	got := &sdnv1alpha1.VPC{}
	if err := c.Get(ctx, ykey, got); err != nil {
		t.Fatalf("get younger: %v", err)
	}
	if got.Status.VNI == 101 || got.Status.VNI == 0 {
		t.Errorf("younger duplicate should have reallocated, got vni=%d", got.Status.VNI)
	}

	// The older (winning) claim keeps its VNI.
	okey := types.NamespacedName{Namespace: "team-b", Name: "older"}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: okey}); err != nil {
		t.Fatalf("reconcile older: %v", err)
	}
	if err := c.Get(ctx, okey, got); err != nil {
		t.Fatalf("get older: %v", err)
	}
	if got.Status.VNI != 101 {
		t.Errorf("older claim must keep its VNI, got %d", got.Status.VNI)
	}
}

// Equal creationTimestamps (1s granularity — the live incident had both VPCs
// created the same second) fall back to namespace/name order; exactly one side
// yields.
func TestVPCDuplicateVNIRepairTimestampTie(t *testing.T) {
	scheme := testScheme(t)
	ts := metav1.Date(2026, 7, 5, 6, 38, 24, 0, time.UTC)
	winner := &sdnv1alpha1.VPC{ // "team-a/aaa" < "team-b/bbb"
		ObjectMeta: metav1.ObjectMeta{Name: "aaa", Namespace: "team-a", CreationTimestamp: ts},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.0.0.0/24"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: 105, Phase: sdnv1alpha1.VPCPhaseReady},
	}
	loser := &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: "bbb", Namespace: "team-b", CreationTimestamp: ts},
		Spec:       sdnv1alpha1.VPCSpec{CIDRs: []string{"10.1.0.0/24"}},
		Status:     sdnv1alpha1.VPCStatus{VNI: 105, Phase: sdnv1alpha1.VPCPhaseReady},
	}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(winner, loser).
		WithStatusSubresource(&sdnv1alpha1.VPC{}).Build()
	r := &VPCReconciler{Client: c, Scheme: scheme}
	ctx := context.Background()

	for _, k := range []types.NamespacedName{
		{Namespace: "team-a", Name: "aaa"},
		{Namespace: "team-b", Name: "bbb"},
	} {
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: k}); err != nil {
			t.Fatalf("reconcile %s: %v", k, err)
		}
	}
	a, b := &sdnv1alpha1.VPC{}, &sdnv1alpha1.VPC{}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-a", Name: "aaa"}, a); err != nil {
		t.Fatal(err)
	}
	if err := c.Get(ctx, types.NamespacedName{Namespace: "team-b", Name: "bbb"}, b); err != nil {
		t.Fatal(err)
	}
	if a.Status.VNI != 105 {
		t.Errorf("tiebreak winner must keep the VNI, got %d", a.Status.VNI)
	}
	if b.Status.VNI == 105 || b.Status.VNI == 0 {
		t.Errorf("tiebreak loser must reallocate, got %d", b.Status.VNI)
	}
}
