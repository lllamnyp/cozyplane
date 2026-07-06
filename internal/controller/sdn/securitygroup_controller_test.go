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
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

func sg(ns, name, vpc string, created time.Time) *sdnv1alpha1.SecurityGroup {
	return &sdnv1alpha1.SecurityGroup{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, CreationTimestamp: metav1.NewTime(created)},
		Spec:       sdnv1alpha1.SecurityGroupSpec{VPCRef: sdnv1alpha1.LocalVPCRef{Name: vpc}},
	}
}

func reconcileSG(t *testing.T, r *SecurityGroupReconciler, ns, name string) *sdnv1alpha1.SecurityGroup {
	t.Helper()
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.SecurityGroup{}
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	return got
}

// Two groups in the same VPC get distinct ids; a group in another VPC reuses the
// low id (ids are per-VPC, since the datapath keys them by net).
func TestSecurityGroupIDAllocationPerVPC(t *testing.T) {
	t0 := time.Now()
	a := sg("team-a", "web", "vpc-a", t0)
	b := sg("team-a", "db", "vpc-a", t0.Add(time.Second))
	other := sg("team-a", "web", "vpc-b", t0) // same name, different VPC
	// distinct object names within the namespace
	other.Name = "web-b"
	other.Spec.VPCRef.Name = "vpc-b"
	c := fake.NewClientBuilder().WithScheme(svcScheme(t)).
		WithObjects(a, b, other).
		WithStatusSubresource(&sdnv1alpha1.SecurityGroup{}).
		Build()
	r := &SecurityGroupReconciler{Client: c}

	gotA := reconcileSG(t, r, "team-a", "web")
	gotB := reconcileSG(t, r, "team-a", "db")
	gotOther := reconcileSG(t, r, "team-a", "web-b")

	if gotA.Status.ID != 1 {
		t.Errorf("web id = %d, want 1", gotA.Status.ID)
	}
	if gotB.Status.ID != 2 {
		t.Errorf("db id = %d, want 2 (same VPC, must differ)", gotB.Status.ID)
	}
	if gotOther.Status.ID != 1 {
		t.Errorf("web-b id = %d, want 1 (different VPC reuses ids)", gotOther.Status.ID)
	}
	if gotA.Status.Phase != sdnv1alpha1.SecurityGroupPhaseReady {
		t.Errorf("web phase = %q, want Ready", gotA.Status.Phase)
	}
}

// Two groups in the same VPC that ended up with the same id: the younger yields
// (deterministic tiebreak), so the collision repairs to distinct ids.
func TestSecurityGroupDuplicateIDRepair(t *testing.T) {
	t0 := time.Now()
	older := sg("team-a", "web", "vpc-a", t0)
	older.Status.ID = 1
	younger := sg("team-a", "db", "vpc-a", t0.Add(time.Second))
	younger.Status.ID = 1 // duplicate
	c := fake.NewClientBuilder().WithScheme(svcScheme(t)).
		WithObjects(older, younger).
		WithStatusSubresource(&sdnv1alpha1.SecurityGroup{}).
		Build()
	r := &SecurityGroupReconciler{Client: c}

	// Younger reconciles first: it loses the tiebreak and releases its id.
	gotYounger := reconcileSG(t, r, "team-a", "db")
	if gotYounger.Status.ID == 1 {
		t.Fatalf("younger kept id 1; expected it to yield")
	}
	// Re-allocate the younger; it must land on a free id (2), not collide again.
	gotYounger = reconcileSG(t, r, "team-a", "db")
	if gotYounger.Status.ID != 2 {
		t.Errorf("younger re-allocated id = %d, want 2", gotYounger.Status.ID)
	}
	gotOlder := reconcileSG(t, r, "team-a", "web")
	if gotOlder.Status.ID != 1 {
		t.Errorf("older id = %d, want 1 kept", gotOlder.Status.ID)
	}
}

// Membership resolves from the pod-labels annotation: a matching selector adds
// its group id, a non-matching pod stays empty.
func TestPortMembershipResolution(t *testing.T) {
	web := sg("team-a", "web", "vpc-a", time.Now())
	web.Spec.PodSelector = metav1.LabelSelector{MatchLabels: map[string]string{"role": "web"}}
	web.Status.ID = 7
	web.Status.Phase = sdnv1alpha1.SecurityGroupPhaseReady

	member := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "v101.10-70-0-4",
			Annotations: map[string]string{sdnv1alpha1.AnnotationPodLabels: `{"role":"web"}`},
		},
		Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"}, IP: "10.70.0.4"},
	}
	nonMember := &sdnv1alpha1.Port{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "v101.10-70-0-5",
			Annotations: map[string]string{sdnv1alpha1.AnnotationPodLabels: `{"role":"client"}`},
		},
		Spec: sdnv1alpha1.PortSpec{VPCRef: sdnv1alpha1.VPCRef{Namespace: "team-a", Name: "vpc-a"}, IP: "10.70.0.5"},
	}
	c := fake.NewClientBuilder().WithScheme(svcScheme(t)).
		WithObjects(web, member, nonMember).
		WithStatusSubresource(&sdnv1alpha1.Port{}).
		Build()
	r := &PortMembershipReconciler{Client: c}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: member.Name}}); err != nil {
		t.Fatalf("reconcile member: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: nonMember.Name}}); err != nil {
		t.Fatalf("reconcile non-member: %v", err)
	}

	got := &sdnv1alpha1.Port{}
	_ = r.Get(context.Background(), types.NamespacedName{Name: member.Name}, got)
	if len(got.Status.Groups) != 1 || got.Status.Groups[0] != 7 {
		t.Errorf("member groups = %v, want [7]", got.Status.Groups)
	}
	_ = r.Get(context.Background(), types.NamespacedName{Name: nonMember.Name}, got)
	if len(got.Status.Groups) != 0 {
		t.Errorf("non-member groups = %v, want empty", got.Status.Groups)
	}
}
