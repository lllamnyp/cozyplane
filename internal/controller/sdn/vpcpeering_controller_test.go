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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// Overlapping VPCs may coexist, but never peer: even a mutually-matched pair
// stays Pending with CIDRsDisjoint=False.
func TestVPCPeeringPendingWhenCIDRsOverlap(t *testing.T) {
	a := nsVPCWithVNI("team-a", "vpc-a", 100)
	a.Spec.CIDRs = []string{"10.10.0.0/24"}
	b := nsVPCWithVNI("team-b", "vpc-b", 101)
	b.Spec.CIDRs = []string{"10.10.0.0/16"} // contains vpc-a

	c := peeringClient(t, a, b,
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		peeringHalf("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
	)
	got := reconcilePeering(t, c, "team-a", "to-b")
	if got.Status.Phase != sdnv1alpha1.VPCPeeringPhasePending {
		t.Errorf("phase = %q, want Pending for overlapping CIDRs", got.Status.Phase)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.VPCPeeringConditionDisjoint) {
		t.Error("CIDRsDisjoint should be False for overlapping VPCs")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.VPCPeeringConditionMatched) {
		t.Error("PeerMatched should still be True: the halves do match")
	}
}

func peeringHalf(ns, name, localVPC, peerNS, peerVPC string) *sdnv1alpha1.VPCPeering {
	return &sdnv1alpha1.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: sdnv1alpha1.VPCPeeringSpec{
			VPCRef:  sdnv1alpha1.LocalVPCRef{Name: localVPC},
			PeerRef: sdnv1alpha1.VPCRef{Namespace: peerNS, Name: peerVPC},
		},
	}
}

func nsVPCWithVNI(ns, name string, vni int32) *sdnv1alpha1.VPC {
	return &sdnv1alpha1.VPC{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Status:     sdnv1alpha1.VPCStatus{VNI: vni, Phase: sdnv1alpha1.VPCPhaseReady},
	}
}

func reconcilePeering(t *testing.T, c client.Client, ns, name string) *sdnv1alpha1.VPCPeering {
	t.Helper()
	r := &VPCPeeringReconciler{Client: c}
	key := types.NamespacedName{Namespace: ns, Name: name}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := &sdnv1alpha1.VPCPeering{}
	if err := c.Get(context.Background(), key, got); err != nil {
		t.Fatalf("get: %v", err)
	}
	return got
}

func peeringClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	return fake.NewClientBuilder().
		WithScheme(testScheme(t)).
		WithObjects(objs...).
		WithStatusSubresource(&sdnv1alpha1.VPCPeering{}).
		Build()
}

// A mutually-matched pair of halves whose VPCs both have VNIs is Ready, with
// the peer's VNI surfaced for observability.
func TestVPCPeeringReadyWhenMatched(t *testing.T) {
	c := peeringClient(t,
		nsVPCWithVNI("team-a", "vpc-a", 100),
		nsVPCWithVNI("team-b", "vpc-b", 101),
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		peeringHalf("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
	)

	got := reconcilePeering(t, c, "team-a", "to-b")
	if got.Status.Phase != sdnv1alpha1.VPCPeeringPhaseReady {
		t.Errorf("phase = %q, want Ready (conditions: %+v)", got.Status.Phase, got.Status.Conditions)
	}
	if got.Status.PeerVNI != 101 {
		t.Errorf("peerVNI = %d, want 101", got.Status.PeerVNI)
	}
	for _, cond := range []string{
		sdnv1alpha1.VPCPeeringConditionMatched,
		sdnv1alpha1.VPCPeeringConditionVPCReady,
		sdnv1alpha1.VPCPeeringConditionPeerVPCReady,
	} {
		if !meta.IsStatusConditionTrue(got.Status.Conditions, cond) {
			t.Errorf("condition %s should be True", cond)
		}
	}
}

// A lone half is Pending: it is the visible, declarative "peering request"
// until the reciprocal half appears.
func TestVPCPeeringPendingWithoutReciprocal(t *testing.T) {
	c := peeringClient(t,
		nsVPCWithVNI("team-a", "vpc-a", 100),
		nsVPCWithVNI("team-b", "vpc-b", 101),
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
	)

	got := reconcilePeering(t, c, "team-a", "to-b")
	if got.Status.Phase != sdnv1alpha1.VPCPeeringPhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.VPCPeeringConditionMatched) {
		t.Error("PeerMatched should be False without a reciprocal half")
	}
}

// A reciprocal half that points at a different VPC is not a match.
func TestVPCPeeringPendingWhenReciprocalMismatches(t *testing.T) {
	c := peeringClient(t,
		nsVPCWithVNI("team-a", "vpc-a", 100),
		nsVPCWithVNI("team-b", "vpc-b", 101),
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		// team-b's half references vpc-other, not vpc-a: no consent for vpc-a.
		peeringHalf("team-b", "to-a", "vpc-b", "team-a", "vpc-other"),
	)

	got := reconcilePeering(t, c, "team-a", "to-b")
	if got.Status.Phase != sdnv1alpha1.VPCPeeringPhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
}

// Matched halves stay Pending until both VPCs have VNIs.
func TestVPCPeeringPendingUntilVPCsReady(t *testing.T) {
	c := peeringClient(t,
		nsVPCWithVNI("team-a", "vpc-a", 100),
		nsVPCWithVNI("team-b", "vpc-b", 0), // no VNI yet
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		peeringHalf("team-b", "to-a", "vpc-b", "team-a", "vpc-a"),
	)

	got := reconcilePeering(t, c, "team-a", "to-b")
	if got.Status.Phase != sdnv1alpha1.VPCPeeringPhasePending {
		t.Errorf("phase = %q, want Pending", got.Status.Phase)
	}
	if meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.VPCPeeringConditionPeerVPCReady) {
		t.Error("PeerVPCReady should be False while the peer VPC has no VNI")
	}
	if !meta.IsStatusConditionTrue(got.Status.Conditions, sdnv1alpha1.VPCPeeringConditionMatched) {
		t.Error("PeerMatched should be True: matching is independent of VPC readiness")
	}
}

// Deleting the reciprocal half flips a Ready peering back to Pending
// (status-side revocation; the agents sever the datapath independently).
func TestVPCPeeringRevertsToPendingOnRevocation(t *testing.T) {
	reciprocal := peeringHalf("team-b", "to-a", "vpc-b", "team-a", "vpc-a")
	c := peeringClient(t,
		nsVPCWithVNI("team-a", "vpc-a", 100),
		nsVPCWithVNI("team-b", "vpc-b", 101),
		peeringHalf("team-a", "to-b", "vpc-a", "team-b", "vpc-b"),
		reciprocal,
	)

	if got := reconcilePeering(t, c, "team-a", "to-b"); got.Status.Phase != sdnv1alpha1.VPCPeeringPhaseReady {
		t.Fatalf("precondition: phase = %q, want Ready", got.Status.Phase)
	}
	if err := c.Delete(context.Background(), reciprocal); err != nil {
		t.Fatalf("delete reciprocal: %v", err)
	}
	if got := reconcilePeering(t, c, "team-a", "to-b"); got.Status.Phase != sdnv1alpha1.VPCPeeringPhasePending {
		t.Errorf("phase = %q, want Pending after reciprocal deleted", got.Status.Phase)
	}
}
