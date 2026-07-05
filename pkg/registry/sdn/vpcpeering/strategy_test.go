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

package vpcpeering

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
)

func newStrategyForTest(t *testing.T) vpcPeeringStrategy {
	t.Helper()
	scheme := runtime.NewScheme()
	install.Install(scheme)
	return NewStrategy(scheme, nil)
}

func peering(ns, localVPC, peerNS, peerVPC string) *sdn.VPCPeering {
	return &sdn.VPCPeering{
		ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: ns},
		Spec: sdn.VPCPeeringSpec{
			VPCRef:  sdn.LocalVPCRef{Name: localVPC},
			PeerRef: sdn.VPCRef{Namespace: peerNS, Name: peerVPC},
		},
	}
}

func TestValidateRejectsSelfPeering(t *testing.T) {
	s := newStrategyForTest(t)
	if errs := s.Validate(context.Background(), peering("team-a", "vpc-a", "team-a", "vpc-a")); len(errs) == 0 {
		t.Error("self-peering should be rejected")
	}
	// Same name in another namespace is a different VPC — allowed.
	if errs := s.Validate(context.Background(), peering("team-a", "vpc-a", "team-b", "vpc-a")); len(errs) != 0 {
		t.Errorf("same-name cross-namespace peering should be valid, got %v", errs)
	}
}

func TestValidateRequiresRefs(t *testing.T) {
	s := newStrategyForTest(t)
	cases := []struct {
		name string
		obj  *sdn.VPCPeering
	}{
		{"missing local VPC name", peering("team-a", "", "team-b", "vpc-b")},
		{"missing peer namespace", peering("team-a", "vpc-a", "", "vpc-b")},
		{"missing peer name", peering("team-a", "vpc-a", "team-b", "")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if errs := s.Validate(context.Background(), tc.obj); len(errs) == 0 {
				t.Error("expected a validation error")
			}
		})
	}
}

// The refs pin the identity the reciprocal half consented to: no re-pointing a
// live grant in place.
func TestValidateUpdateRejectsSpecChange(t *testing.T) {
	s := newStrategyForTest(t)
	old := peering("team-a", "vpc-a", "team-b", "vpc-b")

	repointed := old.DeepCopy()
	repointed.Spec.PeerRef.Name = "vpc-c"
	if errs := s.ValidateUpdate(context.Background(), repointed, old); len(errs) == 0 {
		t.Error("changing spec.peerRef should be rejected")
	}

	relabeled := old.DeepCopy()
	relabeled.Labels = map[string]string{"team": "a"}
	if errs := s.ValidateUpdate(context.Background(), relabeled, old); len(errs) != 0 {
		t.Errorf("metadata-only update should be allowed, got %v", errs)
	}
}

// Status is owned by the controller through /status: a create never sets it and
// a spec-path update never changes it.
func TestStatusIsProtected(t *testing.T) {
	s := newStrategyForTest(t)

	created := peering("team-a", "vpc-a", "team-b", "vpc-b")
	created.Status.Phase = sdn.VPCPeeringPhaseReady
	s.PrepareForCreate(context.Background(), created)
	if created.Status.Phase != "" {
		t.Errorf("create should clear status, got phase %q", created.Status.Phase)
	}

	old := peering("team-a", "vpc-a", "team-b", "vpc-b")
	old.Status.Phase = sdn.VPCPeeringPhaseReady
	updated := old.DeepCopy()
	updated.Status.Phase = sdn.VPCPeeringPhasePending
	s.PrepareForUpdate(context.Background(), updated, old)
	if updated.Status.Phase != sdn.VPCPeeringPhaseReady {
		t.Errorf("spec-path update should preserve status, got phase %q", updated.Status.Phase)
	}

	// The mirror image: /status updates preserve spec.
	ss := NewStatusStrategy(s)
	statusUpdate := old.DeepCopy()
	statusUpdate.Spec.PeerRef.Name = "vpc-c"
	ss.PrepareForUpdate(context.Background(), statusUpdate, old)
	if statusUpdate.Spec.PeerRef.Name != "vpc-b" {
		t.Errorf("status update should preserve spec, got peerRef.name %q", statusUpdate.Spec.PeerRef.Name)
	}
}

// recordingAuthorizer allows or denies every check and records the last
// attributes it saw.
type recordingAuthorizer struct {
	allow bool
	last  authorizer.Attributes
}

func (a *recordingAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	a.last = attrs
	if a.allow {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "no peer verb", nil
}

// Creating a peering half is gated on the `peer` virtual verb on the LOCAL
// VPC (issue #1): the aggregated apiserver bypasses kube-apiserver admission,
// so the strategy is the enforcement point in apiserver mode.
func TestPeeringCreateRequiresPeerVerb(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "tenant-a-admin"})
	p := peering("team-a", "vpc-a", "team-b", "vpc-b")

	denied := &recordingAuthorizer{allow: false}
	if errs := NewStrategy(scheme, denied).Validate(ctx, p); len(errs) == 0 {
		t.Fatal("create without the peer verb should be rejected")
	}
	if denied.last.GetVerb() != PeerVerb || denied.last.GetResource() != "vpcs" ||
		denied.last.GetNamespace() != "team-a" || denied.last.GetName() != "vpc-a" {
		t.Errorf("SAR should check verb=peer on vpcs team-a/vpc-a (the LOCAL vpc), got verb=%s %s %s/%s",
			denied.last.GetVerb(), denied.last.GetResource(), denied.last.GetNamespace(), denied.last.GetName())
	}

	allowed := &recordingAuthorizer{allow: true}
	if errs := NewStrategy(scheme, allowed).Validate(ctx, p); len(errs) != 0 {
		t.Fatalf("create with the peer verb should pass, got %v", errs)
	}

	// No user in context cannot be authorized.
	if errs := NewStrategy(scheme, allowed).Validate(context.Background(), p); len(errs) == 0 {
		t.Fatal("a request without a user must not pass the peer check")
	}

	// nil authorizer = CRD mode; the ValidatingAdmissionPolicy twin enforces.
	if errs := NewStrategy(scheme, nil).Validate(ctx, p); len(errs) != 0 {
		t.Fatalf("nil authorizer must skip the check, got %v", errs)
	}
}
