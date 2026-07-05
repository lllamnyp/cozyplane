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

package vpcbinding

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

type recordingAuthorizer struct {
	allow bool
	calls int
	last  authorizer.Attributes
}

func (a *recordingAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	a.calls++
	a.last = attrs
	if a.allow {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "no export verb", nil
}

func binding(ns, vpcNS, vpcName string) *sdn.VPCBinding {
	return &sdn.VPCBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: ns},
		Spec:       sdn.VPCBindingSpec{VPCRef: sdn.VPCRef{Namespace: vpcNS, Name: vpcName}},
	}
}

// Creating a VPCBinding is gated on the `export` virtual verb on the
// referenced VPC. The ValidatingAdmissionPolicy enforces this in CRD mode
// only — aggregated-API requests bypass kube-apiserver admission, so before
// this strategy check the verb meant nothing in apiserver mode.
func TestBindingCreateRequiresExportVerb(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "consumer-admin"})
	b := binding("team-b", "team-a", "vpc-a")

	denied := &recordingAuthorizer{allow: false}
	if errs := NewStrategy(scheme, denied).Validate(ctx, b); len(errs) == 0 {
		t.Fatal("create without the export verb should be rejected")
	}
	if denied.last.GetVerb() != ExportVerb || denied.last.GetNamespace() != "team-a" || denied.last.GetName() != "vpc-a" {
		t.Errorf("SAR should check verb=export on vpcs team-a/vpc-a, got verb=%s %s/%s",
			denied.last.GetVerb(), denied.last.GetNamespace(), denied.last.GetName())
	}

	allowed := &recordingAuthorizer{allow: true}
	if errs := NewStrategy(scheme, allowed).Validate(ctx, b); len(errs) != 0 {
		t.Fatalf("create with the export verb should pass, got %v", errs)
	}

	// An empty ref namespace defaults to the binding's own namespace.
	own := binding("team-b", "", "vpc-b")
	allowed.last = nil
	if errs := NewStrategy(scheme, allowed).Validate(ctx, own); len(errs) != 0 {
		t.Fatalf("same-namespace binding should pass with the verb, got %v", errs)
	}
	if allowed.last.GetNamespace() != "team-b" {
		t.Errorf("empty ref namespace must default to the binding namespace, SAR saw %q", allowed.last.GetNamespace())
	}
}

// A metadata/finalizer write (the controller's reap finalizer) leaves vpcRef
// unchanged and must not need the export verb — the same refUnchanged guard
// the VAP applies. Retargeting the ref re-checks.
func TestBindingUpdateChecksOnlyOnRefChange(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "cozyplane-controller"})

	old := binding("team-b", "team-a", "vpc-a")
	same := old.DeepCopy()
	same.Finalizers = []string{"sdn.cozystack.io/reap"}

	denied := &recordingAuthorizer{allow: false}
	s := NewStrategy(scheme, denied)
	if errs := s.ValidateUpdate(ctx, same, old); len(errs) != 0 {
		t.Fatalf("finalizer-only update must not require export, got %v", errs)
	}
	if denied.calls != 0 {
		t.Errorf("no SAR should be issued for an unchanged ref, got %d calls", denied.calls)
	}

	retargeted := old.DeepCopy()
	retargeted.Spec.VPCRef.Name = "vpc-other"
	if errs := s.ValidateUpdate(ctx, retargeted, old); len(errs) == 0 {
		t.Fatal("retargeting vpcRef without the export verb should be rejected")
	}
}
