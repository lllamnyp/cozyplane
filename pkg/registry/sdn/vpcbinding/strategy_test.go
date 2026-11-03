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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/api/sdn/install"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

type recordingAuthorizer struct {
	allow bool
	calls int
	last  authorizer.Attributes
}

type consumerVPCOnlyAuthorizer struct{}

func TestBindingForwardingPrefixInputBudget(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	strategy := NewStrategy(scheme, &recordingAuthorizer{allow: true})
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "network-owner"})
	old := binding("consumer", "owner", "net")
	for _, size := range []int{sdnv1alpha1.MaxForwardingPrefixes, sdnv1alpha1.MaxForwardingPrefixes + 1} {
		updated := old.DeepCopy()
		updated.Spec.AllowForwarding = true
		updated.Spec.ForwardingCIDRs = make([]string, size)
		for i := range updated.Spec.ForwardingCIDRs {
			updated.Spec.ForwardingCIDRs[i] = "10.0.0.0/24"
		}
		for _, errs := range []int{len(strategy.Validate(ctx, updated)), len(strategy.ValidateUpdate(ctx, updated, old))} {
			if (errs != 0) != (size > sdnv1alpha1.MaxForwardingPrefixes) {
				t.Fatalf("size=%d errors=%d", size, errs)
			}
		}
	}
}

func TestBindingRejectsMalformedForwardingWithSmallErrors(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	strategy := NewStrategy(scheme, &recordingAuthorizer{allow: true})
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "network-owner"})
	old := binding("consumer", "owner", "net")
	for _, prefix := range []string{"not-a-cidr", strings.Repeat("x", 1<<20)} {
		updated := old.DeepCopy()
		updated.Spec.AllowForwarding = true
		updated.Spec.ForwardingCIDRs = []string{prefix}
		for _, errs := range []string{strategy.Validate(ctx, updated).ToAggregate().Error(), strategy.ValidateUpdate(ctx, updated, old).ToAggregate().Error()} {
			if len(errs) == 0 || len(errs) > 256 {
				t.Fatal("admission error copied untrusted prefix", len(errs))
			}
		}
	}
}

func TestMalformedLegacyBindingCanStillBeRevokedByOwner(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "network-owner"})
	for _, mode := range []string{"oversized", "invalid CIDR"} {
		old := binding("consumer", "owner", "net")
		old.Finalizers = []string{"sdn.cozystack.io/reap-ports"}
		old.Spec.AllowForwarding = true
		old.Spec.ForwardingCIDRs = []string{"not-a-cidr"}
		if mode == "oversized" {
			old.Spec.ForwardingCIDRs = make([]string, sdnv1alpha1.MaxForwardingPrefixes+1)
		}
		for _, change := range []string{"disable forwarding", "remove reap finalizer"} {
			updated := old.DeepCopy()
			if change == "disable forwarding" {
				updated.Spec.AllowForwarding = false
			} else {
				updated.Finalizers = nil
			}
			for _, allow := range []bool{true, false} {
				auth := &recordingAuthorizer{allow: allow}
				errs := NewStrategy(scheme, auth).ValidateUpdate(ctx, updated, old)
				if (len(errs) == 0) != allow || auth.calls != 1 {
					t.Fatalf("legacy=%s change=%s allow=%v calls=%d errors=%v", mode, change, allow, auth.calls, errs)
				}
			}
		}
	}
}

func (consumerVPCOnlyAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	if attrs.GetNamespace() == "consumer" && attrs.GetName() == "owned" {
		return authorizer.DecisionAllow, "", nil
	}
	return authorizer.DecisionDeny, "no authority on original VPC", nil
}

func TestBindingCannotRetargetRevocationBarrier(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(t.Context(), &user.DefaultInfo{Name: "consumer-admin"})
	old := binding("consumer", "owner", "shared")
	old.Finalizers = []string{"sdn.cozystack.io/reap-ports"}
	for _, dropFinalizer := range []bool{false, true} {
		updated := old.DeepCopy()
		updated.Spec.VPCRef = sdn.VPCRef{Namespace: "consumer", Name: "owned"}
		if dropFinalizer {
			updated.Finalizers = nil
		}
		if errs := NewStrategy(scheme, consumerVPCOnlyAuthorizer{}).ValidateUpdate(ctx, updated, old); len(errs) == 0 {
			t.Fatalf("retargeting original revocation barrier admitted; remove finalizer=%v", dropFinalizer)
		}
		if errs := NewStrategy(scheme, &recordingAuthorizer{allow: true}).ValidateUpdate(ctx, updated, old); len(errs) == 0 {
			t.Fatal("authorized retarget loses the original Ports' durable reaping target")
		}
	}
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
// the VAP applies. Retargeting the ref is rejected to preserve the reap target.
func TestBindingMetadataUpdatesDoNotRequireExport(t *testing.T) {
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

func TestBindingCreatedWithReapFinalizer(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	b := binding("consumer", "owner", "vpc")
	s := NewStrategy(scheme, nil)
	s.PrepareForCreate(t.Context(), b)
	s.PrepareForCreate(t.Context(), b)
	if len(b.Finalizers) != 1 || b.Finalizers[0] != "sdn.cozystack.io/reap-ports" {
		t.Fatalf("grant has no durable revocation finalizer: %v", b.Finalizers)
	}
}

func TestBindingGrantChangesRequireExport(t *testing.T) {
	scheme := runtime.NewScheme()
	install.Install(scheme)
	ctx := request.WithUser(context.Background(), &user.DefaultInfo{Name: "consumer-admin"})
	for _, change := range []struct {
		name   string
		mutate func(*sdn.VPCBinding)
	}{
		{"enable forwarding", func(b *sdn.VPCBinding) { b.Spec.AllowForwarding = true }},
		{"remove CIDR restriction", func(b *sdn.VPCBinding) { b.Spec.ForwardingCIDRs = nil }},
		{"widen CIDR restriction", func(b *sdn.VPCBinding) { b.Spec.ForwardingCIDRs = []string{"0.0.0.0/0"} }},
		{"remove reap finalizer", func(b *sdn.VPCBinding) { b.Finalizers = nil }},
	} {
		t.Run(change.name, func(t *testing.T) {
			old := binding("consumer", "owner", "shared")
			old.Spec.ForwardingCIDRs = []string{"10.50.0.0/16"}
			old.Finalizers = []string{"sdn.cozystack.io/reap-ports"}
			updated := old.DeepCopy()
			change.mutate(updated)
			denied := &recordingAuthorizer{}
			if errs := NewStrategy(scheme, denied).ValidateUpdate(ctx, updated, old); len(errs) == 0 {
				t.Fatal("consumer without export was allowed to change the grant")
			}
			if denied.calls != 1 || denied.last.GetNamespace() != "owner" {
				t.Fatal("export must be checked against the VPC owner")
			}
			if errs := NewStrategy(scheme, &recordingAuthorizer{allow: true}).ValidateUpdate(ctx, updated, old); len(errs) != 0 {
				t.Fatalf("owner's authorized change rejected: %v", errs)
			}
		})
	}
}
