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

package admission

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/vpcpeering"
	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

type recordingAuthorizer struct {
	seen     authorizer.Attributes
	decision authorizer.Decision
	err      error
}

func (a *recordingAuthorizer) Authorize(_ context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	a.seen = attrs
	return a.decision, "", a.err
}
func reviewRequest(t *testing.T, resource, kind string, operation admissionv1.Operation, obj, old any) *admissionv1.AdmissionRequest {
	t.Helper()
	raw := func(v any) runtime.RawExtension {
		if v == nil {
			return runtime.RawExtension{}
		}
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return runtime.RawExtension{Raw: b}
	}
	return &admissionv1.AdmissionRequest{UID: "test-request", Resource: metav1.GroupVersionResource{Group: sdnv1.GroupName, Version: "v1alpha1", Resource: resource}, Kind: metav1.GroupVersionKind{Group: sdnv1.GroupName, Version: "v1alpha1", Kind: kind}, Operation: operation, Namespace: "test-tenant", Name: "test-object", UserInfo: authv1.UserInfo{Username: "test-principal", UID: "test-uid", Groups: []string{"test-group"}, Extra: map[string]authv1.ExtraValue{"test-extra": {"test-value"}}}, Object: raw(obj), OldObject: raw(old)}
}
func TestWebhookAuthorizesActualCallerAndFailsClosed(t *testing.T) {
	obj := &sdnv1.VPCBinding{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "VPCBinding"}, ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-tenant"}, Spec: sdnv1.VPCBindingSpec{VPCRef: sdnv1.VPCRef{Name: "test-vpc"}}}
	a := &recordingAuthorizer{decision: authorizer.DecisionDeny}
	h, e := NewHandler(a, nil)
	if e != nil {
		t.Fatal(e)
	}
	r := reviewRequest(t, "vpcbindings", "VPCBinding", admissionv1.Create, obj, nil)
	resp := h.Validate(context.Background(), r)
	if resp.Allowed {
		t.Fatal("export denial accepted")
	}
	if a.seen == nil || a.seen.GetUser().GetName() != "test-principal" || a.seen.GetNamespace() != "test-tenant" || a.seen.GetVerb() != "export" || a.seen.GetName() != "test-vpc" || a.seen.GetUser().GetExtra()["test-extra"][0] != "test-value" {
		t.Fatalf("wrong caller or resource: %v", a.seen)
	}
	a.decision = authorizer.DecisionAllow
	if got := h.Validate(context.Background(), r); !got.Allowed {
		t.Fatalf("authorized binding rejected: %v", got.Result)
	}
	if _, e := NewHandler(nil, nil); e == nil {
		t.Fatal("nil authorizer accepted")
	}
}
func TestWebhookRejectsPortOverflowAndInvalidStatus(t *testing.T) {
	h, e := NewHandler(&recordingAuthorizer{decision: authorizer.DecisionAllow}, nil)
	if e != nil {
		t.Fatal(e)
	}
	obj := &sdnv1.ServiceVIP{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "ServiceVIP"}, ObjectMeta: metav1.ObjectMeta{Name: "sv100.10-0-0-2"}, Spec: sdnv1.ServiceVIPSpec{IP: "10.0.0.2", Ports: []sdnv1.VIPPort{{Protocol: "TCP", Port: 65536}}}}
	r := reviewRequest(t, "servicevips", "ServiceVIP", admissionv1.Create, obj, nil)
	r.Namespace = ""
	r.Name = obj.Name
	resp := h.Validate(context.Background(), r)
	if resp.Allowed || resp.Result == nil || resp.Result.Reason != metav1.StatusReasonInvalid {
		t.Fatalf("overflow accepted: %v", resp)
	}
	port := &sdnv1.Port{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "Port"}, ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2"}, Spec: sdnv1.PortSpec{IP: "10.0.0.2"}}
	old := port.DeepCopy()
	port.Status.Groups = []int32{63}
	r = reviewRequest(t, "ports", "Port", admissionv1.Update, port, old)
	r.Namespace = ""
	r.Name = port.Name
	r.SubResource = "status"
	if got := h.Validate(context.Background(), r); got.Allowed {
		t.Fatal("World membership accepted")
	}
}
func TestWebhookTypedConflictAndLookupFailure(t *testing.T) {
	obj := &sdnv1.Port{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "Port"}, ObjectMeta: metav1.ObjectMeta{Name: "v100.10-0-0-2"}, Spec: sdnv1.PortSpec{IP: "10.0.0.2"}}
	r := reviewRequest(t, "ports", "Port", admissionv1.Create, obj, nil)
	r.Namespace = ""
	r.Name = obj.Name
	h, e := NewHandler(&recordingAuthorizer{decision: authorizer.DecisionAllow}, func(_ context.Context, resource, name string) (bool, error) {
		if resource != "servicevips" || name != "sv100.10-0-0-2" {
			t.Fatalf("wrong twin %s %s", resource, name)
		}
		return true, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	resp := h.Validate(context.Background(), r)
	if resp.Allowed || !apierrors.IsConflict(&apierrors.StatusError{ErrStatus: *resp.Result}) {
		t.Fatalf("not typed Conflict: %v", resp)
	}
	h.twin = func(context.Context, string, string) (bool, error) { return false, errors.New("test lookup failure") }
	if got := h.Validate(context.Background(), r); got.Allowed || got.Result == nil || got.Result.Reason != metav1.StatusReasonInternalError {
		t.Fatalf("lookup failed open: %v", got)
	}
}
func TestWebhookHTTPRejectsMalformedAndOversizedReviews(t *testing.T) {
	h, e := NewHandler(&recordingAuthorizer{decision: authorizer.DecisionAllow}, nil)
	if e != nil {
		t.Fatal(e)
	}
	validPrefix := `{"apiVersion":"admission.k8s.io/v1","kind":"AdmissionReview","request":{"uid":"test"},"padding":"`
	for _, body := range []string{"{}", validPrefix + strings.Repeat("x", MaxReviewBytes) + `"}`, validPrefix + `"} {}`, validPrefix + `"} garbage`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/validate", strings.NewReader(body)))
		if w.Code < 400 {
			t.Fatalf("bad review accepted: %d", w.Code)
		}
	}
}

func TestWebhookRejectsCancelledContextAndOldIdentityMismatch(t *testing.T) {
	h, e := NewHandler(&recordingAuthorizer{decision: authorizer.DecisionAllow}, nil)
	if e != nil {
		t.Fatal(e)
	}
	obj := &sdnv1.VPC{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "VPC"}, ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-tenant"}}
	r := reviewRequest(t, "vpcs", "VPC", admissionv1.Create, obj, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := h.Validate(ctx, r); got.Allowed {
		t.Fatal("cancelled request allowed")
	}
	obj.Name = "different-object"
	r = reviewRequest(t, "vpcs", "VPC", admissionv1.Delete, nil, obj)
	if got := h.Validate(context.Background(), r); got.Allowed {
		t.Fatal("mismatched deletion allowed")
	}
}

func TestWebhookBoundsConcurrentBodyReads(t *testing.T) {
	h, e := NewHandler(&recordingAuthorizer{decision: authorizer.DecisionAllow}, nil)
	if e != nil {
		t.Fatal(e)
	}
	h.slots <- struct{}{}
	h.slots <- struct{}{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/validate", strings.NewReader("{}")))
	if w.Code != 503 {
		t.Fatalf("overload accepted: %d", w.Code)
	}
	<-h.slots
	<-h.slots
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/validate", strings.NewReader("{}")))
	if w.Code != 400 || len(h.slots) != 0 {
		t.Fatalf("capacity not released: %d %d", w.Code, len(h.slots))
	}
}

func TestWebhookCollectionDeletePreservesScopeAndManagedAuthorization(t *testing.T) {
	a := &recordingAuthorizer{decision: authorizer.DecisionDeny}
	h, err := NewHandler(a, nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := &sdnv1.SecurityGroup{TypeMeta: metav1.TypeMeta{APIVersion: sdnv1.SchemeGroupVersion.String(), Kind: "SecurityGroup"}, ObjectMeta: metav1.ObjectMeta{Name: "test-object", Namespace: "test-tenant"}}
	r := reviewRequest(t, "securitygroups", "SecurityGroup", admissionv1.Delete, nil, obj)
	r.Name = ""
	if got := h.Validate(context.Background(), r); !got.Allowed {
		t.Fatalf("ordinary collection deletion rejected: %v", got.Result)
	}
	obj.Labels = map[string]string{vpcpeering.PortalManagedByLabel: vpcpeering.PortalManagedBy}
	r = reviewRequest(t, "securitygroups", "SecurityGroup", admissionv1.Delete, nil, obj)
	r.Name = ""
	got := h.Validate(context.Background(), r)
	if got.Allowed || got.Result == nil || got.Result.Reason != metav1.StatusReasonForbidden || a.seen == nil || a.seen.GetName() != obj.Name || a.seen.GetVerb() != "manage-boundary" {
		t.Fatalf("collection deletion lost managed authorization: %v", got.Result)
	}
	a.decision = authorizer.DecisionAllow
	if got := h.Validate(context.Background(), r); !got.Allowed {
		t.Fatalf("authorized managed collection deletion rejected: %v", got.Result)
	}
	r.Namespace = "different-tenant"
	if got := h.Validate(context.Background(), r); got.Allowed {
		t.Fatal("collection delete crossed namespace")
	}
	obj.Name = ""
	r = reviewRequest(t, "securitygroups", "SecurityGroup", admissionv1.Delete, nil, obj)
	r.Name = ""
	if got := h.Validate(context.Background(), r); got.Allowed {
		t.Fatal("collection delete accepted nameless old object")
	}
}
