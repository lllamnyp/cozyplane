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
	"errors"
	"reflect"
	"testing"

	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

func TestSARPrincipalAndFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status authv1.SubjectAccessReviewStatus
		err    error
		want   authorizer.Decision
	}{
		{"allow", authv1.SubjectAccessReviewStatus{Allowed: true}, nil, authorizer.DecisionAllow},
		{"deny", authv1.SubjectAccessReviewStatus{Denied: true}, nil, authorizer.DecisionDeny},
		{"no-decision", authv1.SubjectAccessReviewStatus{}, nil, authorizer.DecisionDeny},
		{"contradictory", authv1.SubjectAccessReviewStatus{Allowed: true, Denied: true}, nil, authorizer.DecisionDeny},
		{"evaluation-error", authv1.SubjectAccessReviewStatus{Allowed: true, EvaluationError: "test-error"}, nil, authorizer.DecisionDeny},
		{"transport-error", authv1.SubjectAccessReviewStatus{}, errors.New("test-error"), authorizer.DecisionDeny},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := fake.NewClientset()
			principal := &user.DefaultInfo{Name: "test-user", UID: "test-uid", Groups: []string{"test-group"}, Extra: map[string][]string{"test-extra": {"test-value"}}}
			attrs := authorizer.AttributesRecord{User: principal, ResourceRequest: true, Verb: "export", APIGroup: "sdn.cozystack.io", APIVersion: "v1alpha1", Namespace: "test-namespace", Resource: "vpcs", Subresource: "status", Name: "test-vpc"}
			client.PrependReactor("create", "subjectaccessreviews", func(action clienttesting.Action) (bool, runtime.Object, error) {
				spec := action.(clienttesting.CreateAction).GetObject().(*authv1.SubjectAccessReview).Spec
				if spec.User != principal.Name || spec.UID != principal.UID || !reflect.DeepEqual(spec.Groups, principal.Groups) || !reflect.DeepEqual([]string(spec.Extra["test-extra"]), principal.Extra["test-extra"]) {
					t.Fatal("caller identity lost")
				}
				if !reflect.DeepEqual(spec.ResourceAttributes, &authv1.ResourceAttributes{Verb: "export", Group: "sdn.cozystack.io", Version: "v1alpha1", Namespace: "test-namespace", Resource: "vpcs", Subresource: "status", Name: "test-vpc"}) {
					t.Fatal("authorization target changed")
				}
				spec.Groups[0] = "changed-copy"
				spec.Extra["test-extra"][0] = "changed-copy"
				return true, &authv1.SubjectAccessReview{Status: tc.status}, tc.err
			})
			decision, _, _ := (SARAuthorizer{Client: client.AuthorizationV1().SubjectAccessReviews()}).Authorize(context.Background(), attrs)
			if decision != tc.want {
				t.Fatalf("decision=%v want=%v", decision, tc.want)
			}
			if principal.Groups[0] != "test-group" || principal.Extra["test-extra"][0] != "test-value" {
				t.Fatal("SAR mutated caller identity")
			}
		})
	}
	if d, _, e := (SARAuthorizer{}).Authorize(context.Background(), authorizer.AttributesRecord{}); d != authorizer.DecisionDeny || e == nil {
		t.Fatal("missing context did not fail closed")
	}
}
