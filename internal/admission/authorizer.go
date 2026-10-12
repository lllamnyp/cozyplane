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

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	clientauth "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

// SARAuthorizer checks the AdmissionReview principal, never the webhook's own identity.
type SARAuthorizer struct {
	Client clientauth.SubjectAccessReviewInterface
}

func (a SARAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	if a.Client == nil || attrs.GetUser() == nil || !attrs.IsResourceRequest() {
		return authorizer.DecisionDeny, "", errors.New("missing resource authorization context")
	}
	u := attrs.GetUser()
	extra := map[string]authv1.ExtraValue{}
	for k, v := range u.GetExtra() {
		extra[k] = append(authv1.ExtraValue(nil), v...)
	}
	r, err := a.Client.Create(ctx, &authv1.SubjectAccessReview{Spec: authv1.SubjectAccessReviewSpec{User: u.GetName(), UID: u.GetUID(), Groups: append([]string(nil), u.GetGroups()...), Extra: extra, ResourceAttributes: &authv1.ResourceAttributes{Namespace: attrs.GetNamespace(), Verb: attrs.GetVerb(), Group: attrs.GetAPIGroup(), Version: attrs.GetAPIVersion(), Resource: attrs.GetResource(), Subresource: attrs.GetSubresource(), Name: attrs.GetName()}}}, metav1.CreateOptions{})
	if err != nil {
		return authorizer.DecisionDeny, "", err
	}
	if r.Status.EvaluationError != "" {
		return authorizer.DecisionDeny, "", errors.New("authorization evaluation failed")
	}
	if r.Status.Allowed && !r.Status.Denied {
		return authorizer.DecisionAllow, r.Status.Reason, nil
	}
	return authorizer.DecisionDeny, r.Status.Reason, nil
}
