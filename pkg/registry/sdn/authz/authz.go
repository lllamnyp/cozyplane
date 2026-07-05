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

// Package authz holds the virtual-verb checks the aggregated apiserver's
// strategies enforce on VPC references. In CRD mode the same gates are
// ValidatingAdmissionPolicies (deploy/authz.yaml); aggregated-API requests
// bypass kube-apiserver admission entirely, so the strategies must enforce
// them here or the verbs mean nothing in apiserver mode.
package authz

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/endpoints/request"

	"github.com/lllamnyp/cozyplane/api/sdn"
)

// CheckVPCVerb verifies that the request's user holds the virtual verb on the
// referenced VPC (an RBAC rule naming the verb on sdn.cozystack.io/vpcs; `*`
// verbs match, so cluster-admins pass). Returns a Forbidden field error on
// denial, nil when allowed.
//
// A nil authorizer skips the check: that is the CRD-mode/test construction,
// where the ValidatingAdmissionPolicy twin owns enforcement. The aggregated
// apiserver always wires the delegated authorizer in.
func CheckVPCVerb(ctx context.Context, auth authorizer.Authorizer, verb, namespace, name string, path *field.Path) *field.Error {
	if auth == nil {
		return nil
	}
	u, ok := request.UserFrom(ctx)
	if !ok {
		return field.Forbidden(path, fmt.Sprintf("no user in request context to check the %q verb", verb))
	}
	decision, reason, err := auth.Authorize(ctx, authorizer.AttributesRecord{
		User:            u,
		Verb:            verb,
		APIGroup:        sdn.GroupName,
		Resource:        "vpcs",
		Namespace:       namespace,
		Name:            name,
		ResourceRequest: true,
	})
	if err != nil {
		return field.Forbidden(path, fmt.Sprintf("checking the %q verb on VPC %s/%s: %v", verb, namespace, name, err))
	}
	if decision != authorizer.DecisionAllow {
		msg := fmt.Sprintf("requires the %q verb on VPC %s/%s (sdn.cozystack.io vpcs)", verb, namespace, name)
		if reason != "" {
			msg += ": " + reason
		}
		return field.Forbidden(path, msg)
	}
	return nil
}
