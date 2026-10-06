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

package vpc

import (
	"context"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry"
	metainternalversion "k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
)

// NewREST returns RESTStorage objects for VPCs and their /status subresource.
func NewREST(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter, auth authorizer.Authorizer) (*BoundaryREST, *StatusREST, error) {
	strategy := NewStrategy(scheme, auth)

	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &sdn.VPC{} },
		NewListFunc:               func() runtime.Object { return &sdn.VPCList{} },
		PredicateFunc:             MatchVPC,
		DefaultQualifiedResource:  sdn.Resource("vpcs"),
		SingularQualifiedResource: sdn.Resource("vpc"),

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,

		TableConvertor: rest.NewDefaultTableConvertor(sdn.Resource("vpcs")),
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, err
	}

	// The /status subresource shares the store but only updates status.
	statusStore := *store
	statusStore.UpdateStrategy = NewStatusStrategy(strategy)

	return &BoundaryREST{REST: &registry.REST{Store: store}, auth: auth}, &StatusREST{store: &statusStore}, nil
}

// BoundaryREST checks the actual object in the store's delete validation, so a
// concurrent policy update cannot race an earlier read-only authorization check.
type BoundaryREST struct {
	*registry.REST
	auth authorizer.Authorizer
}

func (r *BoundaryREST) deletionCheck(check rest.ValidateObjectFunc) rest.ValidateObjectFunc {
	return func(ctx context.Context, obj runtime.Object) error {
		v := obj.(*sdn.VPC)
		if v.Spec.Boundary != nil {
			if err := authz.CheckVPCVerb(ctx, r.auth, "manage-boundary", v.Namespace, v.Name, field.NewPath("spec", "boundary")); err != nil {
				return apierrors.NewForbidden(sdn.Resource("vpcs"), v.Name, err)
			}
		}
		if check != nil {
			return check(ctx, obj)
		}
		return nil
	}
}

func (r *BoundaryREST) Delete(ctx context.Context, name string, check rest.ValidateObjectFunc, options *metav1.DeleteOptions) (runtime.Object, bool, error) {
	return r.Store.Delete(ctx, name, r.deletionCheck(check), options)
}

func (r *BoundaryREST) DeleteCollection(ctx context.Context, check rest.ValidateObjectFunc, options *metav1.DeleteOptions, listOptions *metainternalversion.ListOptions) (runtime.Object, error) {
	return r.Store.DeleteCollection(ctx, r.deletionCheck(check), options, listOptions)
}

// StatusREST implements the REST endpoint for changing the status of a VPC.
type StatusREST struct {
	store *genericregistry.Store
}

// New returns an empty VPC.
func (r *StatusREST) New() runtime.Object {
	return &sdn.VPC{}
}

// Destroy cleans up resources. The store is shared with the main REST, which
// owns teardown, so this is a no-op.
func (r *StatusREST) Destroy() {}

// Get retrieves the object from storage.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object; create-on-update is never allowed.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}

// ConvertToTable converts the object to a table for kubectl display.
func (r *StatusREST) ConvertToTable(ctx context.Context, object runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.store.ConvertToTable(ctx, object, tableOptions)
}
