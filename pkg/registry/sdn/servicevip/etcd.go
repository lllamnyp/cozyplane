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

package servicevip

import (
	"context"
	"fmt"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/claim"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
)

// NewREST returns RESTStorage objects for ServiceVIPs and their /status
// subresource. The name (sv<vni>.<ip>) is the atomic address claim among
// ServiceVIPs; twin is the late-bound handle to the Port store, and a create
// is 409-rejected when a Port holds the same {VNI, IP} claim (the allocator
// treats the 409 like AlreadyExists — address taken, walk on).
func NewREST(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter, twin *claim.Twin) (*registry.REST, *StatusREST, error) {
	strategy := NewStrategy(scheme)

	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &sdn.ServiceVIP{} },
		NewListFunc:               func() runtime.Object { return &sdn.ServiceVIPList{} },
		PredicateFunc:             MatchServiceVIP,
		DefaultQualifiedResource:  sdn.Resource("servicevips"),
		SingularQualifiedResource: sdn.Resource("servicevip"),

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,

		// The cross-kind half of the claim (Validate already pinned the name
		// to {VNI, spec.ip}): fail the create if a Port holds the twin name.
		// One live Get; runs after validation, before the etcd write.
		BeginCreate: func(ctx context.Context, obj runtime.Object, _ *metav1.CreateOptions) (genericregistry.FinishFunc, error) {
			svip := obj.(*sdn.ServiceVIP)
			vni, _, ok := sdn.ParseClaim(sdn.ClaimPrefixServiceVIP, svip.Name)
			if !ok { // unreachable: Validate rejected it already
				return claim.FinishNothing, nil
			}
			twinName := sdn.PortName(vni, svip.Spec.IP)
			taken, err := twin.Exists(ctx, twinName)
			if err != nil {
				return nil, err
			}
			if taken {
				return nil, apierrors.NewConflict(sdn.Resource("servicevips"), svip.Name,
					fmt.Errorf("VPC IP %s (VNI %d) is already held by Port %s", svip.Spec.IP, vni, twinName))
			}
			return claim.FinishNothing, nil
		},

		TableConvertor: rest.NewDefaultTableConvertor(sdn.Resource("servicevips")),
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, err
	}

	// The /status subresource shares the store but only updates status.
	statusStore := *store
	statusStore.UpdateStrategy = NewStatusStrategy(strategy)

	return &registry.REST{Store: store}, &StatusREST{store: &statusStore}, nil
}

// StatusREST implements the REST endpoint for changing the status of a ServiceVIP.
type StatusREST struct {
	store *genericregistry.Store
}

// New returns an empty ServiceVIP.
func (r *StatusREST) New() runtime.Object {
	return &sdn.ServiceVIP{}
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
