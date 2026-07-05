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
	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
)

// NewREST returns a RESTStorage object that will work against VPCBindings.
func NewREST(scheme *runtime.Scheme, optsGetter generic.RESTOptionsGetter, auth authorizer.Authorizer) (*registry.REST, error) {
	strategy := NewStrategy(scheme, auth)

	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &sdn.VPCBinding{} },
		NewListFunc:               func() runtime.Object { return &sdn.VPCBindingList{} },
		PredicateFunc:             MatchVPCBinding,
		DefaultQualifiedResource:  sdn.Resource("vpcbindings"),
		SingularQualifiedResource: sdn.Resource("vpcbinding"),

		CreateStrategy: strategy,
		UpdateStrategy: strategy,
		DeleteStrategy: strategy,

		TableConvertor: rest.NewDefaultTableConvertor(sdn.Resource("vpcbindings")),
	}

	options := &generic.StoreOptions{RESTOptions: optsGetter, AttrFunc: GetAttrs}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}

	return &registry.REST{Store: store}, nil
}
