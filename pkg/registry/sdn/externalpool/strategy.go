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

package externalpool

import (
	"context"
	"errors"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not an ExternalPool.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	pool, ok := obj.(*sdn.ExternalPool)
	if !ok {
		return nil, nil, errors.New("given object is not an ExternalPool")
	}

	return labels.Set(pool.Labels), SelectableFields(pool), nil
}

// MatchExternalPool is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchExternalPool(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.ExternalPool) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, false)
}

type externalPoolStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns an externalPoolStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) externalPoolStrategy {
	return externalPoolStrategy{typer, names.SimpleNameGenerator}
}

func (externalPoolStrategy) NamespaceScoped() bool {
	return false
}

func (externalPoolStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	pool := obj.(*sdn.ExternalPool)
	pool.Status = sdn.ExternalPoolStatus{}
}

func (externalPoolStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newPool := obj.(*sdn.ExternalPool)
	oldPool := old.(*sdn.ExternalPool)
	newPool.Status = oldPool.Status
}

func (externalPoolStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (externalPoolStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (externalPoolStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (externalPoolStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (externalPoolStrategy) Canonicalize(obj runtime.Object) {
}

func (externalPoolStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (externalPoolStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// externalPoolStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of externalPoolStrategy).
type externalPoolStatusStrategy struct {
	externalPoolStrategy
}

// NewStatusStrategy creates a strategy for the ExternalPool status subresource.
func NewStatusStrategy(strategy externalPoolStrategy) externalPoolStatusStrategy {
	return externalPoolStatusStrategy{strategy}
}

func (externalPoolStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPool := obj.(*sdn.ExternalPool)
	oldPool := old.(*sdn.ExternalPool)
	newPool.Spec = oldPool.Spec
}

func (externalPoolStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (externalPoolStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
