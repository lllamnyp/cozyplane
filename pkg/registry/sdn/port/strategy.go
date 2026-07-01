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

package port

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a Port.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	port, ok := obj.(*sdn.Port)
	if !ok {
		return nil, nil, errors.New("given object is not a Port")
	}

	return labels.Set(port.Labels), SelectableFields(port), nil
}

// MatchPort is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchPort(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. Ports are
// cluster-scoped, so the object-meta field set is built without a namespace.
func SelectableFields(obj *sdn.Port) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, false)
}

type portStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a portStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) portStrategy {
	return portStrategy{typer, names.SimpleNameGenerator}
}

func (portStrategy) NamespaceScoped() bool {
	return false
}

func (portStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
}

func (portStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
}

func (portStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (portStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (portStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (portStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (portStrategy) Canonicalize(obj runtime.Object) {
}

func (portStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (portStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
