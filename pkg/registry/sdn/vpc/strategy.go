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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPC.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	vpc, ok := obj.(*sdn.VPC)
	if !ok {
		return nil, nil, errors.New("given object is not a VPC")
	}

	return labels.Set(vpc.Labels), SelectableFields(vpc), nil
}

// MatchVPC is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPC(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.VPC) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpcStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpcStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) vpcStrategy {
	return vpcStrategy{typer, names.SimpleNameGenerator}
}

func (vpcStrategy) NamespaceScoped() bool {
	return true
}

func (vpcStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
}

func (vpcStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
}

func (vpcStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpcStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpcStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpcStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpcStrategy) Canonicalize(obj runtime.Object) {
}

func (vpcStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
