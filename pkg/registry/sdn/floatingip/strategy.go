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

package floatingip

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a FloatingIP.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	fip, ok := obj.(*sdn.FloatingIP)
	if !ok {
		return nil, nil, errors.New("given object is not a FloatingIP")
	}

	return labels.Set(fip.Labels), SelectableFields(fip), nil
}

// MatchFloatingIP is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchFloatingIP(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.FloatingIP) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type floatingIPStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a floatingIPStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) floatingIPStrategy {
	return floatingIPStrategy{typer, names.SimpleNameGenerator}
}

func (floatingIPStrategy) NamespaceScoped() bool {
	return true
}

func (floatingIPStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	fip := obj.(*sdn.FloatingIP)
	fip.Status = sdn.FloatingIPStatus{}
}

func (floatingIPStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newFIP := obj.(*sdn.FloatingIP)
	oldFIP := old.(*sdn.FloatingIP)
	newFIP.Status = oldFIP.Status
}

func (floatingIPStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (floatingIPStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (floatingIPStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (floatingIPStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (floatingIPStrategy) Canonicalize(obj runtime.Object) {
}

func (floatingIPStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (floatingIPStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// floatingIPStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of floatingIPStrategy).
type floatingIPStatusStrategy struct {
	floatingIPStrategy
}

// NewStatusStrategy creates a strategy for the FloatingIP status subresource.
func NewStatusStrategy(strategy floatingIPStrategy) floatingIPStatusStrategy {
	return floatingIPStatusStrategy{strategy}
}

func (floatingIPStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newFIP := obj.(*sdn.FloatingIP)
	oldFIP := old.(*sdn.FloatingIP)
	newFIP.Spec = oldFIP.Spec
}

func (floatingIPStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (floatingIPStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
