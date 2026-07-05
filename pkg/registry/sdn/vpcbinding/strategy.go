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
	"context"
	"errors"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPCBinding.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	binding, ok := obj.(*sdn.VPCBinding)
	if !ok {
		return nil, nil, errors.New("given object is not a VPCBinding")
	}

	return labels.Set(binding.Labels), SelectableFields(binding), nil
}

// MatchVPCBinding is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPCBinding(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. VPCBindings
// are namespaced.
func SelectableFields(obj *sdn.VPCBinding) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpcBindingStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
	authz authorizer.Authorizer
}

// NewStrategy creates and returns a vpcBindingStrategy instance.
// NewStrategy builds the strategy. auth is the delegated authorizer for the
// export-verb check; nil skips it (CRD mode, where the VAP enforces).
func NewStrategy(typer runtime.ObjectTyper, auth authorizer.Authorizer) vpcBindingStrategy {
	return vpcBindingStrategy{typer, names.SimpleNameGenerator, auth}
}

func (vpcBindingStrategy) NamespaceScoped() bool {
	return true
}

func (vpcBindingStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
}

func (vpcBindingStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
}

// ExportVerb is the virtual verb on the referenced VPC that gates creating a
// VPCBinding to it — the escalation gate that stops a tenant binding to a VPC
// it doesn't own (docs/control-plane.md §6). The VAP enforces it in CRD mode;
// this strategy enforces it in aggregated-apiserver mode, which bypasses
// kube-apiserver admission.
const ExportVerb = "export"

func (s vpcBindingStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	binding := obj.(*sdn.VPCBinding)
	ref := binding.Spec.VPCRef
	ns := ref.Namespace
	if ns == "" {
		ns = binding.Namespace
	}
	if err := authz.CheckVPCVerb(ctx, s.authz, ExportVerb, ns, ref.Name, field.NewPath("spec", "vpcRef")); err != nil {
		return field.ErrorList{err}
	}
	return field.ErrorList{}
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpcBindingStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpcBindingStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpcBindingStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpcBindingStrategy) Canonicalize(obj runtime.Object) {
}

func (s vpcBindingStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	// Retargeting vpcRef needs a fresh export check; metadata/finalizer writes
	// (the controller's reap finalizer) must pass unchecked — the same
	// refUnchanged guard the VAP applies.
	newB, oldB := obj.(*sdn.VPCBinding), old.(*sdn.VPCBinding)
	if newB.Spec.VPCRef == oldB.Spec.VPCRef {
		return field.ErrorList{}
	}
	return s.Validate(ctx, obj)
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcBindingStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
