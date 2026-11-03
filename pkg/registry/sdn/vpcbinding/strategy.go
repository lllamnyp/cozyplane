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
	"slices"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apiserver/pkg/authorization/authorizer"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
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
	// Install atomically with the grant, before a CNI can consume it. An
	// asynchronous controller update leaves a create/delete revocation race.
	b := obj.(*sdn.VPCBinding)
	const reapFinalizer = "sdn.cozystack.io/reap-ports"
	if !slices.Contains(b.Finalizers, reapFinalizer) {
		b.Finalizers = append(b.Finalizers, reapFinalizer)
	}
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
	if errs := vpnlimits.ReferenceErrors(binding.Spec.VPCRef.Name, field.NewPath("spec", "vpcRef", "name"), true); len(errs) != 0 {
		return errs
	}
	if errs := vpnlimits.NamespaceReferenceErrors(binding.Spec.VPCRef.Namespace, field.NewPath("spec", "vpcRef", "namespace")); len(errs) != 0 {
		return errs
	}
	if len(binding.Spec.ForwardingCIDRs) > sdnv1alpha1.MaxForwardingPrefixes {
		return field.ErrorList{field.TooMany(field.NewPath("spec", "forwardingCIDRs"), len(binding.Spec.ForwardingCIDRs), sdnv1alpha1.MaxForwardingPrefixes)}
	}
	if binding.Spec.AllowForwarding {
		if err := sdnv1alpha1.ValidateForwardingPrefixes(binding.Spec.ForwardingCIDRs); err != nil {
			return field.ErrorList{field.Invalid(field.NewPath("spec", "forwardingCIDRs"), "", err.Error())}
		}
	}
	return s.checkExport(ctx, binding)
}

func (s vpcBindingStrategy) checkExport(ctx context.Context, binding *sdn.VPCBinding) field.ErrorList {
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
	// Every grant change needs the owner's authority, including enabling or
	// widening forwarding without retargeting the VPC. Removing the reap
	// finalizer also needs that authority: otherwise a consumer can bypass
	// revocation. Other metadata-only writes remain permitted.
	newB, oldB := obj.(*sdn.VPCBinding), old.(*sdn.VPCBinding)
	if newB.Spec.VPCRef != oldB.Spec.VPCRef {
		return field.ErrorList{field.Invalid(field.NewPath("spec", "vpcRef"), nil, "is immutable; delete and recreate the binding")}
	}
	const reapFinalizer = "sdn.cozystack.io/reap-ports"
	removesReap := slices.Contains(oldB.Finalizers, reapFinalizer) && !slices.Contains(newB.Finalizers, reapFinalizer)
	if equality.Semantic.DeepEqual(newB.Spec, oldB.Spec) {
		if removesReap {
			return s.checkExport(ctx, newB)
		}
		return nil
	}
	// Input validation must not trap a malformed legacy grant in an enabled
	// state. This exception only removes authority; owner authorization remains.
	if oldB.Spec.AllowForwarding && !newB.Spec.AllowForwarding && slices.Equal(oldB.Spec.ForwardingCIDRs, newB.Spec.ForwardingCIDRs) {
		return s.checkExport(ctx, newB)
	}
	return s.Validate(ctx, obj)
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcBindingStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
