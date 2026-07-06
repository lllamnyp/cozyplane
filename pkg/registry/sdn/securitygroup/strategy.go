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

package securitygroup

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a SecurityGroup.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	sg, ok := obj.(*sdn.SecurityGroup)
	if !ok {
		return nil, nil, errors.New("given object is not a SecurityGroup")
	}
	return labels.Set(sg.Labels), SelectableFields(sg), nil
}

// MatchSecurityGroup is the filter used by the generic etcd backend.
func MatchSecurityGroup(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. SecurityGroups
// are namespaced.
func SelectableFields(obj *sdn.SecurityGroup) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type securityGroupStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a securityGroupStrategy instance. A group lives
// in its VPC owner's namespace; owning the namespace is owning the VPC's policy,
// so there is no virtual verb to check (contrast VPCPeering's `peer`).
func NewStrategy(typer runtime.ObjectTyper) securityGroupStrategy {
	return securityGroupStrategy{typer, names.SimpleNameGenerator}
}

func (securityGroupStrategy) NamespaceScoped() bool {
	return true
}

func (securityGroupStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status (including the allocated id) is controller-owned via /status.
	sg := obj.(*sdn.SecurityGroup)
	sg.Status = sdn.SecurityGroupStatus{}
}

func (securityGroupStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newSG := obj.(*sdn.SecurityGroup)
	oldSG := old.(*sdn.SecurityGroup)
	newSG.Status = oldSG.Status
}

func (securityGroupStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	sg := obj.(*sdn.SecurityGroup)
	return validateSecurityGroup(sg)
}

func validateSecurityGroup(sg *sdn.SecurityGroup) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if sg.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"), "the local VPC name is required"))
	}
	for i, r := range sg.Spec.Ingress {
		p := specPath.Child("ingress").Index(i).Child("from")
		hasGroup := r.From.Group != ""
		hasCIDR := r.From.CIDR != ""
		switch {
		case hasGroup && hasCIDR:
			errs = append(errs, field.Invalid(p, r.From, "set exactly one of group or cidr"))
		case !hasGroup && !hasCIDR:
			errs = append(errs, field.Required(p, "one of group or cidr is required"))
		}
	}
	return errs
}

func (securityGroupStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (securityGroupStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (securityGroupStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (securityGroupStrategy) Canonicalize(obj runtime.Object) {
}

func (securityGroupStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newSG := obj.(*sdn.SecurityGroup)
	oldSG := old.(*sdn.SecurityGroup)
	errs := validateSecurityGroup(newSG)
	// The VPC binding is the group's identity anchor; changing it would
	// re-home the group and orphan its allocated id. Replace instead.
	if newSG.Spec.VPCRef != oldSG.Spec.VPCRef {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "vpcRef"), "vpcRef is immutable"))
	}
	return errs
}

func (securityGroupStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// securityGroupStatusStrategy is the /status update strategy: it updates status
// but preserves spec.
type securityGroupStatusStrategy struct {
	securityGroupStrategy
}

// NewStatusStrategy creates a strategy for the SecurityGroup status subresource.
func NewStatusStrategy(strategy securityGroupStrategy) securityGroupStatusStrategy {
	return securityGroupStatusStrategy{strategy}
}

func (securityGroupStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newSG := obj.(*sdn.SecurityGroup)
	oldSG := old.(*sdn.SecurityGroup)
	newSG.Spec = oldSG.Spec
}

func (securityGroupStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (securityGroupStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
