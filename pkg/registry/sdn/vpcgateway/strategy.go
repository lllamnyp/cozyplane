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

package vpcgateway

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPCGateway.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	gw, ok := obj.(*sdn.VPCGateway)
	if !ok {
		return nil, nil, errors.New("given object is not a VPCGateway")
	}

	return labels.Set(gw.Labels), SelectableFields(gw), nil
}

// MatchVPCGateway is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPCGateway(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. VPCGateways
// are namespaced.
func SelectableFields(obj *sdn.VPCGateway) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpcGatewayStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpcGatewayStrategy instance. The gateway
// needs no escalation gate anymore: who may mint the public address it draws is
// Service RBAC + the allocator's scoping (docs/external-addresses.md §8).
func NewStrategy(typer runtime.ObjectTyper) vpcGatewayStrategy {
	return vpcGatewayStrategy{typer, names.SimpleNameGenerator}
}

func (vpcGatewayStrategy) NamespaceScoped() bool {
	return true
}

func (vpcGatewayStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	gw := obj.(*sdn.VPCGateway)
	gw.Status = sdn.VPCGatewayStatus{}
}

func (vpcGatewayStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newPeering := obj.(*sdn.VPCGateway)
	oldPeering := old.(*sdn.VPCGateway)
	newPeering.Status = oldPeering.Status
}

func (s vpcGatewayStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	gw := obj.(*sdn.VPCGateway)
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if gw.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"), "the VPC name is required"))
	}
	return errs
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpcGatewayStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpcGatewayStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpcGatewayStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpcGatewayStrategy) Canonicalize(obj runtime.Object) {
}

func (s vpcGatewayStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcGatewayStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpcGatewayStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpcGatewayStrategy).
type vpcGatewayStatusStrategy struct {
	vpcGatewayStrategy
}

// NewStatusStrategy creates a strategy for the VPCGateway status subresource.
func NewStatusStrategy(strategy vpcGatewayStrategy) vpcGatewayStatusStrategy {
	return vpcGatewayStatusStrategy{strategy}
}

func (vpcGatewayStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPeering := obj.(*sdn.VPCGateway)
	oldPeering := old.(*sdn.VPCGateway)
	newPeering.Spec = oldPeering.Spec
}

func (vpcGatewayStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpcGatewayStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
