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
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authorization/authorizer"
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

// AttachVerb is the virtual verb on the referenced ExternalPool that gates
// creating a VPCGateway onto it. A pool is a scarce, cluster-scoped, billable
// resource: the operator owns it and grants it, and the tenant then opens its own
// VPC's door onto what it was given. Without this, a tenant could grant itself
// internet access — which is exactly what `VPC.spec.egress.natGateway` used to
// let it do (docs/north-south.md).
//
// The same escalation gate as VPCBinding's `export` and VPCPeering's `peer`, and
// enforced in the same place: the aggregated apiserver, which admission webhooks
// never see.
const AttachVerb = "attach"

type vpcGatewayStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
	authz authorizer.Authorizer
}

// NewStrategy creates and returns a vpcGatewayStrategy instance.
// NewStrategy builds the strategy. auth is the delegated authorizer for the
// peer-verb check; nil skips it (CRD mode, where the VAP twin enforces).
func NewStrategy(typer runtime.ObjectTyper, auth authorizer.Authorizer) vpcGatewayStrategy {
	return vpcGatewayStrategy{typer, names.SimpleNameGenerator, auth}
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
	// Drawing from a pool is the operator's grant, not the tenant's to take.
	if len(errs) == 0 && gw.Spec.PoolRef.Name != "" {
		if err := authz.CheckResourceVerb(ctx, s.authz, AttachVerb, "externalpools", "ExternalPool",
			"", gw.Spec.PoolRef.Name, specPath.Child("poolRef")); err != nil {
			errs = append(errs, err)
		}
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
	// Retargeting poolRef needs a fresh attach check; everything else (the
	// controller's status/finalizer writes) passes unchecked.
	newG, oldG := obj.(*sdn.VPCGateway), old.(*sdn.VPCGateway)
	if newG.Spec.PoolRef == oldG.Spec.PoolRef {
		return field.ErrorList{}
	}
	return s.Validate(ctx, obj)
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
