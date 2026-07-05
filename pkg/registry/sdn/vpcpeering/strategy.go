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

package vpcpeering

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPCPeering.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	peering, ok := obj.(*sdn.VPCPeering)
	if !ok {
		return nil, nil, errors.New("given object is not a VPCPeering")
	}

	return labels.Set(peering.Labels), SelectableFields(peering), nil
}

// MatchVPCPeering is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPCPeering(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. VPCPeerings
// are namespaced.
func SelectableFields(obj *sdn.VPCPeering) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

// PeerVerb is the virtual verb on the LOCAL VPC that gates creating a peering
// half: verbs on a VPC express what a principal may do with it (`export` =
// grant use, `peer` = connect it to another VPC). Consent from the remote side
// is the reciprocal half, so no verb is checked on the peer VPC.
const PeerVerb = "peer"

type vpcPeeringStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
	authz authorizer.Authorizer
}

// NewStrategy creates and returns a vpcPeeringStrategy instance.
// NewStrategy builds the strategy. auth is the delegated authorizer for the
// peer-verb check; nil skips it (CRD mode, where the VAP twin enforces).
func NewStrategy(typer runtime.ObjectTyper, auth authorizer.Authorizer) vpcPeeringStrategy {
	return vpcPeeringStrategy{typer, names.SimpleNameGenerator, auth}
}

func (vpcPeeringStrategy) NamespaceScoped() bool {
	return true
}

func (vpcPeeringStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	peering := obj.(*sdn.VPCPeering)
	peering.Status = sdn.VPCPeeringStatus{}
}

func (vpcPeeringStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newPeering := obj.(*sdn.VPCPeering)
	oldPeering := old.(*sdn.VPCPeering)
	newPeering.Status = oldPeering.Status
}

func (s vpcPeeringStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	peering := obj.(*sdn.VPCPeering)
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if peering.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"), "the local VPC name is required"))
	}
	if peering.Spec.PeerRef.Namespace == "" {
		errs = append(errs, field.Required(specPath.Child("peerRef", "namespace"), "the peer VPC namespace is required"))
	}
	if peering.Spec.PeerRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("peerRef", "name"), "the peer VPC name is required"))
	}
	if peering.Spec.PeerRef.Namespace == peering.Namespace && peering.Spec.PeerRef.Name == peering.Spec.VPCRef.Name {
		errs = append(errs, field.Invalid(specPath.Child("peerRef"), peering.Spec.PeerRef,
			"a VPC cannot peer with itself"))
	}
	// Creating a half connects the LOCAL VPC outward — that is what the peer
	// verb on it authorizes (issue #1). The local VPC lives in the peering's
	// own namespace.
	if len(errs) == 0 {
		if err := authz.CheckVPCVerb(ctx, s.authz, PeerVerb, peering.Namespace, peering.Spec.VPCRef.Name, specPath.Child("vpcRef")); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpcPeeringStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpcPeeringStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpcPeeringStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpcPeeringStrategy) Canonicalize(obj runtime.Object) {
}

func (vpcPeeringStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	// The refs pin the identity the reciprocal half consented to; changing them
	// would silently re-point a live grant. Replace the object instead.
	newPeering := obj.(*sdn.VPCPeering)
	oldPeering := old.(*sdn.VPCPeering)
	if newPeering.Spec != oldPeering.Spec {
		return field.ErrorList{field.Forbidden(field.NewPath("spec"), "spec is immutable")}
	}
	return field.ErrorList{}
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcPeeringStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpcPeeringStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpcPeeringStrategy).
type vpcPeeringStatusStrategy struct {
	vpcPeeringStrategy
}

// NewStatusStrategy creates a strategy for the VPCPeering status subresource.
func NewStatusStrategy(strategy vpcPeeringStrategy) vpcPeeringStatusStrategy {
	return vpcPeeringStatusStrategy{strategy}
}

func (vpcPeeringStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPeering := obj.(*sdn.VPCPeering)
	oldPeering := old.(*sdn.VPCPeering)
	newPeering.Spec = oldPeering.Spec
}

func (vpcPeeringStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpcPeeringStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
