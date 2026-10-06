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
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"net"
	"reflect"
	"slices"

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
	auth authorizer.Authorizer
}

// NewStrategy creates and returns a vpcStrategy instance.
func NewStrategy(typer runtime.ObjectTyper, auth ...authorizer.Authorizer) vpcStrategy {
	var a authorizer.Authorizer
	if len(auth) > 0 {
		a = auth[0]
	}
	return vpcStrategy{typer, names.SimpleNameGenerator, a}
}

func (vpcStrategy) NamespaceScoped() bool {
	return true
}

func (vpcStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	vpc := obj.(*sdn.VPC)
	vpc.Status = sdn.VPCStatus{}
	vpc.Generation = 1
}

func (vpcStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newVPC := obj.(*sdn.VPC)
	oldVPC := old.(*sdn.VPC)
	newVPC.Status = oldVPC.Status
	newVPC.Generation = oldVPC.Generation
	if !reflect.DeepEqual(newVPC.Spec, oldVPC.Spec) {
		newVPC.Generation++
	}
}

func (s vpcStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	v := obj.(*sdn.VPC)
	errs := validateVPCSpec(v)
	if v.Spec.Boundary != nil {
		if err := authz.CheckVPCVerb(ctx, s.auth, "manage-boundary", v.Namespace, v.Name, field.NewPath("spec", "boundary")); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// validateVPCSpec rejects a VPC that cannot become a working network.
//
// This is the group's ONLY validation layer: the tenant kinds are served by the
// aggregated apiserver, which — unlike a CRD — applies no structural schema. An
// empty Validate here meant a VPC with no CIDR, or with "not-a-cidr", was stored
// happily; the controller then assigned it a VNI and marked it Ready (it never
// looks at the CIDRs), the agents skipped it silently, and the tenant only found
// out when every pod died in ContainerCreating with "vpc has no CIDR". A VPC that
// reports Ready and cannot host a pod is the worst answer we can give, so refuse
// the object instead.
func validateVPCSpec(vpc *sdn.VPC) field.ErrorList {
	var errs field.ErrorList
	cidrsPath := field.NewPath("spec", "cidrs")

	if len(vpc.Spec.CIDRs) == 0 {
		errs = append(errs, field.Required(cidrsPath,
			"a VPC needs at least one CIDR; pods cannot attach to a VPC with no address space"))
	}
	for i, c := range vpc.Spec.CIDRs {
		p := cidrsPath.Index(i)
		ip, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			errs = append(errs, field.Invalid(p, c, "not a valid CIDR"))
			continue
		}
		// Canonical (masked) form, like the Port and ServiceVIP name claims:
		// "10.0.0.5/24" means 10.0.0.0/24 to every consumer of this field, and a
		// tenant reading its own spec back should not have to know that.
		if !ip.Equal(ipnet.IP) || ipnet.String() != c {
			errs = append(errs, field.Invalid(p, c,
				"must be in canonical form (the network address and prefix, e.g. "+ipnet.String()+")"))
		}
	}

	// The MTU is handed to the CNI verbatim; a nonsensical one produces a pod
	// interface nothing can talk through. Zero means "take the default".
	if m := vpc.Spec.MTU; m != 0 && (m < 576 || m > 65535) {
		errs = append(errs, field.Invalid(field.NewPath("spec", "mtu"), m,
			"must be 0 (the controller default) or between 576 and 65535"))
	}
	return append(errs, validateBoundary(vpc)...)
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

// ValidateUpdate ratchets: the spec is re-validated only where it CHANGED, so a
// VPC stored before this validation existed can still be edited (and repaired)
// rather than being frozen by a rule it predates.
func (s vpcStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newVPC := obj.(*sdn.VPC)
	oldVPC := old.(*sdn.VPC)
	boundaryChanged := !reflect.DeepEqual(newVPC.Spec.Boundary, oldVPC.Spec.Boundary)
	networkChanged := !slices.Equal(newVPC.Spec.CIDRs, oldVPC.Spec.CIDRs) || newVPC.Spec.MTU != oldVPC.Spec.MTU
	var errs field.ErrorList
	if boundaryChanged || (oldVPC.Spec.Boundary != nil && networkChanged) {
		if err := authz.CheckVPCVerb(ctx, s.auth, "manage-boundary", oldVPC.Namespace, oldVPC.Name, field.NewPath("spec")); err != nil {
			errs = append(errs, err)
		}
	}
	if boundaryChanged {
		if newVPC.Spec.Boundary != nil && oldVPC.Spec.Boundary != nil && newVPC.Spec.Boundary.Revision <= oldVPC.Spec.Boundary.Revision {
			errs = append(errs, field.Invalid(field.NewPath("spec", "boundary", "revision"), newVPC.Spec.Boundary.Revision, "must increase when boundary changes"))
		}
	}
	if !networkChanged && !boundaryChanged {
		return field.ErrorList{}
	}
	return append(errs, validateVPCSpec(newVPC)...)
}

// WarningsOnUpdate returns warnings for the given update.
func (vpcStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpcStatusStrategy is the update strategy for the /status subresource: it
// updates status but preserves spec (the mirror image of vpcStrategy).
type vpcStatusStrategy struct {
	vpcStrategy
}

// NewStatusStrategy creates a strategy for the VPC status subresource.
func NewStatusStrategy(strategy vpcStrategy) vpcStatusStrategy {
	return vpcStatusStrategy{strategy}
}

func (vpcStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newVPC := obj.(*sdn.VPC)
	oldVPC := old.(*sdn.VPC)
	newVPC.Spec = oldVPC.Spec
	newVPC.Generation = oldVPC.Generation
}

func (vpcStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	vni := obj.(*sdn.VPC).Status.VNI
	if vni != 0 && !netid.ValidVNI(vni) {
		return field.ErrorList{field.Invalid(field.NewPath("status", "vni"), vni, "must be zero (pending) or between 100 and 4194303")}
	}
	return nil
}

func (vpcStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
