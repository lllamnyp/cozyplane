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
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	fip.Generation = 1
}

func (floatingIPStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newFIP := obj.(*sdn.FloatingIP)
	oldFIP := old.(*sdn.FloatingIP)
	newFIP.Status = oldFIP.Status
	if !apiequality.Semantic.DeepEqual(newFIP.Spec, oldFIP.Spec) {
		newFIP.Generation = oldFIP.Generation + 1
	}
}

func (floatingIPStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateFloatingIPSpec(obj.(*sdn.FloatingIP))
}

// validateFloatingIPSpec rejects a binding that can never resolve.
//
// Like the VPC strategy, this is the only validation layer the aggregated
// apiserver gives these kinds. Unvalidated, a FloatingIP whose target was not an
// address at all was accepted and then failed SILENTLY: the controller's
// ensureEndpointSlice parses the target, and on a parse error returns nil and
// writes no endpoint, so the object sat Pending forever with nothing anywhere
// saying why. The target is also matched against Port.spec.IP, which the Port
// strategy already pins to canonical form — so a non-canonical target here could
// never match a Port even when it named a real address.
func validateFloatingIPSpec(fip *sdn.FloatingIP) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")

	if fip.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"),
			"the local VPC name is required"))
	}
	switch ip := net.ParseIP(fip.Spec.Target); {
	case fip.Spec.Target == "":
		errs = append(errs, field.Required(specPath.Child("target"),
			"the tenant IP this address binds to is required"))
	case ip == nil || ip.String() != fip.Spec.Target:
		errs = append(errs, field.Invalid(specPath.Child("target"), fip.Spec.Target,
			"must be an IP address in canonical form: it is matched against a Port's spec.ip"))
	}
	return errs
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

// ValidateUpdate ratchets on the validated fields (see the VPC strategy): an
// object stored before this validation existed stays editable.
func (floatingIPStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newFIP := obj.(*sdn.FloatingIP)
	oldFIP := old.(*sdn.FloatingIP)
	if newFIP.Spec.Target == oldFIP.Spec.Target && newFIP.Spec.VPCRef == oldFIP.Spec.VPCRef {
		return field.ErrorList{}
	}
	return validateFloatingIPSpec(newFIP)
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
