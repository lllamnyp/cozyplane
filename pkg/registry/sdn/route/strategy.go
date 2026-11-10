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

package route

import (
	"context"
	"errors"
	"net/netip"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a Route.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	o, ok := obj.(*sdn.Route)
	if !ok {
		return nil, nil, errors.New("given object is not a Route")
	}
	return labels.Set(o.Labels), SelectableFields(o), nil
}

// MatchRoute is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchRoute(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. Routes are
// namespaced.
func SelectableFields(obj *sdn.Route) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns the Route strategy.
func NewStrategy(typer runtime.ObjectTyper) strategy {
	return strategy{typer, names.SimpleNameGenerator}
}

func (strategy) NamespaceScoped() bool { return true }

// PrepareForCreate clears status: it is the controller's, via /status.
func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	o := obj.(*sdn.Route)
	o.Status = sdn.RouteStatus{}
}

// PrepareForUpdate keeps status: a spec update never changes it.
func (strategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	obj.(*sdn.Route).Status = old.(*sdn.Route).Status
}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateSpec(&obj.(*sdn.Route).Spec, field.NewPath("spec"))
}

func (strategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	n, o := obj.(*sdn.Route), old.(*sdn.Route)
	errs := validateSpec(&n.Spec, field.NewPath("spec"))
	return append(errs, validateImmutable(&n.Spec, &o.Spec, field.NewPath("spec"))...)
}

func (strategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string { return nil }
func (strategy) AllowCreateOnUpdate() bool                                         { return false }
func (strategy) AllowUnconditionalUpdate() bool                                    { return false }
func (strategy) Canonicalize(obj runtime.Object)                                   {}
func (strategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// statusStrategy updates status and preserves spec.
type statusStrategy struct {
	strategy
}

// NewStatusStrategy creates the strategy for the /status subresource.
func NewStatusStrategy(s strategy) statusStrategy {
	return statusStrategy{s}
}

func (statusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	obj.(*sdn.Route).Spec = old.(*sdn.Route).Spec
}

func (statusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return nil
}

func (statusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

func validateSpec(s *sdn.RouteSpec, p *field.Path) field.ErrorList {
	var errs field.ErrorList
	if s.RouteTableRef.Name == "" {
		errs = append(errs, field.Required(p.Child("routeTableRef", "name"), "the route table name is required"))
	}
	dp := p.Child("destination")
	if pfx, err := netip.ParsePrefix(s.Destination); err != nil {
		errs = append(errs, field.Invalid(dp, s.Destination, "must be a CIDR"))
	} else if pfx.Masked() != pfx {
		errs = append(errs, field.Invalid(dp, s.Destination, "must be canonical: no host bits set (want "+pfx.Masked().String()+")"))
	} else if pfx.Addr().Is4In6() {
		errs = append(errs, field.Invalid(dp, s.Destination, "must be an IPv4 or IPv6 CIDR, not IPv4-mapped IPv6"))
	}
	n := 0
	t := s.Target
	if t.NATGateway != nil {
		n++
		if t.NATGateway.Name == "" {
			errs = append(errs, field.Required(p.Child("target", "natGateway", "name"), "the NAT gateway name is required"))
		}
	}
	if t.Internet != nil {
		n++
	}
	if t.Blackhole != nil {
		n++
	}
	if n != 1 {
		errs = append(errs, field.Invalid(p.Child("target"), n, "exactly one of natGateway, internet or blackhole must be set"))
	}
	return errs
}

func validateImmutable(n, o *sdn.RouteSpec, p *field.Path) field.ErrorList {
	if n.RouteTableRef != o.RouteTableRef {
		return field.ErrorList{field.Invalid(p.Child("routeTableRef"), n.RouteTableRef, "is immutable")}
	}
	return nil
}
