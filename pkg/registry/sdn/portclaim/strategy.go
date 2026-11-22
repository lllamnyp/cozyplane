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

package portclaim

import (
	"context"
	"errors"
	"net"
	"slices"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1alpha1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a PortClaim.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	pc, ok := obj.(*sdn.PortClaim)
	if !ok {
		return nil, nil, errors.New("given object is not a PortClaim")
	}
	return labels.Set(pc.Labels), SelectableFields(pc), nil
}

// MatchPortClaim is the filter used by the generic etcd backend to watch events.
func MatchPortClaim(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.PortClaim) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type portClaimStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a portClaimStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) portClaimStrategy {
	return portClaimStrategy{typer, names.SimpleNameGenerator}
}

func (portClaimStrategy) NamespaceScoped() bool {
	return true
}

// PrepareForCreate clears status, defaults the VPC namespace to the claim's, and adds the Port finalizer.
func (portClaimStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	pc := obj.(*sdn.PortClaim)
	pc.Status = sdn.PortClaimStatus{}
	if pc.Spec.VPCRef.Namespace == "" {
		pc.Spec.VPCRef.Namespace = pc.Namespace
		if pc.Spec.VPCRef.Namespace == "" {
			pc.Spec.VPCRef.Namespace, _ = genericapirequest.NamespaceFrom(ctx)
		}
	}
	if !slices.Contains(pc.Finalizers, sdnv1alpha1.FinalizerPortClaim) {
		pc.Finalizers = append(pc.Finalizers, sdnv1alpha1.FinalizerPortClaim)
	}
}

func (portClaimStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPC := obj.(*sdn.PortClaim)
	oldPC := old.(*sdn.PortClaim)
	newPC.Status = oldPC.Status
}

func (portClaimStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateSpec(&obj.(*sdn.PortClaim).Spec)
}

// validateSpec checks the VPC reference and the canonical form of a requested MAC and IP.
func validateSpec(spec *sdn.PortClaimSpec) field.ErrorList {
	var errs field.ErrorList
	p := field.NewPath("spec")
	if spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(p.Child("vpcRef", "name"), "the VPC name is required"))
	}
	if spec.MAC != "" {
		if msg := ValidateMAC(spec.MAC); msg != "" {
			errs = append(errs, field.Invalid(p.Child("mac"), spec.MAC, msg))
		}
	}
	if spec.IP != "" {
		if ip := net.ParseIP(spec.IP); ip == nil || ip.String() != spec.IP {
			errs = append(errs, field.Invalid(p.Child("ip"), spec.IP, "must be an IP address in canonical form"))
		}
	}
	return errs
}

// ValidateMAC returns why mac cannot be an interface MAC, or "" if it can.
func ValidateMAC(mac string) string {
	hw, err := net.ParseMAC(mac)
	switch {
	case err != nil || len(hw) != 6:
		return "must be a 48-bit MAC address"
	case hw.String() != mac:
		return "must be in canonical form (lower-case, colon-separated)"
	case hw[0]&0x01 != 0:
		return "must be a unicast address"
	case slices.Equal(hw, make(net.HardwareAddr, 6)):
		return "must not be all zeros"
	}
	return ""
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (portClaimStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (portClaimStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (portClaimStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (portClaimStrategy) Canonicalize(obj runtime.Object) {
}

// ValidateUpdate keeps the spec immutable.
func (portClaimStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newPC := obj.(*sdn.PortClaim)
	oldPC := old.(*sdn.PortClaim)
	if newPC.Spec != oldPC.Spec {
		return field.ErrorList{field.Forbidden(field.NewPath("spec"), "immutable")}
	}
	return nil
}

// WarningsOnUpdate returns warnings for the given update.
func (portClaimStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// portClaimStatusStrategy updates status and preserves spec.
type portClaimStatusStrategy struct {
	portClaimStrategy
}

// NewStatusStrategy creates a strategy for the PortClaim status subresource.
func NewStatusStrategy(strategy portClaimStrategy) portClaimStatusStrategy {
	return portClaimStatusStrategy{strategy}
}

func (portClaimStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPC := obj.(*sdn.PortClaim)
	oldPC := old.(*sdn.PortClaim)
	newPC.Spec = oldPC.Spec
}

// ValidateUpdate keeps a pinned status IP and MAC from changing.
func (portClaimStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newPC := obj.(*sdn.PortClaim)
	oldPC := old.(*sdn.PortClaim)
	var errs field.ErrorList
	p := field.NewPath("status")
	if oldPC.Status.IP != "" && newPC.Status.IP != oldPC.Status.IP {
		errs = append(errs, field.Forbidden(p.Child("ip"), "immutable once pinned"))
	}
	if oldPC.Status.MAC != "" && newPC.Status.MAC != oldPC.Status.MAC {
		errs = append(errs, field.Forbidden(p.Child("mac"), "immutable once pinned"))
	}
	return errs
}

func (portClaimStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
