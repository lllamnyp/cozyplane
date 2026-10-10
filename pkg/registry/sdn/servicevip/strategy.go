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

package servicevip

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a ServiceVIP.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	svip, ok := obj.(*sdn.ServiceVIP)
	if !ok {
		return nil, nil, errors.New("given object is not a ServiceVIP")
	}

	return labels.Set(svip.Labels), SelectableFields(svip), nil
}

// MatchServiceVIP is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchServiceVIP(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.ServiceVIP) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type serviceVIPStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a serviceVIPStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) serviceVIPStrategy {
	return serviceVIPStrategy{typer, names.SimpleNameGenerator}
}

func (serviceVIPStrategy) NamespaceScoped() bool {
	return false // cluster-scoped, like Port: the name encodes the VNI+VIP claim
}

func (serviceVIPStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	svip := obj.(*sdn.ServiceVIP)
	svip.Status = sdn.ServiceVIPStatus{}
}

func (serviceVIPStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newFIP := obj.(*sdn.ServiceVIP)
	oldFIP := old.(*sdn.ServiceVIP)
	newFIP.Status = oldFIP.Status
}

// Validate pins the name to the address claim: a ServiceVIP must be named
// exactly sv<vni>.<escaped spec.ip> with spec.ip in canonical form, or the
// name-based claim (and the registry's cross-kind twin check) could be
// spoofed by naming one address and using another.
func (serviceVIPStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	svip := obj.(*sdn.ServiceVIP)
	errs := validateVIPPorts(svip)

	ip := net.ParseIP(svip.Spec.IP)
	if ip == nil || ip.String() != svip.Spec.IP {
		errs = append(errs, field.Invalid(field.NewPath("spec", "ip"), svip.Spec.IP,
			"must be an IP address in canonical form"))
		return errs
	}
	if ipam.IsReserved(ip) {
		errs = append(errs, field.Invalid(field.NewPath("spec", "ip"), svip.Spec.IP, "reserved platform bridge or hairpin address"))
	}
	vni, _, ok := sdn.ParseClaim(sdn.ClaimPrefixServiceVIP, svip.Name)
	if !ok {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), svip.Name,
			"must have the form sv<vni>.<escaped spec.ip>: the name is the address claim"))
	} else if svip.Name != sdn.ServiceVIPName(vni, svip.Spec.IP) {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), svip.Name,
			fmt.Sprintf("must be %q (sv<vni>.<escaped spec.ip>): the name is the address claim",
				sdn.ServiceVIPName(vni, svip.Spec.IP))))
	}
	return errs
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (serviceVIPStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (serviceVIPStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (serviceVIPStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (serviceVIPStrategy) Canonicalize(obj runtime.Object) {
}

// ValidateUpdate keeps the claimed address immutable: the (immutable) name is
// the claim on {VNI, spec.ip}. The controller reallocates a VIP by
// delete+recreate, never in place; declared ports and affinity update freely.
func (serviceVIPStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newVIP := obj.(*sdn.ServiceVIP)
	oldVIP := old.(*sdn.ServiceVIP)
	errs := validateVIPPorts(newVIP)
	if newVIP.Spec.IP != oldVIP.Spec.IP {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "ip"),
			"immutable: the ServiceVIP name is the claim on this address"))
	}
	if newVIP.Spec.VPCRef != oldVIP.Spec.VPCRef {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "vpcRef"),
			"immutable: the claim is scoped to the VPC's VNI"))
	}
	return errs
}

// WarningsOnUpdate returns warnings for the given update.
func (serviceVIPStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// serviceVIPStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of serviceVIPStrategy).
type serviceVIPStatusStrategy struct {
	serviceVIPStrategy
}

// NewStatusStrategy creates a strategy for the ServiceVIP status subresource.
func NewStatusStrategy(strategy serviceVIPStrategy) serviceVIPStatusStrategy {
	return serviceVIPStatusStrategy{strategy}
}

func (serviceVIPStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newFIP := obj.(*sdn.ServiceVIP)
	oldFIP := old.(*sdn.ServiceVIP)
	newFIP.Spec = oldFIP.Spec
}

func (serviceVIPStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	var errs field.ErrorList
	for i, backend := range obj.(*sdn.ServiceVIP).Status.Backends {
		for j, port := range backend.Ports {
			p := field.NewPath("status", "backends").Index(i).Child("ports").Index(j)
			errs = append(errs, validatePort(port.Protocol, port.Port, p)...)
			if port.TargetPort < 1 || port.TargetPort > 65535 {
				errs = append(errs, field.Invalid(p.Child("targetPort"), port.TargetPort, "must be between 1 and 65535"))
			}
		}
	}
	return errs
}

func validateVIPPorts(vip *sdn.ServiceVIP) field.ErrorList {
	var errs field.ErrorList
	for i, port := range vip.Spec.Ports {
		errs = append(errs, validatePort(port.Protocol, port.Port, field.NewPath("spec", "ports").Index(i))...)
	}
	return errs
}

func validatePort(protocol string, port int32, p *field.Path) field.ErrorList {
	var errs field.ErrorList
	if protocol != "TCP" && protocol != "UDP" {
		errs = append(errs, field.NotSupported(p.Child("protocol"), protocol, []string{"TCP", "UDP"}))
	}
	if port < 1 || port > 65535 {
		errs = append(errs, field.Invalid(p.Child("port"), port, "must be between 1 and 65535"))
	}
	return errs
}

func (serviceVIPStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
