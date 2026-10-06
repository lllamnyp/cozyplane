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
	"github.com/lllamnyp/cozyplane/pkg/netid"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/authz"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	metavalidation "k8s.io/apimachinery/pkg/apis/meta/v1/validation"
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
	auth authorizer.Authorizer
}

// NewStrategy preserves ordinary tenant policy permissions and separately
// authorizes changes to operator-managed groups.
func NewStrategy(typer runtime.ObjectTyper, auth authorizer.Authorizer) securityGroupStrategy {
	return securityGroupStrategy{typer, names.SimpleNameGenerator, auth}
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

func (s securityGroupStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	sg := obj.(*sdn.SecurityGroup)
	errs := validateSecurityGroup(sg)
	if err := authz.CheckManaged(ctx, s.auth, "securitygroups", obj, nil); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func validateSecurityGroup(sg *sdn.SecurityGroup) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	errs = append(errs, metavalidation.ValidateLabelSelector(&sg.Spec.PodSelector, metavalidation.LabelSelectorValidationOptions{}, specPath.Child("podSelector"))...)
	if sg.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"), "the local VPC name is required"))
	}
	for i, r := range sg.Spec.Ingress {
		errs = append(errs, validatePorts(r.Ports, specPath.Child("ingress").Index(i).Child("ports"))...)
		p := specPath.Child("ingress").Index(i).Child("from")
		hasGroup := r.From.Group != ""
		hasCIDR := r.From.CIDR != ""
		switch {
		case hasGroup && hasCIDR:
			errs = append(errs, field.Invalid(p, r.From, "set exactly one of group or cidr"))
		case !hasGroup && !hasCIDR:
			errs = append(errs, field.Required(p, "one of group or cidr is required"))
		case hasCIDR:
			// v2 north-south: the all-addresses CIDR (SG_WORLD) and specific
			// ranges (sg_cidr LPM) are both enforced. Validate it parses.
			if _, _, err := net.ParseCIDR(r.From.CIDR); err != nil {
				errs = append(errs, field.Invalid(p.Child("cidr"), r.From.CIDR, "not a valid CIDR"))
			}
		}
		// A peer-VPC reference must name a group in that VPC.
		if r.From.VPC != nil {
			if r.From.VPC.Namespace == "" || r.From.VPC.Name == "" {
				errs = append(errs, field.Invalid(p.Child("vpc"), r.From.VPC, "peer vpc ref needs both namespace and name"))
			}
			if !hasGroup {
				errs = append(errs, field.Required(p.Child("group"), "a peer-VPC reference must name a group"))
			}
		}
	}
	for i, r := range sg.Spec.Egress {
		errs = append(errs, validatePorts(r.Ports, specPath.Child("egress").Index(i).Child("ports"))...)
		p := specPath.Child("egress").Index(i).Child("to")
		hasGroup := r.To.Group != ""
		hasCIDR := r.To.CIDR != ""
		switch {
		case hasGroup && hasCIDR:
			errs = append(errs, field.Invalid(p, r.To, "set exactly one of group or cidr"))
		case !hasGroup && !hasCIDR:
			errs = append(errs, field.Required(p, "an egress rule must name a destination group or cidr"))
		case hasCIDR:
			if _, _, err := net.ParseCIDR(r.To.CIDR); err != nil {
				errs = append(errs, field.Invalid(p.Child("cidr"), r.To.CIDR, "not a valid CIDR"))
			}
		}
		if r.To.VPC != nil {
			if r.To.VPC.Namespace == "" || r.To.VPC.Name == "" {
				errs = append(errs, field.Invalid(p.Child("vpc"), r.To.VPC, "peer vpc ref needs both namespace and name"))
			}
			if !hasGroup {
				errs = append(errs, field.Required(p.Child("group"), "a peer-VPC egress reference must name a group"))
			}
		}
	}
	return errs
}

// Only an empty port list denotes all ports. Explicit zero and overflowing
// ports must never reach the datapath's uint16 wildcard representation.
func validatePorts(ports []sdn.SecurityGroupPort, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	for i, port := range ports {
		p := path.Index(i)
		if port.Protocol != "TCP" && port.Protocol != "UDP" {
			errs = append(errs, field.NotSupported(p.Child("protocol"), port.Protocol, []string{"TCP", "UDP"}))
		}
		if port.Port < 1 || port.Port > 65535 {
			errs = append(errs, field.Invalid(p.Child("port"), port.Port, "must be between 1 and 65535"))
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

func (s securityGroupStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newSG := obj.(*sdn.SecurityGroup)
	oldSG := old.(*sdn.SecurityGroup)
	errs := validateSecurityGroup(newSG)
	if err := authz.CheckManaged(ctx, s.auth, "securitygroups", obj, old); err != nil {
		errs = append(errs, err)
	}
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
	authz.PreserveManager(obj, old)
}

func (securityGroupStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	id := obj.(*sdn.SecurityGroup).Status.ID
	if id != 0 && !netid.ValidGroup(id) {
		return field.ErrorList{field.Invalid(field.NewPath("status", "id"), id, "must be zero (pending) or between 1 and 62")}
	}
	return nil
}

func (securityGroupStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
