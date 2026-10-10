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
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	errs := validateSecurityGroup(sg, false)
	if err := authz.CheckManaged(ctx, s.auth, "securitygroups", obj, nil); err != nil {
		errs = append(errs, err)
	}
	return errs
}

func validateSecurityGroup(sg *sdn.SecurityGroup, unchanged bool) field.ErrorList {
	specPath := field.NewPath("spec")
	if !unchanged {
		if errs := vpnlimits.ReferenceErrors(sg.Spec.VPCRef.Name, specPath.Child("vpcRef", "name"), true); len(errs) != 0 {
			return errs
		}
	}
	if _, err := metav1.LabelSelectorAsSelector(&sg.Spec.PodSelector); err != nil {
		return field.ErrorList{field.Invalid(specPath.Child("podSelector"), nil, "must be a valid label selector")}
	}
	if sg.Spec.VPCRef.Name == "" {
		return field.ErrorList{field.Required(specPath.Child("vpcRef", "name"), "the local VPC name is required")}
	}
	for i, r := range sg.Spec.Ingress {
		rp := specPath.Child("ingress").Index(i)
		if errs := validateRulePorts(r.Ports, rp.Child("ports")); len(errs) != 0 {
			return errs
		}
		if errs := validateRulePeer(r.From, rp.Child("from"), unchanged); len(errs) != 0 {
			return errs
		}
	}
	for i, r := range sg.Spec.Egress {
		rp := specPath.Child("egress").Index(i)
		if errs := validateRulePorts(r.Ports, rp.Child("ports")); len(errs) != 0 {
			return errs
		}
		if errs := validateRulePeer(r.To, rp.Child("to"), unchanged); len(errs) != 0 {
			return errs
		}
	}
	return nil
}

func validateRulePeer(peer sdn.SecurityGroupPeer, path *field.Path, unchanged bool) field.ErrorList {
	hasGroup, hasCIDR := peer.Group != "", peer.CIDR != ""
	if hasGroup && hasCIDR {
		return field.ErrorList{field.Invalid(path, nil, "set exactly one of group or cidr")}
	}
	if !hasGroup && !hasCIDR {
		return field.ErrorList{field.Required(path, "one of group or cidr is required")}
	}
	if hasGroup && !unchanged {
		if errs := vpnlimits.ReferenceErrors(peer.Group, path.Child("group"), true); len(errs) != 0 {
			return errs
		}
	}
	if hasCIDR {
		if len(peer.CIDR) > 64 {
			return field.ErrorList{field.Invalid(path.Child("cidr"), nil, "must contain at most 64 bytes")}
		}
		if _, _, err := net.ParseCIDR(peer.CIDR); err != nil {
			return field.ErrorList{field.Invalid(path.Child("cidr"), nil, "not a valid CIDR")}
		}
	}
	if peer.VPC != nil {
		if peer.VPC.Namespace == "" || peer.VPC.Name == "" {
			return field.ErrorList{field.Invalid(path.Child("vpc"), nil, "peer vpc ref needs both namespace and name")}
		}
		if !hasGroup {
			return field.ErrorList{field.Required(path.Child("group"), "a peer-VPC reference must name a group")}
		}
		if !unchanged {
			if !vpnlimits.NamespaceName(peer.VPC.Namespace) {
				return field.ErrorList{field.Invalid(path.Child("vpc", "namespace"), nil, "must be a DNS label namespace of at most 63 bytes")}
			}
			if errs := vpnlimits.ReferenceErrors(peer.VPC.Name, path.Child("vpc", "name"), true); len(errs) != 0 {
				return errs
			}
		}
	}
	return nil
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
	errs := validateSecurityGroup(newSG, equality.Semantic.DeepEqual(newSG.Spec, oldSG.Spec))
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
func validateRulePorts(ports []sdn.SecurityGroupPort, path *field.Path) field.ErrorList {
	for i, port := range ports {
		if port.Protocol != "TCP" && port.Protocol != "UDP" {
			return field.ErrorList{field.Invalid(path.Index(i).Child("protocol"), nil, "must be TCP or UDP")}
		}
		if port.Port < 0 || port.Port > 65535 {
			return field.ErrorList{field.Invalid(path.Index(i).Child("port"), port.Port, "must be 0-65535")}
		}
	}
	return nil
}
