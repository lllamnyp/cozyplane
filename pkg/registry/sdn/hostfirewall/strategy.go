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

package hostfirewall

import (
	"context"
	"errors"
	"net"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a HostFirewall.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	hf, ok := obj.(*sdn.HostFirewall)
	if !ok {
		return nil, nil, errors.New("given object is not a HostFirewall")
	}

	return labels.Set(hf.Labels), SelectableFields(hf), nil
}

// MatchHostFirewall is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchHostFirewall(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.HostFirewall) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, false)
}

type hostFirewallStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns an hostFirewallStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) hostFirewallStrategy {
	return hostFirewallStrategy{typer, names.SimpleNameGenerator}
}

func (hostFirewallStrategy) NamespaceScoped() bool {
	return false
}

func (hostFirewallStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status is owned by the controller via the /status subresource; a create
	// never sets it.
	hf := obj.(*sdn.HostFirewall)
	hf.Status = sdn.HostFirewallStatus{}
}

func (hostFirewallStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update must not change status (that goes through /status).
	newHF := obj.(*sdn.HostFirewall)
	oldHF := old.(*sdn.HostFirewall)
	newHF.Status = oldHF.Status
}

func (hostFirewallStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateSpec(obj.(*sdn.HostFirewall))
}

// validateSpec rejects rules the agent compiler would otherwise have to
// fail-close on: unparsable CIDRs, non-TCP/UDP protocols, and port ranges
// beyond the datapath's per-port expansion cap (docs/host-firewall.md).
func validateSpec(hf *sdn.HostFirewall) field.ErrorList {
	errs := field.ErrorList{}
	for i, rule := range hf.Spec.Egress {
		rp := field.NewPath("spec", "egress").Index(i)
		errs = append(errs, validatePeers(rp.Child("to"), rule.To)...)
		errs = append(errs, validatePorts(rp.Child("ports"), rule.Ports)...)
	}
	for i, rule := range hf.Spec.Ingress {
		rp := field.NewPath("spec", "ingress").Index(i)
		errs = append(errs, validatePeers(rp.Child("from"), rule.From)...)
		errs = append(errs, validatePorts(rp.Child("ports"), rule.Ports)...)
	}
	return errs
}

func validatePeers(path *field.Path, peers []sdn.HostFirewallPeer) field.ErrorList {
	errs := field.ErrorList{}
	for j, peer := range peers {
		pp := path.Index(j)
		if _, _, err := net.ParseCIDR(peer.CIDR); err != nil {
			errs = append(errs, field.Invalid(pp.Child("cidr"), peer.CIDR, "must be a valid CIDR"))
		}
		for k, ex := range peer.Except {
			if _, _, err := net.ParseCIDR(ex); err != nil {
				errs = append(errs, field.Invalid(pp.Child("except").Index(k), ex, "must be a valid CIDR"))
			}
		}
	}
	return errs
}

func validatePorts(path *field.Path, ports []sdn.HostFirewallPort) field.ErrorList {
	errs := field.ErrorList{}
	for j, port := range ports {
		pp := path.Index(j)
		if port.Protocol != "TCP" && port.Protocol != "UDP" {
			errs = append(errs, field.NotSupported(pp.Child("protocol"), port.Protocol, []string{"TCP", "UDP"}))
		}
		if port.Port < 0 || port.Port > 65535 {
			errs = append(errs, field.Invalid(pp.Child("port"), port.Port, "must be 0-65535"))
		}
		if port.EndPort != 0 {
			switch {
			case port.Port == 0:
				errs = append(errs, field.Invalid(pp.Child("endPort"), port.EndPort, "requires port"))
			case port.EndPort < port.Port || port.EndPort > 65535:
				errs = append(errs, field.Invalid(pp.Child("endPort"), port.EndPort, "must be port-65535"))
			case int(port.EndPort)-int(port.Port)+1 > 64:
				errs = append(errs, field.Invalid(pp.Child("endPort"), port.EndPort, "ranges expand per-port and are capped at 64 ports"))
			}
		}
	}
	return errs
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (hostFirewallStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (hostFirewallStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (hostFirewallStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (hostFirewallStrategy) Canonicalize(obj runtime.Object) {
}

func (hostFirewallStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validateSpec(obj.(*sdn.HostFirewall))
}

// WarningsOnUpdate returns warnings for the given update.
func (hostFirewallStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// hostFirewallStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of hostFirewallStrategy).
type hostFirewallStatusStrategy struct {
	hostFirewallStrategy
}

// NewStatusStrategy creates a strategy for the HostFirewall status subresource.
func NewStatusStrategy(strategy hostFirewallStrategy) hostFirewallStatusStrategy {
	return hostFirewallStatusStrategy{strategy}
}

func (hostFirewallStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newHF := obj.(*sdn.HostFirewall)
	oldHF := old.(*sdn.HostFirewall)
	newHF.Spec = oldHF.Spec
}

func (hostFirewallStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (hostFirewallStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
