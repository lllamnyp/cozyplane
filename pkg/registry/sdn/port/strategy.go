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

package port

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/lllamnyp/cozyplane/pkg/netid"

	"github.com/lllamnyp/cozyplane/api/sdn"
	sdnv1 "github.com/lllamnyp/cozyplane/api/sdn/v1alpha1"
	"github.com/lllamnyp/cozyplane/internal/ipam"
	"github.com/lllamnyp/cozyplane/pkg/registry/sdn/claim"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/storage"
	"k8s.io/apiserver/pkg/storage/names"
)

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a Port.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	port, ok := obj.(*sdn.Port)
	if !ok {
		return nil, nil, errors.New("given object is not a Port")
	}

	return labels.Set(port.Labels), SelectableFields(port), nil
}

// MatchPort is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchPort(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object. Ports are
// cluster-scoped, so the object-meta field set is built without a namespace.
func SelectableFields(obj *sdn.Port) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, false)
}

type portStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a portStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) portStrategy {
	return portStrategy{typer, names.SimpleNameGenerator}
}

func (portStrategy) NamespaceScoped() bool {
	return false
}

func (portStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	// Status (group membership) is controller-owned via the /status subresource.
	port := obj.(*sdn.Port)
	port.Status = sdn.PortStatus{}
}

func (portStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	// A spec update (e.g. the agent re-pointing spec.node at migration cutover)
	// must not clobber controller-owned status.
	newPort := obj.(*sdn.Port)
	oldPort := old.(*sdn.Port)
	newPort.Status = oldPort.Status
}

// Validate pins the name to the address claim: a Port must be named exactly
// v<vni>.<escaped spec.ip> with spec.ip in canonical form, or the name-based
// claim (and the registry's cross-kind twin check) could be spoofed by naming
// one address and using another.
func (portStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	port := obj.(*sdn.Port)
	var errs field.ErrorList
	if claim.IsPersistent(port) {
		for _, entry := range []struct {
			path  *field.Path
			value string
		}{
			{field.NewPath("spec", "podNamespace"), port.Spec.PodNamespace},
			{field.NewPath("spec", "vpcRef", "namespace"), port.Spec.VPCRef.Namespace},
			{field.NewPath("spec", "vpcRef", "name"), port.Spec.VPCRef.Name},
			{field.NewPath("metadata", "labels").Key(sdnv1.LabelVMNIC), port.Labels[sdnv1.LabelVMNIC]},
		} {
			if entry.value == "" {
				errs = append(errs, field.Required(entry.path, "persistent NIC identity must be complete"))
			}
		}
		mac, err := net.ParseMAC(port.Spec.MAC)
		if err != nil || len(mac) != 6 || mac[0]&1 != 0 {
			errs = append(errs, field.Invalid(field.NewPath("spec", "mac"), "", "persistent NIC requires a six-byte unicast MAC"))
		}
	}

	ip := net.ParseIP(port.Spec.IP)
	if ip == nil || ip.String() != port.Spec.IP {
		errs = append(errs, field.Invalid(field.NewPath("spec", "ip"), port.Spec.IP,
			"must be an IP address in canonical form"))
		return errs
	}
	if ipam.IsReserved(ip) {
		errs = append(errs, field.Invalid(field.NewPath("spec", "ip"), port.Spec.IP, "reserved platform bridge or hairpin address"))
	}
	vni, _, ok := sdn.ParseClaim(sdn.ClaimPrefixPort, port.Name)
	if !ok {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), port.Name,
			"must have the form v<vni>.<escaped spec.ip>: the name is the address claim"))
	} else if port.Name != sdn.PortName(vni, port.Spec.IP) {
		errs = append(errs, field.Invalid(field.NewPath("metadata", "name"), port.Name,
			fmt.Sprintf("must be %q (v<vni>.<escaped spec.ip>): the name is the address claim",
				sdn.PortName(vni, port.Spec.IP))))
	}
	return errs
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (portStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (portStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (portStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (portStrategy) Canonicalize(obj runtime.Object) {
}

// ValidateUpdate keeps the claimed address immutable: the (immutable) name is
// the claim on {VNI, spec.ip}, so neither the address nor the VPC it is
// scoped to may drift after create. Persistent NIC identity and MAC are pinned;
// node and launcher binding updates remain allowed during migration.
func (portStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	newPort := obj.(*sdn.Port)
	oldPort := old.(*sdn.Port)
	var errs field.ErrorList
	if newPort.Spec.IP != oldPort.Spec.IP {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "ip"),
			"immutable: the Port name is the claim on this address"))
	}
	if newPort.Spec.VPCRef != oldPort.Spec.VPCRef {
		errs = append(errs, field.Forbidden(field.NewPath("spec", "vpcRef"),
			"immutable: the claim is scoped to the VPC's VNI"))
	}
	return append(errs, validatePersistentUpdate(newPort, oldPort)...)
}

// WarningsOnUpdate returns warnings for the given update.
func (portStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// portStatusStrategy is the /status update strategy: it updates status but
// preserves spec (the mirror image of portStrategy).
type portStatusStrategy struct {
	portStrategy
}

// NewStatusStrategy creates a strategy for the Port status subresource.
func NewStatusStrategy(strategy portStrategy) portStatusStrategy {
	return portStatusStrategy{strategy}
}

func (portStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newPort := obj.(*sdn.Port)
	oldPort := old.(*sdn.Port)
	newPort.Spec = oldPort.Spec
}

func (portStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	groups := obj.(*sdn.Port).Status.Groups
	path := field.NewPath("status", "groups")
	if len(groups) > 63 {
		return field.ErrorList{field.TooMany(path, len(groups), 63)}
	}
	for i, id := range groups {
		if id != 0 && !netid.ValidGroup(id) {
			return field.ErrorList{field.Invalid(path.Index(i), id, "must be between 0 and 62")}
		}
	}

	return validatePersistentUpdate(obj.(*sdn.Port), old.(*sdn.Port))
}

func validatePersistentUpdate(next, old *sdn.Port) field.ErrorList {
	var errs field.ErrorList
	for _, key := range []string{sdnv1.LabelVMName, sdnv1.LabelVMNIC} {
		if next.Labels[key] != old.Labels[key] {
			errs = append(errs, field.Forbidden(field.NewPath("metadata", "labels").Key(key), "immutable persistent NIC identity"))
		}
	}
	if claim.IsPersistent(old) {
		if next.Spec.PodNamespace != old.Spec.PodNamespace {
			errs = append(errs, field.Forbidden(field.NewPath("spec", "podNamespace"), "immutable persistent NIC namespace"))
		}
		if next.Spec.MAC != old.Spec.MAC {
			errs = append(errs, field.Forbidden(field.NewPath("spec", "mac"), "immutable pinned MAC"))
		}
	}
	return errs
}

func (portStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
