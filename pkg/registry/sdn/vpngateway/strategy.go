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

package vpngateway

import (
	"context"
	"errors"
	"fmt"
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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPNGateway.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	gw, ok := obj.(*sdn.VPNGateway)
	if !ok {
		return nil, nil, errors.New("given object is not a VPNGateway")
	}

	return labels.Set(gw.Labels), SelectableFields(gw), nil
}

// MatchVPNGateway is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPNGateway(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.VPNGateway) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpnGatewayStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpnGatewayStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) vpnGatewayStrategy {
	return vpnGatewayStrategy{typer, names.SimpleNameGenerator}
}

func (vpnGatewayStrategy) NamespaceScoped() bool {
	return true
}

func (vpnGatewayStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	gw := obj.(*sdn.VPNGateway)
	gw.Status = sdn.VPNGatewayStatus{}
}

func (vpnGatewayStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGW := obj.(*sdn.VPNGateway)
	oldGW := old.(*sdn.VPNGateway)
	newGW.Status = oldGW.Status
}

func (vpnGatewayStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateVPNGateway(obj.(*sdn.VPNGateway))
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpnGatewayStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpnGatewayStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpnGatewayStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpnGatewayStrategy) Canonicalize(obj runtime.Object) {
}

func (vpnGatewayStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validateVPNGateway(obj.(*sdn.VPNGateway))
}

func validateVPNGateway(gw *sdn.VPNGateway) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if gw.Spec.VPCRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("vpcRef", "name"), "VPC name is required"))
	}
	// AdditionalVPCRefs turn the gateway into a hub serving several same-namespace
	// VPCs (docs/vpn.md §3.3). The CNI caps attachments at 10 legs total, so at
	// most 9 additional VPCs are allowed alongside spec.vpcRef; entries must be
	// unique and distinct from spec.vpcRef.name, and the feature is incompatible
	// with the LiveMigration KubeVirt appliance, which only has one VPC leg.
	additionalPath := specPath.Child("additionalVPCRefs")
	if len(gw.Spec.AdditionalVPCRefs) > 9 {
		errs = append(errs, field.TooMany(additionalPath, len(gw.Spec.AdditionalVPCRefs), 9))
	}
	additionalNames := map[string]bool{}
	for i, ref := range gw.Spec.AdditionalVPCRefs {
		p := additionalPath.Index(i)
		if ref.Name == "" {
			errs = append(errs, field.Required(p.Child("name"), "VPC name is required"))
			continue
		}
		if ref.Name == gw.Spec.VPCRef.Name {
			errs = append(errs, field.Invalid(p.Child("name"), ref.Name, "must differ from spec.vpcRef.name"))
		}
		if additionalNames[ref.Name] {
			errs = append(errs, field.Duplicate(p.Child("name"), ref.Name))
		}
		additionalNames[ref.Name] = true
	}
	if gw.Spec.HA != nil && gw.Spec.HA.Mode == sdn.VPNGatewayHAModeLiveMigration && len(gw.Spec.AdditionalVPCRefs) > 0 {
		errs = append(errs, field.Forbidden(additionalPath,
			"not supported with ha.mode=LiveMigration: the KubeVirt appliance has a single VPC leg"))
	}
	backends := 0
	if gw.Spec.WireGuard != nil {
		backends++
	}
	if gw.Spec.IPsec != nil {
		backends++
	}
	if backends > 1 {
		errs = append(errs, field.Invalid(specPath, gw.Spec, "wireGuard and ipsec are mutually exclusive"))
	}
	haPath := specPath.Child("ha")
	if gw.Spec.HighAvailability && gw.Spec.HA != nil {
		errs = append(errs, field.Invalid(haPath, gw.Spec.HA,
			"ha and the legacy highAvailability flag are mutually exclusive"))
	}
	if ha := gw.Spec.HA; ha != nil {
		switch ha.Mode {
		case sdn.VPNGatewayHAModeWarmStandby:
			if ha.ActiveActive != nil || ha.VirtualMachine != nil {
				errs = append(errs, field.Invalid(haPath, ha, "WarmStandby accepts no mode-specific configuration"))
			}
		case sdn.VPNGatewayHAModeActiveActive:
			if ha.ActiveActive == nil {
				errs = append(errs, field.Required(haPath.Child("activeActive"), "ActiveActive configuration is required"))
			} else {
				errs = append(errs, validateActiveActive(ha.ActiveActive, haPath.Child("activeActive"))...)
			}
			if ha.VirtualMachine != nil {
				errs = append(errs, field.Forbidden(haPath.Child("virtualMachine"), "only valid with LiveMigration"))
			}
			claims := gw.Spec.ExternalAddress.AddressClaimNames
			if gw.Spec.ExternalAddress.AddressClaimName != "" {
				errs = append(errs, field.Forbidden(specPath.Child("externalAddress", "addressClaimName"),
					"ActiveActive uses addressClaimNames"))
			}
			if len(claims) != 0 && len(claims) != 2 {
				errs = append(errs, field.Invalid(specPath.Child("externalAddress", "addressClaimNames"), claims,
					"must be empty for dynamic allocation or contain exactly two claims"))
			}
			if len(claims) == 2 && claims[0] == claims[1] {
				errs = append(errs, field.Duplicate(specPath.Child("externalAddress", "addressClaimNames").Index(1), claims[1]))
			}
		case sdn.VPNGatewayHAModeLiveMigration:
			if ha.VirtualMachine == nil {
				errs = append(errs, field.Required(haPath.Child("virtualMachine"), "LiveMigration VM configuration is required"))
			} else {
				vmPath := haPath.Child("virtualMachine")
				if ha.VirtualMachine.Image == "" {
					errs = append(errs, field.Required(vmPath.Child("image"), "bootable containerDisk image is required"))
				}
				if ha.VirtualMachine.StateClaimName == "" {
					errs = append(errs, field.Required(vmPath.Child("stateClaimName"), "RWX state PVC is required"))
				}
			}
			if ha.ActiveActive != nil {
				errs = append(errs, field.Forbidden(haPath.Child("activeActive"), "only valid with ActiveActive"))
			}
		default:
			errs = append(errs, field.NotSupported(haPath.Child("mode"), ha.Mode, []string{
				string(sdn.VPNGatewayHAModeWarmStandby), string(sdn.VPNGatewayHAModeLiveMigration), string(sdn.VPNGatewayHAModeActiveActive),
			}))
		}
	}
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		poolsPath := specPath.Child("ipsec", "addressPools")
		names := map[string]int{}
		parsed := make([]*net.IPNet, 0, len(ipsec.AddressPools))
		for i, pool := range ipsec.AddressPools {
			p := poolsPath.Index(i)
			if pool.Name == "" {
				errs = append(errs, field.Required(p.Child("name"), "pool name is required"))
			} else if previous, exists := names[pool.Name]; exists {
				errs = append(errs, field.Duplicate(p.Child("name"),
					fmt.Sprintf("%s (already used at index %d)", pool.Name, previous)))
			} else {
				names[pool.Name] = i
			}
			_, network, err := net.ParseCIDR(pool.CIDR)
			if err != nil {
				errs = append(errs, field.Invalid(p.Child("cidr"), pool.CIDR, "must be a valid CIDR"))
				continue
			}
			for j, other := range parsed {
				if network.Contains(other.IP) || other.Contains(network.IP) {
					errs = append(errs, field.Invalid(p.Child("cidr"), pool.CIDR,
						fmt.Sprintf("overlaps addressPools[%d]", j)))
				}
			}
			parsed = append(parsed, network)
			for j, dns := range pool.DNS {
				if net.ParseIP(dns) == nil {
					errs = append(errs, field.Invalid(p.Child("dns").Index(j), dns, "must be an IP address"))
				}
			}
		}
		if len(ipsec.AddressPools) > 0 && ipsec.CredentialSecretRef == "" {
			errs = append(errs, field.Required(specPath.Child("ipsec", "credentialSecretRef"),
				"roadwarrior pools require a gateway TLS credential"))
		}
	}
	return errs
}

func validateActiveActive(aa *sdn.VPNGatewayActiveActive, path *field.Path) field.ErrorList {
	var errs field.ErrorList
	const maxASN = int64(4294967295)
	if aa.LocalASN < 1 || aa.LocalASN > maxASN {
		errs = append(errs, field.Invalid(path.Child("localASN"), aa.LocalASN, "must be between 1 and 4294967295"))
	}
	if aa.PeerASN < 1 || aa.PeerASN > maxASN {
		errs = append(errs, field.Invalid(path.Child("peerASN"), aa.PeerASN, "must be between 1 and 4294967295"))
	}
	if len(aa.PeerAddresses) == 0 {
		errs = append(errs, field.Required(path.Child("peerAddresses"), "at least one BGP neighbor is required"))
	}
	for i, address := range aa.PeerAddresses {
		if net.ParseIP(address) == nil {
			errs = append(errs, field.Invalid(path.Child("peerAddresses").Index(i), address, "must be an IP address"))
		}
	}
	return errs
}

// WarningsOnUpdate returns warnings for the given update.
func (vpnGatewayStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpnGatewayStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpnGatewayStrategy).
type vpnGatewayStatusStrategy struct {
	vpnGatewayStrategy
}

// NewStatusStrategy creates a strategy for the VPNGateway status subresource.
func NewStatusStrategy(strategy vpnGatewayStrategy) vpnGatewayStatusStrategy {
	return vpnGatewayStatusStrategy{strategy}
}

func (vpnGatewayStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGW := obj.(*sdn.VPNGateway)
	oldGW := old.(*sdn.VPNGateway)
	newGW.Spec = oldGW.Spec
}

func (vpnGatewayStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnGatewayStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
