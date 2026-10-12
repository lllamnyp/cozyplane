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
	"github.com/lllamnyp/cozyplane/internal/vpnlimits"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
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
	if wireGuardClientGatewayMode(gw) || gw.Spec.IPsec != nil {
		gw.Generation = 1
	}
}

func (vpnGatewayStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newGW := obj.(*sdn.VPNGateway)
	oldGW := old.(*sdn.VPNGateway)
	newGW.Status = oldGW.Status
	if wireGuardClientGatewayMode(newGW) || wireGuardClientGatewayMode(oldGW) || newGW.Spec.IPsec != nil || oldGW.Spec.IPsec != nil {
		newGW.Generation = oldGW.Generation
		if !apiequality.Semantic.DeepEqual(newGW.Spec, oldGW.Spec) {
			newGW.Generation++
		}
	}
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
	gw, previous := obj.(*sdn.VPNGateway), old.(*sdn.VPNGateway)
	client, wasClient := wireGuardClientGatewayMode(gw), wireGuardClientGatewayMode(previous)
	// Permit finalizer cleanup of an unchanged legacy client specification even
	// when stricter current validation would reject it on a new object.
	if wasClient && apiequality.Semantic.DeepEqual(gw.Spec, previous.Spec) {
		return nil
	}
	if client != wasClient {
		return field.ErrorList{field.Forbidden(field.NewPath("spec", "wireguard", "addressPools"), "client gateway mode is immutable; create a new gateway")}
	}
	return validateVPNGateway(gw)
}

func wireGuardClientGatewayMode(gw *sdn.VPNGateway) bool {
	return gw.Spec.WireGuard != nil && len(gw.Spec.WireGuard.AddressPools) != 0
}

func validateVPNGateway(gw *sdn.VPNGateway) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if len(gw.Spec.ExternalAddress.AddressClaimNames) > 2 {
		return field.ErrorList{field.TooMany(specPath.Child("externalAddress", "addressClaimNames"), len(gw.Spec.ExternalAddress.AddressClaimNames), 2)}
	}
	errs = append(errs, vpnlimits.ReferenceErrors(gw.Spec.VPCRef.Name, specPath.Child("vpcRef", "name"), true)...)
	errs = append(errs, vpnlimits.ReferenceErrors(gw.Spec.ExternalAddress.AddressClaimName, specPath.Child("externalAddress", "addressClaimName"), false)...)
	for i, name := range gw.Spec.ExternalAddress.AddressClaimNames {
		errs = append(errs, vpnlimits.ReferenceErrors(name, specPath.Child("externalAddress", "addressClaimNames").Index(i), true)...)
	}
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		errs = append(errs, vpnlimits.ReferenceErrors(ipsec.CredentialSecretRef, specPath.Child("ipsec", "credentialSecretRef"), false)...)
		errs = append(errs, vpnlimits.ReferenceErrors(ipsec.TrustedCASecretRef, specPath.Child("ipsec", "trustedCASecretRef"), false)...)
	}
	if ha := gw.Spec.HA; ha != nil && ha.VirtualMachine != nil {
		vm := ha.VirtualMachine
		errs = append(errs, vpnlimits.ReferenceErrors(vm.StateClaimName, specPath.Child("ha", "virtualMachine", "stateClaimName"), false)...)
		errs = append(errs, vpnlimits.ReferenceErrors(vm.CloudInitSecretRef, specPath.Child("ha", "virtualMachine", "cloudInitSecretRef"), false)...)
	}
	if len(errs) != 0 {
		return errs
	}
	if wg := gw.Spec.WireGuard; wg != nil {
		path := specPath.Child("wireguard")
		if wg.ListenPort < 0 || wg.ListenPort > 65535 {
			return field.ErrorList{field.Invalid(path.Child("listenPort"), nil, "must be between 0 and 65535")}
		}
		if len(wg.AddressPools) > vpnlimits.AddressPools {
			return field.ErrorList{field.TooMany(path.Child("addressPools"), len(wg.AddressPools), vpnlimits.AddressPools)}
		}
		pools := make([]vpnlimits.WireGuardAddressPool, len(wg.AddressPools))
		for i, pool := range wg.AddressPools {
			pools[i] = vpnlimits.WireGuardAddressPool{Name: pool.Name, CIDR: pool.CIDR, DNS: pool.DNS}
		}
		if problem := vpnlimits.WireGuardAddressPoolsProblem(pools); problem != "" {
			return field.ErrorList{field.Invalid(path.Child("addressPools"), nil, problem)}
		}
		if len(wg.AddressPools) != 0 && gw.Spec.HA != nil && gw.Spec.HA.Mode != sdn.VPNGatewayHAModeWarmStandby {
			return field.ErrorList{field.Forbidden(specPath.Child("ha", "mode"), "WireGuard client gateways support only single-appliance or WarmStandby mode")}
		}
	}
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		if problem := vpnlimits.IPsecScalarProblem("", ipsec.LocalIdentity); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("ipsec", "localIdentity"), nil, problem)}
		}
		if problem := vpnlimits.IPsecProposalProblem(ipsec.Proposals); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("ipsec", "proposals"), nil, problem)}
		}
		poolsPath := specPath.Child("ipsec", "addressPools")
		if len(ipsec.AddressPools) > vpnlimits.AddressPools {
			return field.ErrorList{field.TooMany(poolsPath, len(ipsec.AddressPools), vpnlimits.AddressPools)}
		}
		for i, pool := range ipsec.AddressPools {
			if problem := vpnlimits.IPsecPoolNameProblem(pool.Name, true); problem != "" {
				return field.ErrorList{field.Invalid(poolsPath.Index(i).Child("name"), nil, problem)}
			}
			if len(pool.DNS) > vpnlimits.PoolDNSServers {
				return field.ErrorList{field.TooMany(poolsPath.Index(i).Child("dns"), len(pool.DNS), vpnlimits.PoolDNSServers)}
			}
		}
	}
	if ha := gw.Spec.HA; ha != nil && ha.ActiveActive != nil && len(ha.ActiveActive.PeerAddresses) > vpnlimits.BGPNeighbors {
		return field.ErrorList{field.TooMany(specPath.Child("ha", "activeActive", "peerAddresses"), len(ha.ActiveActive.PeerAddresses), vpnlimits.BGPNeighbors)}
	}
	// AdditionalVPCRefs turn the gateway into a hub serving several same-namespace
	// VPCs (docs/vpn.md §3.3). The CNI caps attachments at 10 legs total, so at
	// most 9 additional VPCs are allowed alongside spec.vpcRef; entries must be
	// unique and distinct from spec.vpcRef.name, and the feature is incompatible
	// with the LiveMigration KubeVirt appliance, which only has one VPC leg.
	additionalPath := specPath.Child("additionalVPCRefs")
	if len(gw.Spec.AdditionalVPCRefs) > 9 {
		return field.ErrorList{field.TooMany(additionalPath, len(gw.Spec.AdditionalVPCRefs), 9)}
	}
	additionalNames := map[string]bool{}
	for i, ref := range gw.Spec.AdditionalVPCRefs {
		p := additionalPath.Index(i)
		if !vpnlimits.ObjectName(ref.Name) {
			return field.ErrorList{field.Invalid(p.Child("name"), nil, "must be a nonempty DNS subdomain name of at most 253 bytes")}
		}
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
		errs = append(errs, field.Invalid(specPath, nil, "wireGuard and ipsec are mutually exclusive"))
	}
	haPath := specPath.Child("ha")
	if gw.Spec.HighAvailability && gw.Spec.HA != nil {
		errs = append(errs, field.Invalid(haPath, nil,
			"ha and the legacy highAvailability flag are mutually exclusive"))
	}
	if ha := gw.Spec.HA; ha != nil {
		switch ha.Mode {
		case sdn.VPNGatewayHAModeWarmStandby:
			if ha.ActiveActive != nil || ha.VirtualMachine != nil {
				errs = append(errs, field.Invalid(haPath, nil, "WarmStandby accepts no mode-specific configuration"))
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
			errs = append(errs, field.Invalid(haPath.Child("mode"), nil, "must be WarmStandby, LiveMigration or ActiveActive"))
		}
	}
	if len(errs) != 0 {
		return errs
	}
	if ipsec := gw.Spec.IPsec; ipsec != nil {
		poolsPath := specPath.Child("ipsec", "addressPools")
		if len(ipsec.AddressPools) > 0 && gw.Spec.HA != nil && gw.Spec.HA.Mode == sdn.VPNGatewayHAModeActiveActive {
			return field.ErrorList{field.Forbidden(poolsPath, "ActiveActive IPsec appliances do not coordinate client address leases")}
		}
		names := map[string]int{}
		parsed := make([]*net.IPNet, 0, len(ipsec.AddressPools))
		for i, pool := range ipsec.AddressPools {
			p := poolsPath.Index(i)
			if pool.Name == "" {
				return field.ErrorList{field.Required(p.Child("name"), "pool name is required")}
			} else if previous, exists := names[pool.Name]; exists {
				return field.ErrorList{field.Invalid(p.Child("name"), nil, fmt.Sprintf("already used at index %d", previous))}
			} else {
				names[pool.Name] = i
			}
			if len(pool.CIDR) > vpnlimits.RoutePrefixBytes {
				return field.ErrorList{field.Invalid(p.Child("cidr"), nil, "must contain at most 64 bytes")}
			}
			_, network, err := net.ParseCIDR(pool.CIDR)
			if err != nil {
				return field.ErrorList{field.Invalid(p.Child("cidr"), nil, "must be a valid CIDR")}
			}
			for j, other := range parsed {
				if network.Contains(other.IP) || other.Contains(network.IP) {
					return field.ErrorList{field.Invalid(p.Child("cidr"), nil, fmt.Sprintf("overlaps addressPools[%d]", j))}
				}
			}
			parsed = append(parsed, network)
			for j, dns := range pool.DNS {
				if len(dns) > vpnlimits.RoutePrefixBytes || net.ParseIP(dns) == nil {
					return field.ErrorList{field.Invalid(p.Child("dns").Index(j), nil, "must be an IP address of at most 64 bytes")}
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
		if len(address) > vpnlimits.RoutePrefixBytes || net.ParseIP(address) == nil {
			return field.ErrorList{field.Invalid(path.Child("peerAddresses").Index(i), nil, "must be an IP address of at most 64 bytes")}
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
	if wireGuardClientGatewayMode(oldGW) || oldGW.Spec.IPsec != nil {
		newGW.Generation = oldGW.Generation
	}
}

func (vpnGatewayStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnGatewayStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
