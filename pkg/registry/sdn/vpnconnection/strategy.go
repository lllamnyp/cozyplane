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

package vpnconnection

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

// GetAttrs returns labels.Set, fields.Set, and error in case the given runtime.Object is not a VPNConnection.
func GetAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	conn, ok := obj.(*sdn.VPNConnection)
	if !ok {
		return nil, nil, errors.New("given object is not a VPNConnection")
	}

	return labels.Set(conn.Labels), SelectableFields(conn), nil
}

// MatchVPNConnection is the filter used by the generic etcd backend to watch events
// from etcd to clients of the apiserver only interested in specific labels/fields.
func MatchVPNConnection(label labels.Selector, fieldSel fields.Selector) storage.SelectionPredicate {
	return storage.SelectionPredicate{
		Label:    label,
		Field:    fieldSel,
		GetAttrs: GetAttrs,
	}
}

// SelectableFields returns a field set that represents the object.
func SelectableFields(obj *sdn.VPNConnection) fields.Set {
	return generic.ObjectMetaFieldsSet(&obj.ObjectMeta, true)
}

type vpnConnectionStrategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// NewStrategy creates and returns a vpnConnectionStrategy instance.
func NewStrategy(typer runtime.ObjectTyper) vpnConnectionStrategy {
	return vpnConnectionStrategy{typer, names.SimpleNameGenerator}
}

func (vpnConnectionStrategy) NamespaceScoped() bool {
	return true
}

func (vpnConnectionStrategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	conn := obj.(*sdn.VPNConnection)
	conn.Status = sdn.VPNConnectionStatus{}
}

func (vpnConnectionStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newConn := obj.(*sdn.VPNConnection)
	oldConn := old.(*sdn.VPNConnection)
	newConn.Status = oldConn.Status
}

func (vpnConnectionStrategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validateVPNConnection(obj.(*sdn.VPNConnection))
}

// WarningsOnCreate returns warnings for the creation of the given object.
func (vpnConnectionStrategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string {
	return nil
}

func (vpnConnectionStrategy) AllowCreateOnUpdate() bool {
	return false
}

func (vpnConnectionStrategy) AllowUnconditionalUpdate() bool {
	return false
}

func (vpnConnectionStrategy) Canonicalize(obj runtime.Object) {
}

func (vpnConnectionStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validateVPNConnection(obj.(*sdn.VPNConnection))
}

func validateVPNConnection(conn *sdn.VPNConnection) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	if conn.Spec.GatewayRef.Name == "" {
		errs = append(errs, field.Required(specPath.Child("gatewayRef", "name"), "gateway name is required"))
	}
	for i, cidr := range conn.Spec.RemoteCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			errs = append(errs, field.Invalid(specPath.Child("remoteCIDRs").Index(i), cidr, "must be a valid CIDR"))
		}
	}
	backends := 0
	if conn.Spec.WireGuard != nil {
		backends++
	}
	if conn.Spec.IPsec != nil {
		backends++
	}
	if backends > 1 {
		errs = append(errs, field.Invalid(specPath, conn.Spec, "wireGuard and ipsec are mutually exclusive"))
	}
	if wireguard := conn.Spec.WireGuard; wireguard != nil {
		wgPath := specPath.Child("wireGuard")
		if wireguard.PeerPublicKey == "" && len(wireguard.PeerPublicKeys) == 0 {
			errs = append(errs, field.Required(wgPath.Child("peerPublicKey"), "one peer public key or an active-active pair is required"))
		}
		if wireguard.PeerPublicKey != "" && len(wireguard.PeerPublicKeys) > 0 {
			errs = append(errs, field.Invalid(wgPath, *wireguard, "peerPublicKey and peerPublicKeys are mutually exclusive"))
		}
		if len(wireguard.PeerPublicKeys) > 0 && len(wireguard.PeerPublicKeys) != 2 {
			errs = append(errs, field.Invalid(wgPath.Child("peerPublicKeys"), wireguard.PeerPublicKeys, "active-active requires exactly two keys"))
		}
		if wireguard.PeerEndpoint != "" && len(wireguard.PeerEndpoints) > 0 {
			errs = append(errs, field.Invalid(wgPath, *wireguard, "peerEndpoint and peerEndpoints are mutually exclusive"))
		}
		if len(wireguard.PeerEndpoints) > 0 && len(wireguard.PeerEndpoints) != len(wireguard.PeerPublicKeys) {
			errs = append(errs, field.Invalid(wgPath.Child("peerEndpoints"), wireguard.PeerEndpoints, "must contain one endpoint per peerPublicKeys entry"))
		}
		if len(wireguard.PeerPublicKeys) > 0 && wireguard.PeerEndpoint != "" {
			errs = append(errs, field.Invalid(wgPath.Child("peerEndpoint"), wireguard.PeerEndpoint, "use peerEndpoints with active-active peerPublicKeys"))
		}
	}
	if ipsec := conn.Spec.IPsec; ipsec != nil {
		startPath := specPath.Child("ipsec", "startAction")
		switch ipsec.StartAction {
		case "", sdn.VPNIPsecStartActionStart, sdn.VPNIPsecStartActionNone:
		default:
			errs = append(errs, field.NotSupported(startPath, ipsec.StartAction,
				[]string{string(sdn.VPNIPsecStartActionStart), string(sdn.VPNIPsecStartActionNone)}))
		}
		if ipsec.StartAction == sdn.VPNIPsecStartActionStart && ipsec.PeerAddress == "" {
			errs = append(errs, field.Required(specPath.Child("ipsec", "peerAddress"),
				"peerAddress is required when startAction is Start"))
		}
		if ipsec.DPDDelay < 0 {
			errs = append(errs, field.Invalid(specPath.Child("ipsec", "dpdDelay"), ipsec.DPDDelay, "must not be negative"))
		}
		authPath := specPath.Child("ipsec", "auth")
		authMethods := 0
		if ipsec.Auth.PSKSecretRef != "" {
			authMethods++
		}
		if ipsec.Auth.Certificate != nil {
			authMethods++
			if ipsec.Auth.Certificate.RemoteIdentity == "" {
				errs = append(errs, field.Required(authPath.Child("certificate", "remoteIdentity"),
					"remoteIdentity binds the connection to one certificate identity"))
			}
		}
		if ipsec.Auth.EAP != nil {
			authMethods++
			if ipsec.Auth.EAP.Identity == "" {
				errs = append(errs, field.Required(authPath.Child("eap", "identity"), "EAP identity is required"))
			}
			if ipsec.Auth.EAP.SecretRef == "" {
				errs = append(errs, field.Required(authPath.Child("eap", "secretRef"), "EAP password Secret is required"))
			}
			if ipsec.AddressPool == "" {
				errs = append(errs, field.Required(specPath.Child("ipsec", "addressPool"),
					"EAP roadwarrior connections require an address pool"))
			}
		}
		if authMethods > 1 {
			errs = append(errs, field.Invalid(authPath, ipsec.Auth,
				"pskSecretRef, certificate, and eap are mutually exclusive"))
		}
		if ipsec.AddressPool != "" {
			if ipsec.Auth.Certificate == nil && ipsec.Auth.EAP == nil {
				errs = append(errs, field.Invalid(specPath.Child("ipsec", "addressPool"), ipsec.AddressPool,
					"an address pool requires certificate or EAP authentication"))
			}
			if ipsec.StartAction == sdn.VPNIPsecStartActionStart {
				errs = append(errs, field.Invalid(startPath, ipsec.StartAction,
					"a pooled roadwarrior connection is responder-only"))
			}
		}
	}
	if wg := conn.Spec.WireGuard; wg != nil && wg.PersistentKeepalive < 0 {
		errs = append(errs, field.Invalid(specPath.Child("wireGuard", "persistentKeepalive"),
			wg.PersistentKeepalive, "must not be negative"))
	}
	return errs
}

// WarningsOnUpdate returns warnings for the given update.
func (vpnConnectionStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}

// vpnConnectionStatusStrategy is the update strategy for the /status subresource:
// it updates status but preserves spec (the mirror image of vpnConnectionStrategy).
type vpnConnectionStatusStrategy struct {
	vpnConnectionStrategy
}

// NewStatusStrategy creates a strategy for the VPNConnection status subresource.
func NewStatusStrategy(strategy vpnConnectionStrategy) vpnConnectionStatusStrategy {
	return vpnConnectionStatusStrategy{strategy}
}

func (vpnConnectionStatusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newConn := obj.(*sdn.VPNConnection)
	oldConn := old.(*sdn.VPNConnection)
	newConn.Spec = oldConn.Spec
}

func (vpnConnectionStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnConnectionStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
