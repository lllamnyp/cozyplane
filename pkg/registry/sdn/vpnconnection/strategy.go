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
	"slices"

	"github.com/lllamnyp/cozyplane/api/sdn"
	"github.com/lllamnyp/cozyplane/internal/vpnidentity"
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
	if wireGuardClientMode(conn) || conn.Spec.IPsec != nil {
		conn.Generation = 1
	}
}

func (vpnConnectionStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newConn := obj.(*sdn.VPNConnection)
	oldConn := old.(*sdn.VPNConnection)
	newConn.Status = oldConn.Status
	if wireGuardClientMode(newConn) || wireGuardClientMode(oldConn) || newConn.Spec.IPsec != nil || oldConn.Spec.IPsec != nil {
		newConn.Generation = oldConn.Generation
		if !apiequality.Semantic.DeepEqual(newConn.Spec, oldConn.Spec) {
			newConn.Generation++
		}
	}
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
	conn, previous := obj.(*sdn.VPNConnection), old.(*sdn.VPNConnection)
	if wireGuardClientMode(previous) && apiequality.Semantic.DeepEqual(conn.Spec, previous.Spec) {
		return nil
	}
	if errs := validateVPNConnection(conn); len(errs) != 0 {
		return errs
	}
	client := func(c *sdn.VPNConnection) *sdn.VPNWireGuardClient {
		if c.Spec.WireGuard != nil {
			return c.Spec.WireGuard.Client
		}
		return nil
	}
	currentClient, oldClient := client(conn), client(previous)
	if (currentClient == nil) != (oldClient == nil) {
		return field.ErrorList{field.Forbidden(field.NewPath("spec", "wireguard", "client"), "client mode is immutable; create a new connection")}
	}
	if oldClient != nil {
		if conn.Spec.GatewayRef.Name != previous.Spec.GatewayRef.Name {
			return field.ErrorList{field.Forbidden(field.NewPath("spec", "gatewayRef"), "client gateway is immutable; create a new connection")}
		}
		if !slices.Equal(currentClient.AddressPools, oldClient.AddressPools) {
			return field.ErrorList{field.Forbidden(field.NewPath("spec", "wireguard", "client", "addressPools"), "client pools are immutable; create a new connection")}
		}
	}
	return nil
}

func wireGuardClientMode(conn *sdn.VPNConnection) bool {
	return conn.Spec.WireGuard != nil && conn.Spec.WireGuard.Client != nil
}

func validateVPNConnection(conn *sdn.VPNConnection) field.ErrorList {
	var errs field.ErrorList
	specPath := field.NewPath("spec")
	errs = append(errs, vpnlimits.ReferenceErrors(conn.Spec.GatewayRef.Name, specPath.Child("gatewayRef", "name"), true)...)
	if wg := conn.Spec.WireGuard; wg != nil {
		errs = append(errs, vpnlimits.ReferenceErrors(wg.PresharedKeySecretRef, specPath.Child("wireGuard", "presharedKeySecretRef"), false)...)
	}
	if ipsec := conn.Spec.IPsec; ipsec != nil {
		auth := specPath.Child("ipsec", "auth")
		errs = append(errs, vpnlimits.ReferenceErrors(ipsec.Auth.PSKSecretRef, auth.Child("pskSecretRef"), false)...)
		if eap := ipsec.Auth.EAP; eap != nil {
			errs = append(errs, vpnlimits.ReferenceErrors(eap.SecretRef, auth.Child("eap", "secretRef"), true)...)
		}
	}
	if len(errs) != 0 {
		return errs
	}
	if ipsec := conn.Spec.IPsec; ipsec != nil {
		certificate, eap := "", ""
		if problem := vpnlimits.IPsecPoolNameProblem(ipsec.AddressPool, false); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("ipsec", "addressPool"), nil, problem)}
		}
		if ipsec.Auth.Certificate != nil {
			certificate = ipsec.Auth.Certificate.RemoteIdentity
		}
		if ipsec.Auth.EAP != nil {
			eap = ipsec.Auth.EAP.Identity
		}
		if problem := vpnlimits.IPsecScalarProblem(ipsec.PeerAddress, ipsec.RemoteIdentity, certificate, eap); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("ipsec"), nil, problem)}
		}
		if problem := vpnlimits.IPsecProposalProblem(ipsec.Proposals); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("ipsec", "proposals"), nil, problem)}
		}
	}
	if wg := conn.Spec.WireGuard; wg != nil {
		if client := wg.Client; client != nil {
			if len(client.VPCRefs) > 10 {
				return field.ErrorList{field.TooMany(specPath.Child("wireguard", "client", "vpcRefs"), len(client.VPCRefs), 10)}
			}
			names := make([]string, len(client.VPCRefs))
			for i, ref := range client.VPCRefs {
				names[i] = ref.Name
			}
			if problem := vpnlimits.WireGuardClientProblem(vpnlimits.WireGuardPeer{
				PublicKey: wg.PeerPublicKey, PublicKeys: wg.PeerPublicKeys,
				Endpoint: wg.PeerEndpoint, Endpoints: wg.PeerEndpoints, Keepalive: int64(wg.PersistentKeepalive),
			}, client.AddressPools, names, conn.Spec.RemoteCIDRs); problem != "" {
				return field.ErrorList{field.Invalid(specPath.Child("wireguard", "client"), nil, problem)}
			}
		}
		if problem := vpnlimits.WireGuardPeerProblem(vpnlimits.WireGuardPeer{
			PublicKey: wg.PeerPublicKey, PublicKeys: wg.PeerPublicKeys,
			Endpoint: wg.PeerEndpoint, Endpoints: wg.PeerEndpoints, Keepalive: int64(wg.PersistentKeepalive),
		}); problem != "" {
			return field.ErrorList{field.Invalid(specPath.Child("wireGuard"), nil, problem)}
		}
	}
	if len(conn.Spec.RemoteCIDRs) > vpnlimits.RoutePrefixes {
		return field.ErrorList{field.TooMany(specPath.Child("remoteCIDRs"), len(conn.Spec.RemoteCIDRs), vpnlimits.RoutePrefixes)}
	}
	for i, cidr := range conn.Spec.RemoteCIDRs {
		if len(cidr) > vpnlimits.RoutePrefixBytes {
			return field.ErrorList{field.Invalid(specPath.Child("remoteCIDRs").Index(i), nil, "must contain at most 64 bytes")}
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return field.ErrorList{field.Invalid(specPath.Child("remoteCIDRs").Index(i), nil, "must be a valid CIDR")}
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
		errs = append(errs, field.Invalid(specPath, nil, "wireGuard and ipsec are mutually exclusive"))
	}
	if ipsec := conn.Spec.IPsec; ipsec != nil {
		startPath := specPath.Child("ipsec", "startAction")
		switch ipsec.StartAction {
		case "", sdn.VPNIPsecStartActionStart, sdn.VPNIPsecStartActionNone:
		default:
			errs = append(errs, field.Invalid(startPath, nil, "must be Start or None"))
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
			identity := ipsec.RemoteIdentity
			if identity == "" {
				if ip := net.ParseIP(ipsec.PeerAddress); ip != nil {
					identity = ip.String()
				}
			}
			if !exactIdentity(identity) {
				errs = append(errs, field.Invalid(specPath.Child("ipsec", "remoteIdentity"), identity, "PSK authentication requires an exact remote identity or IP peerAddress"))
			}
		}
		if ipsec.Auth.Certificate != nil {
			authMethods++
			if !exactIdentity(ipsec.Auth.Certificate.RemoteIdentity) {
				errs = append(errs, field.Invalid(authPath.Child("certificate", "remoteIdentity"), ipsec.Auth.Certificate.RemoteIdentity,
					"remoteIdentity binds the connection to one certificate identity"))
			}
		}
		if ipsec.Auth.EAP != nil {
			authMethods++
			if !exactIdentity(ipsec.Auth.EAP.Identity) {
				errs = append(errs, field.Invalid(authPath.Child("eap", "identity"), ipsec.Auth.EAP.Identity, "an exact EAP identity is required"))
			}
			if ipsec.Auth.EAP.SecretRef == "" {
				errs = append(errs, field.Required(authPath.Child("eap", "secretRef"), "EAP password Secret is required"))
			}
			if ipsec.AddressPool == "" {
				errs = append(errs, field.Required(specPath.Child("ipsec", "addressPool"),
					"EAP roadwarrior connections require an address pool"))
			}
		}
		if authMethods != 1 {
			errs = append(errs, field.Invalid(authPath, nil,
				"exactly one of pskSecretRef, certificate, and eap is required"))
		}
		if ipsec.AddressPool != "" {
			if ipsec.Auth.Certificate == nil && ipsec.Auth.EAP == nil {
				errs = append(errs, field.Invalid(specPath.Child("ipsec", "addressPool"), nil,
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
func exactIdentity(identity string) bool {
	return vpnidentity.Exact(identity)
}

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
	if wireGuardClientMode(oldConn) || oldConn.Spec.IPsec != nil {
		newConn.Generation = oldConn.Generation
	}
}

func (vpnConnectionStatusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

func (vpnConnectionStatusStrategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string {
	return nil
}
