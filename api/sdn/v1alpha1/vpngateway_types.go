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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPNGatewayPhase is the lifecycle phase of a VPNGateway.
type VPNGatewayPhase string

// VPNGatewayHAMode selects the failure model of the managed appliance.
type VPNGatewayHAMode string

const (
	// VPNGatewayPhasePending means the tunnel endpoint is declared but not yet
	// realized (no external address, or the appliance is not up).
	VPNGatewayPhasePending VPNGatewayPhase = "Pending"
	// VPNGatewayPhaseReady means the endpoint has an address and is serving.
	VPNGatewayPhaseReady VPNGatewayPhase = "Ready"
)

const (
	// VPNGatewayHAModeWarmStandby runs two pods but exposes one selected endpoint.
	VPNGatewayHAModeWarmStandby VPNGatewayHAMode = "WarmStandby"
	// VPNGatewayHAModeLiveMigration runs the appliance as a migratable KubeVirt VM.
	VPNGatewayHAModeLiveMigration VPNGatewayHAMode = "LiveMigration"
	// VPNGatewayHAModeActiveActive runs two tunnel endpoints and ECMP next-hops.
	VPNGatewayHAModeActiveActive VPNGatewayHAMode = "ActiveActive"
)

// VPNGatewayActiveActive configures the remote dynamic-routing contract. FRR
// runs beside each tunnel appliance in the same network namespace.
type VPNGatewayActiveActive struct {
	// LocalASN is the private or public ASN advertised by both appliances.
	LocalASN int64 `json:"localASN"`
	// PeerASN is the remote router's ASN.
	PeerASN int64 `json:"peerASN"`
	// PeerAddresses are BGP neighbor addresses reachable through the tunnels.
	// +listType=atomic
	PeerAddresses []string `json:"peerAddresses"`
	// BFD enables fast failure detection for every neighbor.
	// +optional
	BFD bool `json:"bfd,omitempty"`
}

// VPNGatewayVirtualMachine configures the managed KubeVirt appliance form
// factor. The image must be a bootable containerDisk built from images/vpn-appliance.
type VPNGatewayVirtualMachine struct {
	Image string `json:"image"`
	// StateClaimName is an existing RWX PVC used by both migration endpoints.
	StateClaimName string `json:"stateClaimName"`
	// CloudInitSecretRef optionally names operator-managed user data. Empty uses
	// controller-generated cloud-init containing the current tunnel config.
	// +optional
	CloudInitSecretRef string `json:"cloudInitSecretRef,omitempty"`
}

// VPNGatewayHA configures one explicit HA tier.
type VPNGatewayHA struct {
	Mode VPNGatewayHAMode `json:"mode"`
	// ActiveActive is required with mode ActiveActive.
	// +optional
	ActiveActive *VPNGatewayActiveActive `json:"activeActive,omitempty"`
	// VirtualMachine is required with mode LiveMigration.
	// +optional
	VirtualMachine *VPNGatewayVirtualMachine `json:"virtualMachine,omitempty"`
}

// Condition types surfaced in VPNGateway status.
const (
	// VPNGatewayConditionApplianceReady is True when the tunnel-termination
	// appliance is running and holds a Port in the VPC.
	VPNGatewayConditionApplianceReady = "ApplianceReady"
	// VPNGatewayConditionAddressAssigned is True when the tunnel endpoint's
	// FloatingIP has an assigned external address.
	VPNGatewayConditionAddressAssigned = "AddressAssigned"
	// VPNGatewayConditionRoutesProgrammed is True when the VPC route table
	// carries the connections' remote CIDRs toward this gateway.
	VPNGatewayConditionRoutesProgrammed = "RoutesProgrammed"
	// VPNGatewayConditionRemoteCIDRsAccepted is False when a connection declared a
	// remote CIDR overlapping cluster-internal space (pod/service/node/link-local/
	// loopback/multicast). Such a CIDR is refused — it is never added to the
	// forwarding grant or the route table — so a tenant cannot redirect the VPC's
	// own internal traffic into a tunnel (the increment-6 route-CIDR deny-set).
	VPNGatewayConditionRemoteCIDRsAccepted = "RemoteCIDRsAccepted"
)

// VPNGatewayWireGuard configures a WireGuard tunnel endpoint.
type VPNGatewayWireGuard struct {
	// ListenPort is the UDP port the WireGuard endpoint listens on. Zero lets
	// the appliance pick the default.
	// +optional
	ListenPort int32 `json:"listenPort,omitempty"`
}

// VPNGatewayIPsec configures an IPsec (IKEv2) tunnel endpoint terminated by a
// strongSwan appliance (docs/vpn.md §3.2). Its presence selects the IPsec
// backend; the appliance runs charon (route-based, xfrm-interface) rather than
// WireGuard. IKE listens on the fixed UDP 500/4500 — no listen port to pick.
type VPNGatewayIPsec struct {
	// Proposals are the default IKE/ESP proposals for connections that do not set
	// their own (strongSwan proposal syntax, e.g. "aes256-sha256-modp2048").
	// Empty lets charon negotiate its defaults.
	// +optional
	// +listType=atomic
	Proposals []string `json:"proposals,omitempty"`

	// CredentialSecretRef names a cert-manager-compatible TLS Secret containing
	// tls.crt and tls.key. ca.crt in the same Secret is accepted as the trust
	// anchor when TrustedCASecretRef is empty.
	// +optional
	CredentialSecretRef string `json:"credentialSecretRef,omitempty"`

	// TrustedCASecretRef names a Secret containing ca.crt used to authenticate
	// certificate-based remote peers.
	// +optional
	TrustedCASecretRef string `json:"trustedCASecretRef,omitempty"`

	// LocalIdentity is the IKE identity presented by the gateway. Empty lets
	// strongSwan derive it from the selected certificate.
	// +optional
	LocalIdentity string `json:"localIdentity,omitempty"`

	// AddressPools are non-overlapping virtual-IP pools available to roadwarrior
	// connections. A connection selects one by name.
	// +optional
	// +listType=map
	// +listMapKey=name
	AddressPools []VPNIPsecAddressPool `json:"addressPools,omitempty"`
}

// VPNIPsecAddressPool is a strongSwan-managed virtual-IP pool. Leases are
// identity-bound by strongSwan and disappear when the corresponding
// VPNConnection credential is revoked.
type VPNIPsecAddressPool struct {
	// Name is unique within the gateway.
	Name string `json:"name"`

	// CIDR is the address range allocated to clients and routed to the appliance.
	CIDR string `json:"cidr"`

	// DNS lists optional DNS servers pushed to clients.
	// +optional
	// +listType=atomic
	DNS []string `json:"dns,omitempty"`
}

// VPNExternalAddress selects the tunnel endpoint's external (public) address —
// the address a remote peer dials. Reused verbatim from the FloatingIP model:
// cozyplane allocates nothing, it consumes what the LB implementation assigns.
type VPNExternalAddress struct {
	// LoadBalancerClass selects which LB implementation allocates and attracts
	// the endpoint address. Empty uses the cluster default.
	// +optional
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`

	// AddressClaimName names an IPAddressClaim reservation whose address the
	// endpoint should wear. Reserving it matters for IPsec, whose remote peer
	// pins the endpoint address (docs/vpn.md §3.2). Empty means dynamic.
	// +optional
	AddressClaimName string `json:"addressClaimName,omitempty"`

	// AddressClaimNames reserves one stable endpoint per active-active appliance.
	// It must contain exactly two distinct names in ActiveActive mode.
	// +optional
	// +listType=atomic
	AddressClaimNames []string `json:"addressClaimNames,omitempty"`
}

// VPNGatewaySpec declares a managed tunnel endpoint for a VPC (issue #6).
type VPNGatewaySpec struct {
	// VPCRef is the VPC this gateway terminates tunnels into, in this namespace.
	// It is the PRIMARY served VPC: the appliance's default route, its endpoint
	// FloatingIP and the tunnel MTU budget all belong to it.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// AdditionalVPCRefs are further VPCs this gateway serves (hub, docs/vpn.md
	// §3.3): every connection's remoteCIDRs are routed into each of them, and
	// each of them reaches every connection's remote sites. Same namespace as the
	// gateway. Served VPCs' CIDRs must be pairwise disjoint. Forbidden with
	// ha.mode=LiveMigration.
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=9
	AdditionalVPCRefs []LocalVPCRef `json:"additionalVPCRefs,omitempty"`

	// WireGuard configures a WireGuard endpoint. Exactly one tunnel backend is
	// set per gateway.
	// +optional
	WireGuard *VPNGatewayWireGuard `json:"wireguard,omitempty"`

	// IPsec configures an IKEv2/strongSwan endpoint — the enterprise-interop
	// backend (issue #6). Exactly one of WireGuard or IPsec is set.
	// +optional
	IPsec *VPNGatewayIPsec `json:"ipsec,omitempty"`

	// ExternalAddress is the public endpoint a remote peer dials.
	// +optional
	ExternalAddress VPNExternalAddress `json:"externalAddress,omitempty"`

	// HighAvailability runs the tunnel appliance as a warm standby pair on
	// distinct nodes (anti-affinity, same identity) instead of a single replica
	// (docs/vpn.md §3.5, tier 2). A node loss then costs one handshake, not a
	// reschedule: the controller's oldest-wins Port resolution re-targets the
	// FloatingIP and the route to the survivor. The crash-zero-drop tier
	// (dual-tunnel + BGP) is a later increment.
	// +optional
	HighAvailability bool `json:"highAvailability,omitempty"`

	// HA selects an explicit availability tier. When absent,
	// highAvailability=true retains the legacy WarmStandby behavior.
	// +optional
	HA *VPNGatewayHA `json:"ha,omitempty"`
}

// VPNGatewayStatus is the observed state of a VPNGateway.
type VPNGatewayStatus struct {
	// Address is the assigned external endpoint address — what a tenant reads
	// out to configure the remote peer.
	// +optional
	Address string `json:"address,omitempty"`

	// Addresses are all active public endpoints. Address remains the first entry
	// for compatibility with single-endpoint clients.
	// +optional
	// +listType=atomic
	Addresses []string `json:"addresses,omitempty"`

	// PublicKey is the WireGuard public key of this gateway's endpoint, which the
	// tenant configures the remote peer with. The private key stays in a Secret
	// the appliance mounts; only the public half is surfaced.
	// +optional
	PublicKey string `json:"publicKey,omitempty"`

	// PublicKeys are the WireGuard identities of all active-active endpoints.
	// PublicKey remains the first entry for compatibility.
	// +optional
	// +listType=atomic
	PublicKeys []string `json:"publicKeys,omitempty"`

	// AppliancePort is the cluster-scoped Port name of the tunnel appliance's
	// leg in the VPC — the next-hop the connections' routes resolve to.
	// +optional
	AppliancePort string `json:"appliancePort,omitempty"`

	// AppliancePorts are all ready route next-hops. AppliancePort remains the
	// first entry for compatibility.
	// +optional
	// +listType=atomic
	AppliancePorts []string `json:"appliancePorts,omitempty"`

	// Routes reports the connections' remote CIDRs and the Port they are
	// programmed toward, merged into the VPC route table by the agent (the same
	// shape VPCGateway.status.routes uses).
	// +optional
	// +listType=atomic
	Routes []VPCGatewayRouteStatus `json:"routes,omitempty"`

	// Phase is the lifecycle phase.
	// +optional
	Phase VPNGatewayPhase `json:"phase,omitempty"`

	// Conditions is the detailed state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.address`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPNGateway is a managed tunnel endpoint for a VPC (issue #6): the controller
// runs the tunnel-termination appliance, gives it a FloatingIP endpoint, grants
// its Port the scoped forwarding right, and routes the connections' remote
// CIDRs to it. The crypto lives in the appliance's netns; cozyplane provides
// identity, delivery, routing, policy and metering around it (docs/vpn.md §3.2).
type VPNGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPNGatewaySpec   `json:"spec,omitempty"`
	Status VPNGatewayStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPNGatewayList contains a list of VPNGateway.
type VPNGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPNGateway `json:"items"`
}
