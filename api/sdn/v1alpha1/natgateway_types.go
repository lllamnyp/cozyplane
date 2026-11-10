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

// Condition types surfaced in NATGateway status (docs/vpc-egress.md §2.1).
const (
	// NATGatewayConditionVPCResolved is True when spec.vpcRef names a realized
	// VPC in this namespace.
	NATGatewayConditionVPCResolved = "VPCResolved"
	// NATGatewayConditionAddressAssigned is True when every family the NAT
	// gateway serves has an address. When False, the message names each family
	// that has none and why.
	NATGatewayConditionAddressAssigned = "AddressAssigned"
	// NATGatewayConditionCapacityAvailable is False when every port block of
	// the NAT gateway is leased (docs/vpc-egress.md §4.3).
	NATGatewayConditionCapacityAvailable = "CapacityAvailable"
)

// Reasons for a family without an address (docs/vpc-egress.md §2.1).
const (
	NATGatewayReasonClaimNotFound      = "ClaimNotFound"
	NATGatewayReasonClaimNotBound      = "ClaimNotBound"
	NATGatewayReasonClaimFamilyMissing = "ClaimFamilyMissing"
	NATGatewayReasonClaimNotAttached   = "ClaimNotAttached"
	NATGatewayReasonFamilyNotInVPC     = "FamilyNotInVPC"
	NATGatewayReasonAddressPending     = "AddressPending"
)

// NATGatewaySpec declares a many-to-one egress identity for a VPC.
type NATGatewaySpec struct {
	// VPCRef is the VPC this NAT gateway serves, in this namespace. Immutable.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// LoadBalancerClass selects the load-balancer implementation that assigns and
	// attracts the addresses. Empty uses the cluster's default.
	// +optional
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`

	// AddressClaimName names the IPAddressClaim (local.sdn.cozystack.io) whose
	// IPv4 address this NAT gateway wears. AddressClaimName6 names the claim whose
	// IPv6 address it wears; both may name the same dual-stack claim. With
	// neither set, the NAT gateway serves every family of the VPC with addresses
	// the LB implementation assigns; with either set, it serves exactly the
	// families whose field is set (docs/vpc-egress.md §2.1).
	// +optional
	AddressClaimName string `json:"addressClaimName,omitempty"`
	// +optional
	AddressClaimName6 string `json:"addressClaimName6,omitempty"`
}

// NATGatewayBlocks summarizes the NAT gateway's port-block leases.
type NATGatewayBlocks struct {
	// Leased is the number of blocks some node holds.
	Leased int32 `json:"leased"`
	// Free is the number of blocks no node holds.
	Free int32 `json:"free"`
}

// NATGatewayStatus is the observed state of a NATGateway.
type NATGatewayStatus struct {
	// ID is the cluster-unique datapath identifier of this NAT gateway,
	// allocated by the controller (1..65535). Zero means unallocated.
	// +optional
	ID int32 `json:"id,omitempty"`
	// Address is the IPv4 address the NAT gateway's v4 egress wears. Empty means
	// none.
	// +optional
	Address string `json:"address,omitempty"`
	// Address6 is the IPv6 counterpart.
	// +optional
	Address6 string `json:"address6,omitempty"`
	// BlockSize is the number of ports in one port block (docs/vpc-egress.md
	// §4.3). Every agent divides by this value, so it is published here rather
	// than configured per node.
	// +optional
	BlockSize int32 `json:"blockSize,omitempty"`
	// Blocks summarizes the leases.
	// +optional
	Blocks NATGatewayBlocks `json:"blocks,omitempty"`
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
// +kubebuilder:printcolumn:name="Address6",type=string,JSONPath=`.status.address6`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NATGateway is a many-to-one egress identity for a VPC: at most one address per
// IP family. Routes with a natGateway target send traffic through it
// (docs/vpc-egress.md).
type NATGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NATGatewaySpec   `json:"spec,omitempty"`
	Status NATGatewayStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATGatewayList contains a list of NATGateway.
type NATGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NATGateway `json:"items"`
}
