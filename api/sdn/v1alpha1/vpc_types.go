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

// VPCPhase is the lifecycle phase of a VPC.
// +kubebuilder:validation:Enum=Pending;Ready
type VPCPhase string

const (
	// VPCPhasePending means the VPC has been accepted but not yet realized.
	VPCPhasePending VPCPhase = "Pending"
	// VPCPhaseReady means the VPC has a VNI and is ready to host ports.
	VPCPhaseReady VPCPhase = "Ready"
)

// VPCSpec is the specification of a VPC — a tenant overlay network.
type VPCSpec struct {
	// CIDRs are the address ranges (IPv4 and/or IPv6) of the VPC. These may
	// overlap with other VPCs; isolation is by overlay, not address space.
	// +optional
	// +listType=atomic
	CIDRs []string `json:"cidrs,omitempty"`

	// MTU is the MTU advertised to ports in this VPC. Zero selects the
	// controller default.
	// +optional
	MTU int32 `json:"mtu,omitempty"`
	// Boundary is an operator-managed ceiling, independent of tenant groups.
	// Setting, changing or removing it requires manage-boundary on this VPC.
	// +optional
	Boundary *VPCBoundary `json:"boundary,omitempty"`
}

// VPCBoundary limits cross-VPC initiations and Internet egress.
type VPCBoundary struct {
	// Revision is positive and increases whenever the policy changes.
	Revision int64 `json:"revision"`
	Internet bool  `json:"internet"`
	// +optional
	// +listType=atomic
	Peers []VPCBoundaryRule `json:"peers,omitempty"`
}

// VPCBoundaryRule admits an initiation; tracked replies require no reverse grant.
type VPCBoundaryRule struct {
	PeerRef VPCRef `json:"peerRef"`
	// Direction is ingress or egress, relative to this VPC.
	Direction string `json:"direction"`
	// Protocol is TCP, UDP or ICMP (family follows the packet).
	Protocol string `json:"protocol"`
	// +optional
	// +listType=atomic
	Ports []int32 `json:"ports,omitempty"`
	// +optional
	ICMPType *int32 `json:"icmpType,omitempty"`
	// +optional
	ICMPCode *int32 `json:"icmpCode,omitempty"`
}

// A VPC's way OUT (and in) is not declared here: it is a VPCGateway, which is a
// separate object because opening a north-south door is the operator's
// grant, not the tenant's to take (docs/north-south.md).

// VPCStatus is the observed state of a VPC.
type VPCStatus struct {
	// VNI is the overlay network identifier allocated to this VPC by the
	// controller. Zero means unallocated.
	// +optional
	VNI int32 `json:"vni,omitempty"`

	// Phase is the current lifecycle phase of the VPC.
	// +optional
	Phase VPCPhase `json:"phase,omitempty"`

	// Conditions represent the latest available observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// BoundaryNodes acknowledges the revision loaded by each agent instance.
	// +optional
	// +listType=map
	// +listMapKey=node
	BoundaryNodes []VPCBoundaryNode `json:"boundaryNodes,omitempty"`
}

// VPCBoundaryNode is an agent instance's successful dataplane acknowledgement.
type VPCBoundaryNode struct {
	Node               string `json:"node"`
	AgentUID           string `json:"agentUID"`
	Revision           int64  `json:"revision"`
	ObservedGeneration int64  `json:"observedGeneration"`
	PrimaryPortsDigest string `json:"primaryPortsDigest"`
	// TransportReady confirms that peer maps and routes are synchronized.
	TransportReady bool `json:"transportReady"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VNI",type=integer,JSONPath=`.status.vni`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPC is a tenant overlay network. It is namespaced: the namespace expresses
// ownership. A pod's *use* of a VPC is granted separately by a VPCBinding, even
// within the owner's own namespace.
type VPC struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPCSpec   `json:"spec,omitempty"`
	Status VPCStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCList contains a list of VPC.
type VPCList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPC `json:"items"`
}
