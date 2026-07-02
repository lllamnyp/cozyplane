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

// VPCPeeringPhase is the lifecycle phase of a VPCPeering.
// +kubebuilder:validation:Enum=Pending;Ready
type VPCPeeringPhase string

const (
	// VPCPeeringPhasePending means the peering half exists but is not active
	// (no reciprocal half, or a referenced VPC is not Ready).
	VPCPeeringPhasePending VPCPeeringPhase = "Pending"
	// VPCPeeringPhaseReady means the peering is matched by its reciprocal half
	// and both VPCs are Ready; the datapath connects them.
	VPCPeeringPhaseReady VPCPeeringPhase = "Ready"
)

// Condition types surfaced in VPCPeering status.
const (
	// VPCPeeringConditionMatched is True when a reciprocal half exists.
	VPCPeeringConditionMatched = "PeerMatched"
	// VPCPeeringConditionVPCReady is True when the local VPC is Ready.
	VPCPeeringConditionVPCReady = "VPCReady"
	// VPCPeeringConditionPeerVPCReady is True when the peer VPC is Ready.
	VPCPeeringConditionPeerVPCReady = "PeerVPCReady"
	// VPCPeeringConditionDisjoint is True when the two VPCs' CIDRs do not
	// overlap. Overlapping VPCs may coexist but can never peer: peered
	// traffic is routed natively, and one address cannot mean two things on
	// a shared path.
	VPCPeeringConditionDisjoint = "CIDRsDisjoint"
)

// LocalVPCRef references a VPC in the same namespace as the referring object.
type LocalVPCRef struct {
	// Name is the VPC name within the referring object's namespace.
	Name string `json:"name"`
}

// VPCPeeringSpec declares one half of a peering between two VPCs.
type VPCPeeringSpec struct {
	// VPCRef is the local VPC — it lives in the same namespace as this object.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// PeerRef is the remote VPC (owner namespace + name).
	PeerRef VPCRef `json:"peerRef"`
}

// VPCPeeringStatus is the observed state of a VPCPeering.
type VPCPeeringStatus struct {
	// Phase is the current lifecycle phase of the peering.
	// +optional
	Phase VPCPeeringPhase `json:"phase,omitempty"`

	// PeerVNI is the VNI of the peer VPC, once known.
	// +optional
	PeerVNI int32 `json:"peerVNI,omitempty"`

	// Conditions represent the latest available observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="PeerNamespace",type=string,JSONPath=`.spec.peerRef.namespace`
// +kubebuilder:printcolumn:name="Peer",type=string,JSONPath=`.spec.peerRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPCPeering is one half of a symmetric peering between two VPCs. Each owner
// creates a half in its own namespace (spec.vpcRef = its VPC, spec.peerRef =
// the other); the peering is live only while both halves exist and reference
// each other. Reciprocity is the consent — there is no accept step — and
// either side revokes unilaterally by deleting its half. Peered traffic is
// routed natively (no NAT), so the two VPCs' CIDRs must not overlap.
type VPCPeering struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="spec is immutable"
	Spec   VPCPeeringSpec   `json:"spec,omitempty"`
	Status VPCPeeringStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeeringList contains a list of VPCPeering.
type VPCPeeringList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCPeering `json:"items"`
}

// LocalRef returns the peering's local VPC as a namespace+name VPCRef.
func (p *VPCPeering) LocalRef() VPCRef {
	return VPCRef{Namespace: p.Namespace, Name: p.Spec.VPCRef.Name}
}

// Matches reports whether other is the reciprocal half of p: other's local
// VPC is p's peer and vice versa. Both the controller (status) and the agent
// (datapath programming) key the peering's liveness on this predicate.
func (p *VPCPeering) Matches(other *VPCPeering) bool {
	return other.LocalRef() == p.Spec.PeerRef && p.LocalRef() == other.Spec.PeerRef
}
