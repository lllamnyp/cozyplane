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

// PortClaimConditionBound is True while a live pod holds the claim's Port.
const PortClaimConditionBound = "Bound"

// PortClaimSpec requests a VPC interface identity that outlives the pods binding it.
type PortClaimSpec struct {
	// VPCRef is the VPC the claim's Port lives in; empty namespace means the claim's namespace.
	VPCRef VPCRef `json:"vpcRef"`

	// MAC is the requested interface MAC address; empty means one is generated at first bind.
	// +optional
	MAC string `json:"mac,omitempty"`

	// IP is the requested VPC address; empty means one is allocated at first bind.
	// +optional
	IP string `json:"ip,omitempty"`
}

// PortClaimStatus is the identity pinned to the claim.
type PortClaimStatus struct {
	// IP is the VPC address pinned to the claim.
	// +optional
	IP string `json:"ip,omitempty"`

	// MAC is the interface MAC address pinned to the claim.
	// +optional
	MAC string `json:"mac,omitempty"`

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
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.status.ip`
// +kubebuilder:printcolumn:name="MAC",type=string,JSONPath=`.status.mac`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PortClaim holds a Port's IP and MAC for as long as the claim exists; pods bind it with the sdn.cozystack.io/port-claim annotation.
type PortClaim struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PortClaimSpec   `json:"spec,omitempty"`
	Status PortClaimStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PortClaimList contains a list of PortClaim.
type PortClaimList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PortClaim `json:"items"`
}
