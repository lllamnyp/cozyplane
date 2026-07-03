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

// FloatingIPPhase is the lifecycle phase of a FloatingIP.
// +kubebuilder:validation:Enum=Pending;Ready
type FloatingIPPhase string

const (
	// FloatingIPPhasePending means the FloatingIP has no address assigned yet
	// (pool exhausted, requested address taken, or not yet reconciled).
	FloatingIPPhasePending FloatingIPPhase = "Pending"
	// FloatingIPPhaseReady means an address is assigned and the binding is
	// programmed in the datapath.
	FloatingIPPhaseReady FloatingIPPhase = "Ready"
)

// Condition types surfaced in FloatingIP status.
const (
	// FloatingIPConditionPoolResolved is True when the referenced (or default)
	// ExternalPool exists and could be selected.
	FloatingIPConditionPoolResolved = "PoolResolved"
	// FloatingIPConditionAddressAssigned is True when an address has been
	// allocated from the pool to this binding.
	FloatingIPConditionAddressAssigned = "AddressAssigned"
	// FloatingIPConditionGatewayEnabled is True when the target VPC has an
	// egress gateway enabled — the anchor a floating IP is realized on. A
	// FloatingIP never enables the gateway itself (it does not own the VPC); it
	// stays Pending until the VPC owner turns spec.egress.natGateway on.
	FloatingIPConditionGatewayEnabled = "GatewayEnabled"
)

// FloatingIPSpec binds one externally-routable address 1:1 to a workload inside
// a VPC. The address is reachable bidirectionally: inbound connections DNAT to
// the target, and the target's egress is SNATed from the floating address.
type FloatingIPSpec struct {
	// VPCRef is the VPC the target lives in — it is in the same namespace as
	// this object.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// Target is the tenant IP within the VPC that the floating address binds to.
	Target string `json:"target"`

	// PoolRef selects the ExternalPool to allocate from. Empty selects the
	// default pool.
	// +optional
	PoolRef ExternalPoolRef `json:"poolRef,omitempty"`

	// Address optionally requests a specific address from the pool; empty lets
	// the controller pick a free one.
	// +optional
	Address string `json:"address,omitempty"`
}

// FloatingIPStatus is the observed state of a FloatingIP.
type FloatingIPStatus struct {
	// Address is the externally-routable address assigned to this binding.
	// +optional
	Address string `json:"address,omitempty"`

	// Phase is the current lifecycle phase of the FloatingIP.
	// +optional
	Phase FloatingIPPhase `json:"phase,omitempty"`

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
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.address`
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// FloatingIP binds an externally-routable address from an ExternalPool to a
// single workload inside a VPC (the OpenStack floating-IP model). It is the
// bidirectional counterpart to the egress-only NAT gateway.
type FloatingIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FloatingIPSpec   `json:"spec,omitempty"`
	Status FloatingIPStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIPList contains a list of FloatingIP.
type FloatingIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FloatingIP `json:"items"`
}
