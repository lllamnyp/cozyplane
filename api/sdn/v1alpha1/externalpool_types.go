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

// ExternalPoolAdvertisement is how a pool's addresses are announced to the
// physical network.
// +kubebuilder:validation:Enum=L2;BGP
type ExternalPoolAdvertisement string

const (
	// ExternalPoolAdvertisementL2 announces each in-use address with gratuitous
	// ARP/NDP from the node currently anchoring it.
	ExternalPoolAdvertisementL2 ExternalPoolAdvertisement = "L2"
	// ExternalPoolAdvertisementBGP announces addresses over BGP (not yet
	// implemented; reserved).
	ExternalPoolAdvertisementBGP ExternalPoolAdvertisement = "BGP"
)

// ExternalPoolSpec is the specification of a pool of externally-routable
// addresses that FloatingIPs are allocated from.
type ExternalPoolSpec struct {
	// CIDRs are the address ranges the pool hands out.
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`

	// Advertisement is how in-use addresses are announced to the physical
	// network. Empty selects the controller default (L2).
	// +optional
	Advertisement ExternalPoolAdvertisement `json:"advertisement,omitempty"`
}

// ExternalPoolStatus is the observed state of an ExternalPool.
type ExternalPoolStatus struct {
	// Allocated is the number of addresses currently bound to FloatingIPs.
	// +optional
	Allocated int32 `json:"allocated,omitempty"`

	// Available is the number of addresses still free in the pool.
	// +optional
	Available int32 `json:"available,omitempty"`

	// Conditions represent the latest available observations.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Allocated",type=integer,JSONPath=`.status.allocated`
// +kubebuilder:printcolumn:name="Available",type=integer,JSONPath=`.status.available`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ExternalPool is a cluster-scoped, admin-defined range of externally-routable
// addresses. FloatingIPs claim addresses from a pool; a pool is the equivalent
// of MetalLB's IPAddressPool.
type ExternalPool struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExternalPoolSpec   `json:"spec,omitempty"`
	Status ExternalPoolStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalPoolList contains a list of ExternalPool.
type ExternalPoolList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExternalPool `json:"items"`
}

// ExternalPoolRef references an ExternalPool by name (pools are cluster-scoped).
type ExternalPoolRef struct {
	// Name is the ExternalPool name.
	// +optional
	Name string `json:"name,omitempty"`
}
