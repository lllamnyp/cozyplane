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

// Cozyplane does not ANNOUNCE a pool's addresses — it delivers them
// (docs/north-south.md, tenet 3). Making the fabric hand an address to a node is
// the platform's job: a CCM assigning it to a VNIC, MetalLB, a static route, or
// an address configured on a node. Because from_uplink runs at tc ingress, ahead
// of the kernel's routing decision, delivery works however that was arranged and
// to whichever node the address lands on.
//
// The `advertisement: L2 | BGP` field that used to be here was dead code, and it
// stayed dead: a CNI has no business holding routing sessions with the fabric, and
// the L2 responder it implied was MetalLB reimplemented inside one.

// ExternalPoolSpec is the specification of a pool of externally-routable
// addresses that FloatingIPs are allocated from.
// DEPRECATED — on its way out (docs/north-south.md §9).
//
// An ExternalPool is a hand-written list of CIDRs that NOTHING ROUTES. Cozyplane
// allocates addresses out of it (firstFreeAddress, for both a VPCGateway's NAT
// identity and every FloatingIP) and nothing attracts what it allocates: tenet 3
// ("the CNI does not announce") was only half-applied — we deleted the announcer and
// kept the allocator. An address that is allocated but not attracted exists in etcd
// and nowhere on the wire.
//
// The replacement is a platform-allocated, platform-ATTRACTED claim (a
// PublicIPClaim), referenced instead of a pool. The `attach` verb's grant moves onto
// the claim — it must, since a bare Service would let anyone who can create a Service
// mint a public address.
//
// Do not build new surface on this type.
type ExternalPoolSpec struct {
	// CIDRs are the address ranges the pool hands out.
	// +optional
	CIDRs []string `json:"cidrs,omitempty"`
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
