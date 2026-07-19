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
	// FloatingIPPhasePending means the FloatingIP has no usable binding yet — the
	// owned Service has no address, the target has no live Port, or another
	// FloatingIP already binds the target.
	FloatingIPPhasePending FloatingIPPhase = "Pending"
	// FloatingIPPhaseReady means an address is assigned and the binding is
	// programmed in the datapath.
	FloatingIPPhaseReady FloatingIPPhase = "Ready"
)

// Condition types surfaced in FloatingIP status.
const (
	// FloatingIPConditionServiceReady is True when the owned Service exists (the
	// allocation+attraction vehicle, docs/external-addresses.md).
	FloatingIPConditionServiceReady = "ServiceReady"
	// FloatingIPConditionAddressAssigned is True when the load-balancer
	// implementation has assigned an address to the owned Service
	// (status.loadBalancer.ingress).
	FloatingIPConditionAddressAssigned = "AddressAssigned"
	// FloatingIPConditionTargetLive is True when the target tenant IP belongs to
	// a live Port — a running pod on some node. Without a live target the address
	// is reserved but not announced (the binding stays Pending).
	FloatingIPConditionTargetLive = "TargetLive"
	// FloatingIPConditionTargetExclusive is False when ANOTHER FloatingIP already
	// binds this target. A floating IP is a 1:1 bijection — the datapath's reverse
	// map is keyed by {net, VPC IP} alone, so a second binding on the same target
	// would overwrite the first's egress entry and the pod's replies would leave
	// as the WRONG public address (a client dialling the first address gets a
	// reply from the second, and drops it). The loser is left Pending and dark
	// rather than allowed to break the winner.
	FloatingIPConditionTargetExclusive = "TargetExclusive"
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

	// LoadBalancerClass selects which load-balancer implementation allocates and
	// attracts the address (Kubernetes' generic `Service.spec.loadBalancerClass`).
	// Empty uses the cluster's default. cozyplane allocates nothing itself — it
	// owns a `Service type: LoadBalancer` and consumes the address that
	// implementation assigns (docs/external-addresses.md).
	// +optional
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`

	// AddressClaimName names an IPAddressClaim (local.sdn.cozystack.io, the
	// address-controller) in this namespace whose reserved address this FloatingIP
	// should wear. cozyplane only copies it into the claim contract's association
	// annotation on the owned Service — the claim's driver pins the address there,
	// and cozyplane consumes `status.loadBalancer.ingress` exactly as in the
	// dynamic case (docs/external-addresses.md §7). Empty means dynamic: the LB
	// implementation auto-assigns, and the address lives for this object's
	// lifetime rather than the claim's.
	// +optional
	AddressClaimName string `json:"addressClaimName,omitempty"`
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

// FloatingIP binds an externally-routable address to a single workload inside a
// VPC (the OpenStack floating-IP model). The address comes from an owned
// `Service type: LoadBalancer` (docs/external-addresses.md); the FloatingIP is
// the bidirectional counterpart to the egress-only NAT gateway.
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
