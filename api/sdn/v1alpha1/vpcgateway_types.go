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

// VPCGatewayPhase is the lifecycle phase of a VPCGateway.
type VPCGatewayPhase string

const (
	// VPCGatewayPhasePending means the door is declared but not yet usable —
	// the VPC or the pool has not resolved, or another gateway already owns
	// this VPC.
	VPCGatewayPhasePending VPCGatewayPhase = "Pending"
	// VPCGatewayPhaseReady means the boundary is realized.
	VPCGatewayPhaseReady VPCGatewayPhase = "Ready"
)

// Condition types surfaced in VPCGateway status.
const (
	// VPCGatewayConditionVPCResolved is True when spec.vpcRef names a VPC in
	// this namespace.
	VPCGatewayConditionVPCResolved = "VPCResolved"
	// VPCGatewayConditionPoolResolved is True when spec.poolRef names an
	// existing ExternalPool.
	VPCGatewayConditionPoolResolved = "PoolResolved"
	// VPCGatewayConditionExclusive is False when another VPCGateway already
	// binds this VPC. A VPC has exactly ONE boundary — that is what makes
	// "everything crosses it" a checkable property and the per-VPC counters
	// unambiguous. The older gateway wins; the loser stays Pending and realizes
	// nothing (docs/north-south.md).
	VPCGatewayConditionExclusive = "Exclusive"
)

// VPCGatewayNAT configures many-to-one egress for pods with no address of their
// own. Today it runs the per-VPC gateway pod; the datapath will take the SNAT
// over (docs/north-south.md § increments).
type VPCGatewayNAT struct {
	// Enabled opens outbound access for VPC pods that hold no floating address,
	// masqueraded to an address of the VPC's own.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// VPCGatewayIngress configures what may enter the VPC from outside.
type VPCGatewayIngress struct {
	// LoadBalancer admits Service type=LoadBalancer traffic onto this VPC's
	// pods. It is FALSE by default, and that default is the point: without a
	// gateway saying otherwise, a Service created in any namespace cannot open a
	// door into a tenant's VPC. Ingress into a VPC is something the VPC's own
	// boundary admits (docs/north-south.md, tenet 7).
	//
	// It admits the traffic to the boundary; the destination's SecurityGroups
	// still decide which pods and ports answer.
	// +optional
	LoadBalancer bool `json:"loadBalancer,omitempty"`
}

// VPCGatewaySpec declares a VPC's north-south boundary.
type VPCGatewaySpec struct {
	// VPCRef is the VPC this gateway is the boundary of, in this namespace.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// PoolRef is the ExternalPool the VPC's outside-facing addresses are drawn
	// from — its NAT identity, and the floating addresses bound to its ports.
	// Creating a VPCGateway requires the "attach" verb on this pool: pools are a
	// scarce, cluster-scoped, billable resource, so an operator grants one and a
	// tenant opens its own door onto it.
	// +optional
	PoolRef ExternalPoolRef `json:"poolRef,omitempty"`

	// NAT configures many-to-one egress.
	// +optional
	NAT VPCGatewayNAT `json:"nat,omitempty"`

	// Ingress configures what may enter the VPC from outside.
	// +optional
	Ingress VPCGatewayIngress `json:"ingress,omitempty"`
}

// VPCGatewayStatus is the observed state of a VPCGateway.
type VPCGatewayStatus struct {
	// NATAddress is the address this VPC's egress wears on the wire — allocated
	// from spec.poolRef, and the tenant's OWN identity. Without it a VPC's traffic
	// is SNATed to the node's address and is indistinguishable from the platform's
	// (docs/north-south.md, tenet 8). Empty means no NAT identity: the VPC has no
	// pool, and its egress falls back to the legacy gateway pod.
	// +optional
	NATAddress string `json:"natAddress,omitempty"`

	// Phase is the lifecycle phase.
	// +optional
	Phase VPCGatewayPhase `json:"phase,omitempty"`

	// Conditions is the detailed state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Pool",type=string,JSONPath=`.spec.poolRef.name`
// +kubebuilder:printcolumn:name="NAT",type=boolean,JSONPath=`.spec.nat.enabled`
// +kubebuilder:printcolumn:name="NATAddress",type=string,JSONPath=`.status.natAddress`
// +kubebuilder:printcolumn:name="LB",type=boolean,JSONPath=`.spec.ingress.loadBalancer`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPCGateway is a VPC's north-south boundary: the one place where its traffic to
// and from the outside world is declared, permitted and counted
// (docs/north-south.md).
//
// It is a boundary, not a hop. Packets are not detoured through it —
// enforcement stays in the datapath's eBPF hooks, exactly where it already is.
// What the gateway does is give that enforcement an owner: without one, a VPC has
// no way out (no NAT egress) and no way in (no LoadBalancer ingress), and the
// bytes that cross have nothing to be attributed to.
//
// A VPC has exactly one. Creating a gateway is the tenant's act; the pool it
// draws from is the operator's grant, enforced by the "attach" verb on the
// ExternalPool — the same shape as VPCBinding's "export" and VPCPeering's "peer".
type VPCGateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VPCGatewaySpec   `json:"spec,omitempty"`
	Status VPCGatewayStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCGatewayList contains a list of VPCGateway.
type VPCGatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCGateway `json:"items"`
}
