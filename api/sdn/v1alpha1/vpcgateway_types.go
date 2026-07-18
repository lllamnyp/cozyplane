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
	// the VPC has not resolved, or another gateway already owns this VPC.
	VPCGatewayPhasePending VPCGatewayPhase = "Pending"
	// VPCGatewayPhaseReady means the boundary is realized.
	VPCGatewayPhaseReady VPCGatewayPhase = "Ready"
)

// Condition types surfaced in VPCGateway status.
const (
	// VPCGatewayConditionVPCResolved is True when spec.vpcRef names a VPC in
	// this namespace.
	VPCGatewayConditionVPCResolved = "VPCResolved"
	// VPCGatewayConditionNATReady is True when NAT egress needs no identity
	// (disabled), or every address family the VPC has that the cluster can serve a
	// LoadBalancer for has an assigned NAT address (docs/external-addresses.md §5).
	// A family the cluster cannot serve keeps the gateway pod (#15) and does not
	// hold this False.
	VPCGatewayConditionNATReady = "NATReady"
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

	// LoadBalancerClass selects which load-balancer implementation allocates and
	// attracts the VPC's NAT identity (Kubernetes' generic
	// `Service.spec.loadBalancerClass`). Empty uses the cluster's default. cozyplane
	// allocates nothing itself — the gateway owns a `Service type: LoadBalancer` per
	// address family and consumes the address that implementation assigns
	// (docs/external-addresses.md §5).
	// +optional
	LoadBalancerClass string `json:"loadBalancerClass,omitempty"`

	// NAT configures many-to-one egress.
	// +optional
	NAT VPCGatewayNAT `json:"nat,omitempty"`

	// Ingress configures what may enter the VPC from outside.
	// +optional
	Ingress VPCGatewayIngress `json:"ingress,omitempty"`
}

// VPCGatewayStatus is the observed state of a VPCGateway.
type VPCGatewayStatus struct {
	// NATAddress is the v4 address this VPC's v4 egress wears on the wire — read from
	// the gateway's owned v4 LoadBalancer Service (docs/external-addresses.md §5), and
	// the tenant's OWN identity. Without it a VPC's v4 traffic is SNATed to the node's
	// address and is indistinguishable from the platform's (docs/north-south.md, tenet
	// 8). Empty means the VPC has no v4 CIDR, or the LB implementation assigned no v4
	// address; its v4 egress (if any) falls back to the pod.
	// +optional
	NATAddress string `json:"natAddress,omitempty"`

	// NATAddress6 is the v6 counterpart: the address this VPC's v6 egress wears
	// (docs/north-south.md §6a), read from the gateway's owned v6 LoadBalancer Service.
	// Each family gets its own eBPF identity when the LB implementation can assign one;
	// a family with none keeps the gateway pod. The pod is retired only once every
	// family the VPC has is served in eBPF.
	// +optional
	NATAddress6 string `json:"natAddress6,omitempty"`

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
// A VPC has exactly one. Creating a gateway is the tenant's act; who may mint the
// public address it draws is Service RBAC + the allocator's own scoping
// (docs/external-addresses.md §8).
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
