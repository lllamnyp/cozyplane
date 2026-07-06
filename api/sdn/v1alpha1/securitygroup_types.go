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

// MaxSecurityGroupsPerVPC is the number of distinct security-group identities a
// VPC can have. The datapath carries membership as a bitmap; id 0 is reserved
// for "no groups" (legacy allow), so ids run 1..63.
const MaxSecurityGroupsPerVPC = 63

// SecurityGroupPhase is the lifecycle phase of a SecurityGroup.
// +kubebuilder:validation:Enum=Pending;Ready
type SecurityGroupPhase string

const (
	// SecurityGroupPhasePending means the group exists but has no allocated id
	// yet (or its VPC is not Ready) — it does not yet affect the datapath.
	SecurityGroupPhasePending SecurityGroupPhase = "Pending"
	// SecurityGroupPhaseReady means the group has an id and its rules are
	// programmed by the agents.
	SecurityGroupPhaseReady SecurityGroupPhase = "Ready"
)

// Condition types surfaced in SecurityGroup status.
const (
	// SecurityGroupConditionVPCReady is True when the local VPC is Ready.
	SecurityGroupConditionVPCReady = "VPCReady"
	// SecurityGroupConditionIDAllocated is True once a per-VPC id is assigned.
	SecurityGroupConditionIDAllocated = "IDAllocated"
)

// SecurityGroupSpec declares an intra-VPC policy group: which ports are members
// and, for a member, which sources may reach it.
type SecurityGroupSpec struct {
	// VPCRef is the local VPC — it lives in the same namespace as this object,
	// like VPCPeering. A group belongs to exactly one VPC.
	VPCRef LocalVPCRef `json:"vpcRef"`

	// PodSelector selects the member pods by their labels (evaluated at Port
	// claim time — see the controller). An empty selector selects every pod in
	// the VPC.
	PodSelector metav1.LabelSelector `json:"podSelector"`

	// Ingress is the list of allowed inbound sources. When *any* group selects a
	// pod, that pod's ingress becomes default-deny and is opened only by the
	// union of the ingress rules of the groups it belongs to. v1 is ingress-only;
	// egress is a later increment (the field is additive).
	// +optional
	// +listType=atomic
	Ingress []SecurityGroupRule `json:"ingress,omitempty"`
}

// SecurityGroupRule admits traffic from one source to the group's members,
// optionally narrowed to specific ports.
type SecurityGroupRule struct {
	// From is the admitted source.
	From SecurityGroupPeer `json:"from"`

	// Ports narrows the rule to specific destination ports. Empty means every
	// port and protocol.
	// +optional
	// +listType=atomic
	Ports []SecurityGroupPort `json:"ports,omitempty"`
}

// SecurityGroupPeer identifies an admitted source. Exactly one of Group or CIDR
// is set. Group references another group in the *same* VPC; peered-VPC group
// references are a later increment (they need identity to cross a trust
// boundary — the Geneve TLV).
type SecurityGroupPeer struct {
	// Group is the name of another SecurityGroup in the same VPC.
	// +optional
	Group string `json:"group,omitempty"`

	// CIDR admits north-south (bridge/floating) callers by their pre-masquerade
	// client address. It does not match intra-VPC sources — those are identified
	// by group. FQDN sources are a later increment.
	// +optional
	CIDR string `json:"cidr,omitempty"`
}

// SecurityGroupPort is a protocol/port an ingress rule admits.
type SecurityGroupPort struct {
	// Protocol is TCP or UDP.
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`

	// Port is the destination port. Zero (or omitted) means every port for the
	// protocol.
	// +optional
	Port int32 `json:"port,omitempty"`
}

// SecurityGroupStatus is the observed state of a SecurityGroup.
type SecurityGroupStatus struct {
	// ID is the per-VPC numeric identity (1..63), allocated by the controller —
	// the wire identity the datapath keys on. Zero means unallocated.
	// +optional
	ID int32 `json:"id,omitempty"`

	// Phase is the current lifecycle phase.
	// +optional
	Phase SecurityGroupPhase `json:"phase,omitempty"`

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
// +kubebuilder:printcolumn:name="ID",type=integer,JSONPath=`.status.id`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// SecurityGroup is intra-VPC network policy, AWS-security-group-shaped: it
// selects member pods by label and admits inbound traffic from other groups (in
// the same VPC) or from north-south CIDRs. While no group selects a pod its
// intra-VPC ingress is unrestricted (today's behavior); once any group selects
// it, its ingress is default-deny, opened only by the union of its groups'
// rules. Enforcement is destination-side in the eBPF datapath, so it is
// placement-independent.
type SecurityGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   SecurityGroupSpec   `json:"spec,omitempty"`
	Status SecurityGroupStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityGroupList contains a list of SecurityGroup.
type SecurityGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SecurityGroup `json:"items"`
}

// LocalRef returns the group's local VPC as a namespace+name VPCRef.
func (g *SecurityGroup) LocalRef() VPCRef {
	return VPCRef{Namespace: g.Namespace, Name: g.Spec.VPCRef.Name}
}
