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

// HostFirewallSpec selects nodes and declares what may reach them.
type HostFirewallSpec struct {
	// NodeSelector selects the nodes this firewall applies to by their labels.
	// An empty selector selects every node. A node selected by at least one
	// HostFirewall is host-ingress isolated: new TCP/UDP flows to its
	// addresses are denied unless an ingress rule admits them. Node-sourced
	// traffic, the overlay transport, ICMP, established TCP, and replies to
	// node-originated UDP are never gated (docs/host-firewall.md).
	// +optional
	NodeSelector metav1.LabelSelector `json:"nodeSelector,omitempty"`

	// PolicyTypes selects the directions this object isolates, mirroring
	// NetworkPolicy: empty defaults to [Ingress], plus Egress when Egress
	// rules are present. A node selected by an object whose types include
	// Egress is host-EGRESS isolated: its own new TCP/UDP flows out are
	// default-deny. node->node and node->local-pod stay exempt regardless
	// (kubelet↔apiserver, the agent's own API access, kubelet probes —
	// docs/host-firewall.md).
	// +optional
	PolicyTypes []HostFirewallPolicyType `json:"policyTypes,omitempty"`

	// Ingress rules union across all HostFirewalls selecting a node.
	// +optional
	Ingress []HostFirewallRule `json:"ingress,omitempty"`

	// Egress rules union across all HostFirewalls selecting a node. `to`
	// peers are CIDRs, like ingress `from`.
	// +optional
	Egress []HostFirewallEgressRule `json:"egress,omitempty"`
}

// HostFirewallPolicyType is a direction a HostFirewall isolates.
// +kubebuilder:validation:Enum=Ingress;Egress
type HostFirewallPolicyType string

const (
	// HostFirewallPolicyTypeIngress isolates traffic TO the node.
	HostFirewallPolicyTypeIngress HostFirewallPolicyType = "Ingress"
	// HostFirewallPolicyTypeEgress isolates traffic FROM the node.
	HostFirewallPolicyTypeEgress HostFirewallPolicyType = "Egress"
)

// HostFirewallEgressRule admits node-originated traffic to destinations. An
// empty To admits any destination; an empty Ports admits every TCP and UDP
// port.
type HostFirewallEgressRule struct {
	// To lists admitted destination ranges. Empty means any destination.
	// +optional
	To []HostFirewallPeer `json:"to,omitempty"`

	// Ports narrows the rule to specific destination ports. Empty means
	// every port, TCP and UDP.
	// +optional
	Ports []HostFirewallPort `json:"ports,omitempty"`
}

// HostFirewallRule admits sources to ports. An empty From admits any source;
// an empty Ports admits every TCP and UDP port.
type HostFirewallRule struct {
	// From lists admitted source ranges. Empty means any source.
	// +optional
	From []HostFirewallPeer `json:"from,omitempty"`

	// Ports narrows the rule to specific destination ports. Empty means every
	// port, TCP and UDP.
	// +optional
	Ports []HostFirewallPort `json:"ports,omitempty"`
}

// HostFirewallPeer is an admitted source range.
type HostFirewallPeer struct {
	// CIDR admits sources within the range (either family).
	CIDR string `json:"cidr"`

	// Except carves sub-ranges out of CIDR.
	// +optional
	Except []string `json:"except,omitempty"`
}

// HostFirewallPort is a protocol/port an ingress rule admits.
type HostFirewallPort struct {
	// Protocol is TCP or UDP.
	// +kubebuilder:validation:Enum=TCP;UDP
	Protocol string `json:"protocol"`

	// Port is the destination port. Zero (or omitted) means every port for
	// the protocol.
	// +optional
	Port int32 `json:"port,omitempty"`

	// EndPort extends Port to an inclusive range [Port, EndPort]. Ranges
	// expand to per-port datapath entries and are capped at 64 ports
	// (docs/host-firewall.md); wider ranges are rejected (fail closed).
	// +optional
	EndPort int32 `json:"endPort,omitempty"`
}

// HostFirewallStatus is the observed state of a HostFirewall.
type HostFirewallStatus struct {
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
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HostFirewall is a cluster-scoped, operator-owned ingress policy for the
// nodes themselves — the node-scoped sibling of NetworkPolicy (which gates
// default-network pods) and SecurityGroup (which gates VPC ports). Tenants
// get no access to this kind (docs/host-firewall.md).
type HostFirewall struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HostFirewallSpec   `json:"spec,omitempty"`
	Status HostFirewallStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HostFirewallList contains a list of HostFirewall.
type HostFirewallList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HostFirewall `json:"items"`
}
