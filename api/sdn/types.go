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

package sdn

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VPCPhase is the lifecycle phase of a VPC.
type VPCPhase string

const (
	// VPCPhasePending means the VPC has been accepted but not yet realized
	// (no VNI allocated, datapath not programmed).
	VPCPhasePending VPCPhase = "Pending"
	// VPCPhaseReady means the VPC has a VNI and is ready to host ports.
	VPCPhaseReady VPCPhase = "Ready"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCList is a list of VPC objects.
type VPCList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VPC
}

// VPCSpec is the specification of a VPC — a tenant overlay network.
type VPCSpec struct {
	// CIDRs are the address ranges (IPv4 and/or IPv6) of the VPC. These may
	// overlap with other VPCs; isolation is by overlay, not address space.
	CIDRs []string

	// MTU is the MTU advertised to ports in this VPC. Zero selects the
	// controller default.
	MTU int32
}

// VPCGatewayPhase is the lifecycle phase of a VPCGateway.
type VPCGatewayPhase string

const (
	VPCGatewayPhasePending VPCGatewayPhase = "Pending"
	VPCGatewayPhaseReady   VPCGatewayPhase = "Ready"
)

// Condition types surfaced in VPCGateway status.
const (
	VPCGatewayConditionVPCResolved = "VPCResolved"
	VPCGatewayConditionNATReady    = "NATReady"
	VPCGatewayConditionExclusive   = "Exclusive"
)

// VPCGatewayNAT configures many-to-one egress for pods with no address of their own.
type VPCGatewayNAT struct {
	Enabled bool
	// AddressClaimName / AddressClaimName6: per-family IPAddressClaim names for a
	// reserved NAT identity (docs/external-addresses.md §7); empty = dynamic.
	AddressClaimName  string
	AddressClaimName6 string
}

// VPCGatewayIngress configures what may enter the VPC from outside.
type VPCGatewayIngress struct {
	// LoadBalancer admits Service type=LoadBalancer traffic onto this VPC's pods;
	// false by default (docs/north-south.md, tenet 7).
	LoadBalancer bool
}

// VPCGatewaySpec declares a VPC's north-south boundary.
type VPCGatewaySpec struct {
	VPCRef LocalVPCRef
	// LoadBalancerClass selects which LB implementation allocates+attracts the NAT
	// identity (docs/external-addresses.md §5).
	LoadBalancerClass string
	NAT               VPCGatewayNAT
	Ingress           VPCGatewayIngress
}

// VPCGatewayStatus is the observed state of a VPCGateway.
type VPCGatewayStatus struct {
	// NATAddress is the VPC's own v4 egress identity, read from its owned Service.
	NATAddress string
	// NATAddress6 is the v6 counterpart (docs/north-south.md §6a).
	NATAddress6 string
	Phase       VPCGatewayPhase
	Conditions  []metav1.Condition
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCGateway is a VPC's north-south boundary — the one place its traffic to and
// from the outside is declared, permitted and counted (docs/north-south.md).
type VPCGateway struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCGatewaySpec
	Status VPCGatewayStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCGatewayList contains a list of VPCGateway.
type VPCGatewayList struct {
	metav1.TypeMeta
	metav1.ListMeta
	Items []VPCGateway
}

// VPCStatus is the observed state of a VPC.
type VPCStatus struct {
	// VNI is the overlay network identifier allocated to this VPC by the
	// controller. Zero means unallocated.
	VNI int32

	// Phase is the current lifecycle phase of the VPC.
	Phase VPCPhase

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPC is a tenant overlay network. It is namespaced: the namespace expresses
// ownership of the VPC. Use of a VPC by a pod is granted separately by a
// VPCBinding (see below) — even within the owner's own namespace.
type VPC struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCSpec
	Status VPCStatus
}

// VPCRef references a VPC by namespace and name. The namespace is the VPC
// owner's namespace, not necessarily the referrer's.
type VPCRef struct {
	Namespace string
	Name      string
}

// LocalVPCRef references a VPC in the same namespace as the referring object.
type LocalVPCRef struct {
	Name string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCBindingList is a list of VPCBinding objects.
type VPCBindingList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VPCBinding
}

// VPCBindingSpec authorizes pods in the binding's (consumer) namespace to attach
// to the referenced VPC.
type VPCBindingSpec struct {
	// VPCRef is the VPC being made usable, identified by owner namespace + name.
	VPCRef VPCRef
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCBinding grants pods in its own (consumer) namespace permission to attach to
// the VPC named in spec.vpcRef. It is created by the VPC owner reaching into the
// consumer namespace; its existence is the datapath-readable, namespace-keyed
// authorization the CNI checks at attach time.
type VPCBinding struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec VPCBindingSpec
}

// VPCPeeringPhase is the lifecycle phase of a VPCPeering.
type VPCPeeringPhase string

const (
	// VPCPeeringPhasePending means the peering half exists but is not active
	// (no reciprocal half, or a referenced VPC is not Ready).
	VPCPeeringPhasePending VPCPeeringPhase = "Pending"
	// VPCPeeringPhaseReady means the peering is matched by its reciprocal half
	// and both VPCs are Ready; the datapath connects them.
	VPCPeeringPhaseReady VPCPeeringPhase = "Ready"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeeringList is a list of VPCPeering objects.
type VPCPeeringList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []VPCPeering
}

// VPCPeeringSpec declares one half of a peering between two VPCs.
type VPCPeeringSpec struct {
	// VPCRef is the local VPC — it lives in the same namespace as this object.
	VPCRef LocalVPCRef

	// PeerRef is the remote VPC (owner namespace + name).
	PeerRef VPCRef
}

// VPCPeeringStatus is the observed state of a VPCPeering.
type VPCPeeringStatus struct {
	// Phase is the current lifecycle phase of the peering.
	Phase VPCPeeringPhase

	// PeerVNI is the VNI of the peer VPC, once known.
	PeerVNI int32

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCPeering is one half of a symmetric peering between two VPCs. Each owner
// creates a half in its own namespace; the peering is live only while both
// halves exist and reference each other — reciprocity is the consent, either
// side revokes by deleting its half.
type VPCPeering struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCPeeringSpec
	Status VPCPeeringStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PortList is a list of Port objects.
type PortList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []Port
}

// PortSpec is the realized network interface of a pod on a VPC.
type PortSpec struct {
	VPCRef       VPCRef
	IP           string
	MAC          string
	Node         string
	NodeIP       string
	PodNamespace string
	PodName      string

	// Gateway marks the VPC's gateway port (the .1 leg of the egress gateway
	// pod); agents route off-VPC traffic to it.
	Gateway bool
}

// PortStatus is the controller-observed state of a Port.
type PortStatus struct {
	// Groups is the set of SecurityGroup numeric ids this Port belongs to
	// (resolved from the pod's labels), folded into the datapath membership
	// bitmap by the agent. Empty means "no groups" (legacy allow).
	Groups []int32
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Port is a pod's realized interface on a VPC.
type Port struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   PortSpec
	Status PortStatus
}

// FloatingIPPhase is the lifecycle phase of a FloatingIP.
type FloatingIPPhase string

const (
	// FloatingIPPhasePending means the FloatingIP has no address assigned yet
	// (no address assigned, no live target, or a conflicting binding).
	FloatingIPPhasePending FloatingIPPhase = "Pending"
	// FloatingIPPhaseReady means an address is assigned and the binding is
	// programmed in the datapath.
	FloatingIPPhaseReady FloatingIPPhase = "Ready"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIPList is a list of FloatingIP objects.
type FloatingIPList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []FloatingIP
}

// FloatingIPSpec binds one externally-routable address 1:1 to a workload inside
// a VPC. The address is reachable bidirectionally: inbound connections DNAT to
// the target, and the target's egress is SNATed from the floating address.
type FloatingIPSpec struct {
	// VPCRef is the VPC the target lives in — it is in the same namespace as
	// this object.
	VPCRef LocalVPCRef

	// Target is the tenant IP within the VPC that the floating address binds to.
	Target string

	// LoadBalancerClass selects which LB implementation allocates+attracts the
	// address (docs/external-addresses.md). Empty = cluster default.
	LoadBalancerClass string

	// AddressClaimName names an IPAddressClaim in this namespace whose reserved
	// address this FloatingIP wears (docs/external-addresses.md §7); empty = dynamic.
	AddressClaimName string
}

// FloatingIPStatus is the observed state of a FloatingIP.
type FloatingIPStatus struct {
	// Address is the externally-routable address assigned to this binding.
	Address string

	// Phase is the current lifecycle phase of the FloatingIP.
	Phase FloatingIPPhase

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FloatingIP binds an externally-routable address (from its owned Service) to a
// single workload inside a VPC (the OpenStack floating-IP model). It is the
// bidirectional counterpart to the egress-only NAT gateway.
type FloatingIP struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   FloatingIPSpec
	Status FloatingIPStatus
}

// ServiceVIPPhase is the lifecycle phase of a ServiceVIP.
type ServiceVIPPhase string

const (
	// ServiceVIPPhasePending means the VIP is allocated but has no live
	// backends yet (or the Service has none ready).
	ServiceVIPPhasePending ServiceVIPPhase = "Pending"
	// ServiceVIPPhaseReady means the VIP has at least one live backend and is
	// programmed in the datapath.
	ServiceVIPPhaseReady ServiceVIPPhase = "Ready"
)

// ServiceRef references a Kubernetes Service by namespace and name.
type ServiceRef struct {
	// Namespace of the Service.
	Namespace string
	// Name of the Service.
	Name string
}

// VIPPort is one service port the VIP serves.
type VIPPort struct {
	// Name of the service port (may be empty for a single unnamed port).
	Name string
	// Protocol is TCP or UDP.
	Protocol string
	// Port is the service port the VIP listens on.
	Port int32
}

// VIPBackendPort is one resolved (service port -> target port) pair on a
// backend.
type VIPBackendPort struct {
	// Protocol is TCP or UDP.
	Protocol string
	// Port is the service port on the VIP.
	Port int32
	// TargetPort is the resolved numeric port on the backend.
	TargetPort int32
}

// VIPBackend is one ready backend of the service, resolved to its Port's VPC
// address.
type VIPBackend struct {
	// IP is the backend's VPC IP (never the fabric IP).
	IP string
	// Ports are the resolved per-port targets on this backend.
	Ports []VIPBackendPort
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServiceVIPList is a list of ServiceVIP objects.
type ServiceVIPList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ServiceVIP
}

// ServiceVIPSpec is the materialized ClusterIP-equivalent of a Service
// attached to a VPC.
type ServiceVIPSpec struct {
	// VPCRef identifies the VPC this VIP belongs to (owner namespace + name).
	VPCRef VPCRef

	// IP is the virtual address allocated from the VPC's own address space.
	IP string

	// ServiceRef is the Kubernetes Service this VIP fronts.
	ServiceRef ServiceRef

	// Ports are the service ports the VIP serves.
	Ports []VIPPort

	// SessionAffinity mirrors the Service's ("ClientIP" or "None").
	SessionAffinity string
}

// ServiceVIPStatus is the observed state of a ServiceVIP.
type ServiceVIPStatus struct {
	// Backends are the ready endpoints resolved to same-VPC Port addresses;
	// the agents program the datapath from this list.
	Backends []VIPBackend

	// Phase is the current lifecycle phase.
	Phase ServiceVIPPhase

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServiceVIP is the ClusterIP-equivalent of a Service inside a VPC: a virtual
// address from the VPC's own space, load-balanced to backend VPC IPs by the
// datapath, discovered only through the split-horizon resolver.
type ServiceVIP struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   ServiceVIPSpec
	Status ServiceVIPStatus
}

// SecurityGroupPhase is the lifecycle phase of a SecurityGroup.
type SecurityGroupPhase string

const (
	// SecurityGroupPhasePending means the group has no allocated id yet.
	SecurityGroupPhasePending SecurityGroupPhase = "Pending"
	// SecurityGroupPhaseReady means the group has an id and is programmed.
	SecurityGroupPhaseReady SecurityGroupPhase = "Ready"
)

// SecurityGroupSpec declares an intra-VPC policy group.
type SecurityGroupSpec struct {
	VPCRef      LocalVPCRef
	PodSelector metav1.LabelSelector
	Ingress     []SecurityGroupRule
	Egress      []SecurityGroupEgressRule
}

// SecurityGroupRule admits traffic from one source, optionally port-narrowed.
type SecurityGroupRule struct {
	From  SecurityGroupPeer
	Ports []SecurityGroupPort
}

// SecurityGroupEgressRule admits traffic to one destination, optionally
// port-narrowed.
type SecurityGroupEgressRule struct {
	To    SecurityGroupPeer
	Ports []SecurityGroupPort
}

// SecurityGroupPeer identifies an admitted source (group, optionally in a peer
// VPC, or CIDR).
type SecurityGroupPeer struct {
	Group string
	VPC   *VPCRef
	CIDR  string
}

// SecurityGroupPort is a protocol/port an ingress rule admits.
type SecurityGroupPort struct {
	Protocol string
	Port     int32
}

// SecurityGroupStatus is the observed state of a SecurityGroup.
type SecurityGroupStatus struct {
	ID         int32
	Phase      SecurityGroupPhase
	Conditions []metav1.Condition
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityGroup is intra-VPC network policy (AWS-security-group-shaped):
// destination-side eBPF enforcement of label-selected membership and
// group/CIDR ingress rules within a single VPC.
type SecurityGroup struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   SecurityGroupSpec
	Status SecurityGroupStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// SecurityGroupList is a list of SecurityGroup objects.
type SecurityGroupList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []SecurityGroup
}

// HostFirewallSpec selects nodes and declares what may reach them.
type HostFirewallSpec struct {
	NodeSelector metav1.LabelSelector
	PolicyTypes  []HostFirewallPolicyType
	Ingress      []HostFirewallRule
	Egress       []HostFirewallEgressRule
}

// HostFirewallPolicyType is a direction a HostFirewall isolates.
type HostFirewallPolicyType string

const (
	// HostFirewallPolicyTypeIngress isolates traffic TO the node.
	HostFirewallPolicyTypeIngress HostFirewallPolicyType = "Ingress"
	// HostFirewallPolicyTypeEgress isolates traffic FROM the node.
	HostFirewallPolicyTypeEgress HostFirewallPolicyType = "Egress"
)

// HostFirewallEgressRule admits node-originated traffic to destinations.
type HostFirewallEgressRule struct {
	To    []HostFirewallPeer
	Ports []HostFirewallPort
}

// HostFirewallRule admits sources to ports. An empty From admits any source;
// an empty Ports admits every TCP and UDP port.
type HostFirewallRule struct {
	From  []HostFirewallPeer
	Ports []HostFirewallPort
}

// HostFirewallPeer is an admitted source range.
type HostFirewallPeer struct {
	CIDR   string
	Except []string
}

// HostFirewallPort is a protocol/port an ingress rule admits.
type HostFirewallPort struct {
	Protocol string
	Port     int32
	EndPort  int32
}

// HostFirewallStatus is the observed state of a HostFirewall.
type HostFirewallStatus struct {
	Conditions []metav1.Condition
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HostFirewall is a cluster-scoped, operator-owned ingress policy for the
// nodes themselves — the node-scoped sibling of NetworkPolicy (default-network
// pods) and SecurityGroup (VPC ports). See docs/host-firewall.md.
type HostFirewall struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   HostFirewallSpec
	Status HostFirewallStatus
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// HostFirewallList is a list of HostFirewall objects.
type HostFirewallList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []HostFirewall
}
