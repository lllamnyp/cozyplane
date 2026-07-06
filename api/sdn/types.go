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

	// Egress configures how workloads in this VPC reach destinations outside
	// it. Nil means no egress: the VPC is a closed island for outbound traffic.
	Egress *VPCEgress
}

// VPCEgress is the egress configuration of a VPC.
type VPCEgress struct {
	// NATGateway runs a per-VPC gateway that forwards off-VPC traffic
	// (masqueraded) to the outside world and cluster DNS, while everything
	// else internal stays denied.
	NATGateway bool
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
	FabricIP     string
	MAC          string
	Node         string
	NodeIP       string
	PodNamespace string
	PodName      string

	// Gateway marks the VPC's gateway port (the .1 leg of the egress gateway
	// pod); agents route off-VPC traffic to it.
	Gateway bool
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// Port is a pod's realized interface on a VPC.
type Port struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec PortSpec
}

// ExternalPoolAdvertisement is how a pool's addresses are announced to the
// physical network.
type ExternalPoolAdvertisement string

const (
	// ExternalPoolAdvertisementL2 announces each in-use address with gratuitous
	// ARP/NDP from the node currently anchoring it.
	ExternalPoolAdvertisementL2 ExternalPoolAdvertisement = "L2"
	// ExternalPoolAdvertisementBGP announces addresses over BGP (not yet
	// implemented; reserved).
	ExternalPoolAdvertisementBGP ExternalPoolAdvertisement = "BGP"
)

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalPoolList is a list of ExternalPool objects.
type ExternalPoolList struct {
	metav1.TypeMeta
	metav1.ListMeta

	Items []ExternalPool
}

// ExternalPoolSpec is the specification of a pool of externally-routable
// addresses that FloatingIPs are allocated from.
type ExternalPoolSpec struct {
	// CIDRs are the address ranges the pool hands out.
	CIDRs []string

	// Advertisement is how in-use addresses are announced to the physical
	// network. Empty selects the controller default (L2).
	Advertisement ExternalPoolAdvertisement
}

// ExternalPoolStatus is the observed state of an ExternalPool.
type ExternalPoolStatus struct {
	// Allocated is the number of addresses currently bound to FloatingIPs.
	Allocated int32

	// Available is the number of addresses still free in the pool.
	Available int32

	// Conditions represent the latest available observations.
	Conditions []metav1.Condition
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ExternalPool is a cluster-scoped, admin-defined range of externally-routable
// addresses. FloatingIPs claim addresses from a pool; a pool is the equivalent
// of MetalLB's IPAddressPool.
type ExternalPool struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   ExternalPoolSpec
	Status ExternalPoolStatus
}

// ExternalPoolRef references an ExternalPool by name (pools are cluster-scoped).
type ExternalPoolRef struct {
	Name string
}

// FloatingIPPhase is the lifecycle phase of a FloatingIP.
type FloatingIPPhase string

const (
	// FloatingIPPhasePending means the FloatingIP has no address assigned yet
	// (pool exhausted, requested address taken, or not yet reconciled).
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

	// PoolRef selects the ExternalPool to allocate from. Empty selects the
	// default pool.
	PoolRef ExternalPoolRef

	// Address optionally requests a specific address from the pool; empty lets
	// the controller pick a free one.
	Address string
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

// FloatingIP binds an externally-routable address from an ExternalPool to a
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
