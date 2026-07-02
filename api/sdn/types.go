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
