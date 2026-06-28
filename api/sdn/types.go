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
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPC is a tenant overlay network.
type VPC struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   VPCSpec
	Status VPCStatus
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
	VPC          string
	IP           string
	MAC          string
	Node         string
	NodeIP       string
	PodNamespace string
	PodName      string
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
