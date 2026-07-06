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

// ServiceVIPPhase is the lifecycle phase of a ServiceVIP.
// +kubebuilder:validation:Enum=Pending;Ready
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
	Namespace string `json:"namespace"`
	// Name of the Service.
	Name string `json:"name"`
}

// VIPPort is one service port the VIP serves.
type VIPPort struct {
	// Name of the service port (may be empty for a single unnamed port).
	// +optional
	Name string `json:"name,omitempty"`
	// Protocol is TCP or UDP.
	Protocol string `json:"protocol"`
	// Port is the service port the VIP listens on.
	Port int32 `json:"port"`
}

// VIPBackendPort is one resolved (service port -> target port) pair on a
// backend.
type VIPBackendPort struct {
	// Protocol is TCP or UDP.
	Protocol string `json:"protocol"`
	// Port is the service port on the VIP.
	Port int32 `json:"port"`
	// TargetPort is the resolved numeric port on the backend.
	TargetPort int32 `json:"targetPort"`
}

// VIPBackend is one ready backend of the service, resolved to its Port's VPC
// address.
type VIPBackend struct {
	// IP is the backend's VPC IP (never the fabric IP).
	IP string `json:"ip"`
	// Ports are the resolved per-port targets on this backend.
	Ports []VIPBackendPort `json:"ports,omitempty"`
}

// ServiceVIPSpec is the materialized ClusterIP-equivalent of a Service
// attached to a VPC (docs/services-in-vpc.md).
//
// The controller creates one per attached non-headless Service (the pod->Port
// idiom: the Service carries the sdn.cozystack.io/vpc annotation, the system
// materializes this object). Like a Port, it is cluster-scoped and its name
// encodes the VPC's VNI and the VIP (sv<vni>.<ip-with-dashes>), so creating it
// is an atomic claim on that address among ServiceVIPs; cross-kind uniqueness
// against Ports is enforced by the shared allocator view and the registry (a
// Port always wins a conflict — the VIP is the movable kind, nothing addresses
// it except through a DNS answer).
type ServiceVIPSpec struct {
	// VPCRef identifies the VPC this VIP belongs to (owner namespace + name).
	VPCRef VPCRef `json:"vpcRef"`

	// IP is the virtual address allocated from the VPC's own address space.
	IP string `json:"ip"`

	// ServiceRef is the Kubernetes Service this VIP fronts.
	ServiceRef ServiceRef `json:"serviceRef"`

	// Ports are the service ports the VIP serves.
	// +optional
	Ports []VIPPort `json:"ports,omitempty"`

	// SessionAffinity mirrors the Service's: "ClientIP" pins every connection
	// from one client to the same backend; "None" (default) load-balances
	// per connection.
	// +optional
	SessionAffinity string `json:"sessionAffinity,omitempty"`
}

// ServiceVIPStatus is the observed state of a ServiceVIP.
type ServiceVIPStatus struct {
	// Backends are the ready endpoints resolved to same-VPC Port addresses;
	// the agents program the datapath from this list.
	// +optional
	Backends []VIPBackend `json:"backends,omitempty"`

	// Phase is the current lifecycle phase.
	// +optional
	Phase ServiceVIPPhase `json:"phase,omitempty"`

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
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.spec.ip`
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.serviceRef.name`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// ServiceVIP is the ClusterIP-equivalent of a Service inside a VPC: a virtual
// address from the VPC's own space, load-balanced to backend VPC IPs by the
// datapath, discovered only through the split-horizon resolver.
type ServiceVIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ServiceVIPSpec   `json:"spec,omitempty"`
	Status ServiceVIPStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ServiceVIPList contains a list of ServiceVIP.
type ServiceVIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ServiceVIP `json:"items"`
}
