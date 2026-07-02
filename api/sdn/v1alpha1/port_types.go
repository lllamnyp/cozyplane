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

// VPCRef references a VPC by namespace and name. The namespace is the VPC
// owner's namespace, not necessarily the referrer's.
type VPCRef struct {
	// Namespace is the namespace that owns the VPC.
	Namespace string `json:"namespace"`
	// Name is the VPC name within that namespace.
	Name string `json:"name"`
}

// PortSpec is the realized network interface of a pod on a VPC.
//
// A Port is cluster-scoped and its name encodes the VPC's VNI and the IP
// (v<vni>.<ip-with-dashes>), so creating it is an atomic claim on that IP within
// the VPC — etcd name uniqueness serializes concurrent allocators. The VNI is
// globally unique, so the name stays unique even though VPCs are namespaced.
type PortSpec struct {
	// VPCRef identifies the VPC this port belongs to (owner namespace + name).
	VPCRef VPCRef `json:"vpcRef"`

	// IP is the address allocated to the pod within the VPC CIDR (the tenant
	// address configured inside the pod).
	IP string `json:"ip"`

	// FabricIP is the pod's status.podIP: a unique address from the node pod
	// CIDR, reachable on the default overlay, that the bridge DNATs to IP.
	// +optional
	FabricIP string `json:"fabricIP,omitempty"`

	// MAC is the pod interface MAC address.
	// +optional
	MAC string `json:"mac,omitempty"`

	// Node is the name of the node hosting the pod.
	Node string `json:"node"`

	// NodeIP is the host IP of that node (the Geneve tunnel endpoint).
	NodeIP string `json:"nodeIP"`

	// PodNamespace and PodName identify the owning pod.
	// +optional
	PodNamespace string `json:"podNamespace,omitempty"`
	// +optional
	PodName string `json:"podName,omitempty"`

	// Gateway marks the VPC's gateway port (the .1 leg of the egress gateway
	// pod); agents route off-VPC traffic to it.
	// +optional
	Gateway bool `json:"gateway,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="VPCNamespace",type=string,JSONPath=`.spec.vpcRef.namespace`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.spec.ip`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.node`
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`

// Port is a pod's realized interface on a VPC.
type Port struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PortSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// PortList contains a list of Port.
type PortList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Port `json:"items"`
}
