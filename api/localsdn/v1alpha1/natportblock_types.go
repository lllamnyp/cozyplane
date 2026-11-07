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
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// Labels every NATPortBlock carries, so a NAT gateway's or a node's leases can be
// listed by selector.
const (
	LabelNATGatewayUID = "local.sdn.cozystack.io/natgateway-uid"
	LabelNATBlockNode  = "local.sdn.cozystack.io/node"
)

// A NAT gateway's ports 1024..65535 are cut into blocks (docs/vpc-egress.md
// §4.3). Must match NAT_BASE_PORT in bpf/overlay.c.
const (
	NATBasePort = 1024
	NATPortSpan = 65536 - NATBasePort
)

// NATBlocks is the number of blocks in a NAT gateway's port space at a block size.
func NATBlocks(blockSize int) int {
	if blockSize <= 0 {
		return 0
	}
	return NATPortSpan / blockSize
}

// NATBlockOf returns the block a host-order port belongs to, or -1.
func NATBlockOf(port uint16, blockSize int) int {
	if blockSize <= 0 || int(port) < NATBasePort {
		return -1
	}
	return (int(port) - NATBasePort) / blockSize
}

// NATPortBlockName is the name of the lease on `block` of the NAT gateway with
// `uid`. The NAME is the claim: two agents racing for one block cannot both
// create it (docs/vpc-egress.md §2.5).
func NATPortBlockName(uid types.UID, block int) string {
	return string(uid) + "." + strconv.Itoa(block)
}

// NATGatewayReference identifies the NAT gateway a lease belongs to.
type NATGatewayReference struct {
	Namespace string    `json:"namespace"`
	Name      string    `json:"name"`
	UID       types.UID `json:"uid"`
}

// NATPortBlockSpec records which node holds which block of which NAT gateway.
type NATPortBlockSpec struct {
	// NATGatewayRef is the NAT gateway whose port space the block belongs to.
	NATGatewayRef NATGatewayReference `json:"natGatewayRef"`
	// Block is the block number: ports 1024+Block*blockSize up to the next block.
	Block int32 `json:"block"`
	// Node is the node that holds the block.
	Node string `json:"node"`
}

// NATPortBlockAck records that one node's agent has programmed this block's owner.
type NATPortBlockAck struct {
	Node string `json:"node"`
}

// NATPortBlockStatus carries the per-node acknowledgements.
type NATPortBlockStatus struct {
	// Acks lists the nodes whose agent has programmed this block's owner. The
	// holder allocates from the block only once every Ready node is listed.
	// Each agent server-side-applies its own entry.
	// +optional
	// +listType=map
	// +listMapKey=node
	Acks []NATPortBlockAck `json:"acks,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="NATGateway",type=string,JSONPath=`.spec.natGatewayRef.name`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.natGatewayRef.namespace`
// +kubebuilder:printcolumn:name="Block",type=integer,JSONPath=`.spec.block`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.node`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// NATPortBlock is one node's lease on one block of one NAT gateway's port space
// (docs/vpc-egress.md §2.5, §4.3).
type NATPortBlock struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NATPortBlockSpec   `json:"spec,omitempty"`
	Status NATPortBlockStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NATPortBlockList contains a list of NATPortBlock.
type NATPortBlockList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NATPortBlock `json:"items"`
}
