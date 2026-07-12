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
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EscapeIP encodes an address into the name segment of a claim: `.` and `:`
// both become `-`. (The local group carries its own copy rather than importing
// the sdn group's — the lower layer must not depend on the upper one.)
func EscapeIP(ip string) string {
	return strings.NewReplacer(".", "-", ":", "-").Replace(ip)
}

// FabricIPName is the claim name of the underlay address `ip`. The NAME is the
// claim: creating it is the allocation, and the API server's name uniqueness is
// what makes it atomic cluster-wide. No lock file, no per-node range, no
// double-allocation.
func FabricIPName(ip string) string {
	return fmt.Sprintf("f-%s", EscapeIP(ip))
}

// FabricIPSpec records who holds an underlay address.
type FabricIPSpec struct {
	// Address is the canonical address this object claims (the name is its
	// escaped form). This is the underlay identity of a pod: `status.podIP` for
	// a default-network pod, and the fabric handle of a VPC pod.
	Address string `json:"address"`

	// Node is the node the claiming pod runs on. Informational for a flat pool
	// (delivery keys on the address, not the node), but it is what makes a
	// stranded address diagnosable.
	// +optional
	Node string `json:"node,omitempty"`

	// PodNamespace, PodName and PodUID identify the claimant. The UID is the
	// load-bearing one: GC keys on it, so a pod that reuses a name can never
	// have its address reaped by the previous occupant's DEL.
	// +optional
	PodNamespace string `json:"podNamespace,omitempty"`
	// +optional
	PodName string `json:"podName,omitempty"`
	// +optional
	PodUID string `json:"podUID,omitempty"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=fip
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.spec.address`
// +kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.node`
// +kubebuilder:printcolumn:name="Pod",type=string,JSONPath=`.spec.podName`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// FabricIP is a claim on one underlay address — the cluster-wide, API-backed
// replacement for the `host-local` IPAM plugin's per-node file store
// (docs/api-groups.md).
//
// The file store it replaces is released only by a CNI DEL, so a pod that
// disappears while kubelet is down leaks its address across the reboot, with no
// GC and no way to tell a live reservation from a ghost. A FabricIP is an
// object: the controller reaps it when its pod is gone, `kubectl get fabricips`
// shows who holds what, and the claim is atomic because the name IS the address.
type FabricIP struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec FabricIPSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// FabricIPList contains a list of FabricIP.
type FabricIPList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FabricIP `json:"items"`
}
