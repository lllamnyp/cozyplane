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

// VPCBindingSpec authorizes pods in the binding's (consumer) namespace to attach
// to the referenced VPC.
type VPCBindingSpec struct {
	// VPCRef is the VPC being made usable, identified by owner namespace + name.
	VPCRef VPCRef `json:"vpcRef"`

	// AllowForwarding lets a pod attached under this binding emit packets whose
	// source address is not its own — what a router, firewall or NFV workload
	// bridging two VPCs must do (docs/multi-attach.md).
	//
	// It is a GRANT, and it lives here rather than on the pod for a reason.
	// from_pod runs a source-address RPF check per interface: the source must
	// resolve, in `locals`, to the very veth it was emitted on. A pod's
	// SecurityGroup identity is keyed on that source IP, so lifting the check
	// hands the workload the ability to impersonate ANY member of the VPC and
	// inherit its groups. That is the capability AWS spells
	// `sourceDestCheck: false`, and it belongs to whoever owns the network.
	//
	// A VPCBinding is created by whoever holds the `export` verb on the
	// referenced VPC — the VPC's owner, not the tenant consuming it — so the
	// grant sits at the right level of authority and is visible in RBAC instead
	// of living in an operator's head.
	// +optional
	AllowForwarding bool `json:"allowForwarding,omitempty"`

	// ForwardingCIDRs narrows AllowForwarding to declared remote prefixes
	// (issue #6). Empty (the default) keeps the blanket grant above — any
	// foreign source. Non-empty scopes it: the datapath admits a foreign source
	// ONLY when it falls within one of these CIDRs, and anti-spoofing stays on
	// for everything else. This is the difference between "this VM is a VPN
	// endpoint for 10.50.0.0/16" and "this VM may impersonate anything" — and it
	// is exactly what kube-ovn cannot express (its allowed-address-pair takes
	// host IPs only). Ignored unless AllowForwarding is set.
	// +optional
	ForwardingCIDRs []string `json:"forwardingCIDRs,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:printcolumn:name="VPCNamespace",type=string,JSONPath=`.spec.vpcRef.namespace`
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// VPCBinding grants pods in its own (consumer) namespace permission to attach to
// the VPC named in spec.vpcRef. It is created by the VPC owner reaching into the
// consumer namespace (gated by RBAC create here + an export SAR on the VPC), and
// its existence is the namespace-keyed, datapath-readable authorization the CNI
// checks at attach time. A VPC's namespace expresses ownership; a VPCBinding
// expresses use — required even when the pod and VPC share a namespace.
type VPCBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec VPCBindingSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// VPCBindingList contains a list of VPCBinding.
type VPCBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []VPCBinding `json:"items"`
}
