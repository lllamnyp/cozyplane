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

// Condition types surfaced in RouteTable status (docs/vpc-egress.md §2.2).
const (
	// RouteTableConditionVPCResolved is True when spec.vpcRef names a VPC in this
	// namespace.
	RouteTableConditionVPCResolved = "VPCResolved"
	// RouteTableConditionDefault is True when this table is the VPC's default
	// table. A table with spec.default that is not the oldest such table reports
	// False with reason NotOldest.
	RouteTableConditionDefault = "Default"
)

// RouteTableSpec declares a route table of a VPC.
type RouteTableSpec struct {
	// VPCRef is the VPC this table belongs to, in this namespace. Immutable.
	VPCRef LocalVPCRef `json:"vpcRef"`
	// Default makes this the table of every Port of the VPC whose pod names no
	// table. At most one table per VPC is the default: the oldest wins.
	// +optional
	Default bool `json:"default,omitempty"`
}

// RouteTableStatus is the observed state of a RouteTable.
type RouteTableStatus struct {
	// ID is the cluster-unique datapath identifier of this table, allocated by
	// the controller (1..2^24-1). Zero means unallocated.
	// +optional
	ID int32 `json:"id,omitempty"`
	// Conditions is the detailed state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="VPC",type=string,JSONPath=`.spec.vpcRef.name`
// +kubebuilder:printcolumn:name="Default",type=boolean,JSONPath=`.spec.default`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RouteTable is a route table of a VPC. It holds no routes itself; Route objects
// reference it. A pod chooses its table with the sdn.cozystack.io/route-table
// annotation (docs/vpc-egress.md §2.4).
type RouteTable struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RouteTableSpec   `json:"spec,omitempty"`
	Status RouteTableStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteTableList contains a list of RouteTable.
type RouteTableList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RouteTable `json:"items"`
}

// RouteState is the controller's verdict on a Route (docs/vpc-egress.md §3.3).
type RouteState string

const (
	// RouteStateActive means the route is programmed as declared.
	RouteStateActive RouteState = "Active"
	// RouteStateUnresolved means the route cannot be honoured; it is programmed
	// as a blackhole so its traffic does not fall to a shorter route.
	RouteStateUnresolved RouteState = "Unresolved"
	// RouteStateConflict means an older Route in the same table has the same
	// destination; this one is not programmed.
	RouteStateConflict RouteState = "Conflict"
)

// RouteConditionResolved is True when the route is Active.
const RouteConditionResolved = "Resolved"

// LocalRouteTableRef references a RouteTable in the referring object's namespace.
type LocalRouteTableRef struct {
	// Name is the RouteTable name.
	Name string `json:"name"`
}

// LocalNATGatewayRef references a NATGateway in the referring object's namespace.
type LocalNATGatewayRef struct {
	// Name is the NATGateway name.
	Name string `json:"name"`
}

// RouteInternetTarget is the internet pseudo-target. It has no fields.
type RouteInternetTarget struct{}

// RouteBlackholeTarget is the blackhole target. It has no fields.
type RouteBlackholeTarget struct{}

// RouteTarget is where a route sends matching traffic. Exactly one field is set.
type RouteTarget struct {
	// NATGateway SNATs the traffic to the named NAT gateway's address of the
	// packet's family, for every source (docs/vpc-egress.md §3.2).
	// +optional
	NATGateway *LocalNATGatewayRef `json:"natGateway,omitempty"`
	// Internet sends the traffic out as the source Port's FloatingIP; a Port
	// without one is dropped.
	// +optional
	Internet *RouteInternetTarget `json:"internet,omitempty"`
	// Blackhole drops the traffic.
	// +optional
	Blackhole *RouteBlackholeTarget `json:"blackhole,omitempty"`
}

// RouteSpec declares one route: a destination and a target.
type RouteSpec struct {
	// RouteTableRef is the table this route belongs to, in this namespace.
	RouteTableRef LocalRouteTableRef `json:"routeTableRef"`
	// Destination is the canonical CIDR this route matches (v4 or v6).
	Destination string `json:"destination"`
	// Target is where matching traffic goes.
	Target RouteTarget `json:"target"`
}

// RouteStatus is the observed state of a Route.
type RouteStatus struct {
	// State is the controller's verdict.
	// +optional
	State RouteState `json:"state,omitempty"`
	// Conditions is the detailed state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Table",type=string,JSONPath=`.spec.routeTableRef.name`
// +kubebuilder:printcolumn:name="Destination",type=string,JSONPath=`.spec.destination`
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.state`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Route is one destination and one target in a RouteTable, kept as its own object
// so different owners can manage the routes of one table (docs/vpc-egress.md §2.3).
type Route struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RouteSpec   `json:"spec,omitempty"`
	Status RouteStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// RouteList contains a list of Route.
type RouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Route `json:"items"`
}
