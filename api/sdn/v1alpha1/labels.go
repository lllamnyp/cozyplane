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

// Label and annotation keys shared across components. The CNI plugin writes
// these labels onto Ports; the controller selects on them to reap Ports when a
// VPCBinding is removed. Defining them here keeps the writer and reader from
// drifting apart.
const (
	// AnnotationVPC on a pod requests attachment to a VPC. Its value is
	// "<vpc>" (owner namespace defaults to the pod's namespace) or
	// "<owner-ns>/<vpc>".
	AnnotationVPC = "sdn.cozystack.io/vpc"

	// AnnotationRouteTable on a pod names the RouteTable, in the VPC's
	// namespace, that routes the pod's traffic. Absent means the VPC's default
	// table (docs/vpc-egress.md §2.4).
	AnnotationRouteTable = "sdn.cozystack.io/route-table"

	// AnnotationGatewayFor on a (default-network, system-namespace) pod makes
	// it the egress gateway of a VPC: it gets a second interface carrying the
	// VPC's reserved .1 address. Same value syntax as AnnotationVPC. Honored
	// only for pods in the agent's own (system) namespace, and only when the
	// VPC has spec.egress.natGateway enabled.
	AnnotationGatewayFor = "sdn.cozystack.io/gateway-for"

	// AnnotationVPCIP is an annotation key holding a copy of the object's VPC IP.
	AnnotationVPCIP = "sdn.cozystack.io/vpc-ip"
	// AnnotationVPCMAC is an annotation key holding a copy of the pod's VPC MAC.
	AnnotationVPCMAC = "sdn.cozystack.io/vpc-mac"

	// LabelVPC is the referenced VPC's name.
	LabelVPC = "sdn.cozystack.io/vpc"
	// LabelVPCNamespace is the referenced VPC's (owner) namespace.
	LabelVPCNamespace = "sdn.cozystack.io/vpc-namespace"
	// LabelServiceNamespace and LabelServiceName identify the Kubernetes
	// Service a ServiceVIP fronts (mirroring the pod labels on a Port), so a
	// service's VIP is found by label selection.
	LabelServiceNamespace = "sdn.cozystack.io/service-namespace"
	LabelServiceName      = "sdn.cozystack.io/service-name"

	// LabelPodNamespace is the attached pod's namespace (the consumer side).
	LabelPodNamespace = "sdn.cozystack.io/pod-namespace"
	// LabelPodName is the attached pod's name.
	LabelPodName = "sdn.cozystack.io/pod-name"
	// LabelPodUID is the attached pod's UID (stable across name reuse).
	LabelPodUID = "sdn.cozystack.io/pod-uid"

	// AnnotationPodLabels carries a copy of the attached pod's labels, stamped
	// by the CNI plugin at ADD time. The controller evaluates every
	// SecurityGroup.podSelector against it to resolve the Port's group
	// membership (Port.status.groups) — membership is claim-time, so the copy
	// need not track later pod-label edits in v1. JSON-encoded map[string]string.
	AnnotationPodLabels = "sdn.cozystack.io/pod-labels"

	// AnnotationPortClaim on a pod names the PortClaim, in the pod's namespace, whose Port the pod binds; set by the pod's author.
	AnnotationPortClaim = "sdn.cozystack.io/port-claim"

	// LabelClaimNamespace is the namespace of the PortClaim a Port belongs to; written by the CNI plugin.
	LabelClaimNamespace = "sdn.cozystack.io/claim-namespace"
	// LabelClaimName is the name of the PortClaim a Port belongs to; written by the CNI plugin.
	LabelClaimName = "sdn.cozystack.io/claim-name"
	// LabelClaimUID is the UID of the PortClaim a Port belongs to; written by the CNI plugin.
	LabelClaimUID = "sdn.cozystack.io/claim-uid"

	// LabelVMName marks a Port created for a VM before PortClaim existed; read only to adopt it into a PortClaim.
	LabelVMName = "sdn.cozystack.io/vm-name"

	// FinalizerPortClaim holds a PortClaim until its Port is gone.
	FinalizerPortClaim = "sdn.cozystack.io/port"

	// FinalizerSever holds a Port until the agent on its node has severed the
	// live datapath (or confirmed there is nothing to sever). A revocation
	// that lands while that agent is down therefore waits, still terminating,
	// and is replayed when the agent comes back — the informer's initial sync
	// delivers the terminating Port. The controller strips the finalizer when
	// the Port's node no longer exists.
	FinalizerSever = "sdn.cozystack.io/sever"
)
