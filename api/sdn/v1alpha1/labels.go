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

	// AnnotationGatewayFor on a (default-network, system-namespace) pod makes
	// it the egress gateway of a VPC: it gets a second interface carrying the
	// VPC's reserved .1 address. Same value syntax as AnnotationVPC. Honored
	// only for pods in the agent's own (system) namespace, and only when the
	// VPC has spec.egress.natGateway enabled.
	AnnotationGatewayFor = "sdn.cozystack.io/gateway-for"

	// AnnotationVPCIP and AnnotationVPCMAC are stamped BY the CNI ONTO the pod: the
	// VPC address and MAC it just allocated. They are how a tenant learns its own
	// network identity (docs/multitenancy.md R1).
	//
	// Without them a tenant cannot discover its own address at all. `status.podIP`
	// is the FABRIC IP — the underlay handle the platform routes and kubelet probes
	// — not the address the pod's own interface carries and not the address anything
	// inside the VPC uses. The real identity lives on the cluster-scoped Port, which
	// a tenant may never read (R2), so it would be invisible.
	//
	// They are a CACHE, never a source of truth: the Port is authoritative, nothing
	// reads these back, and their lifetime is exactly the claim's — the pod dies and
	// they die with it. That is deliberate. A namespaced object COPYING the address
	// would be the stale-copy bug rebuilt (we deleted Port.spec.fabricIP for exactly
	// that reason); an annotation on the object the address belongs to cannot drift
	// away from its owner.
	AnnotationVPCIP  = "sdn.cozystack.io/vpc-ip"
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

	// LabelVMName marks a *persistent* Port and records the VM identity it is
	// pinned to (the KubeVirt VM name, within LabelPodNamespace). A virt-launcher
	// pod's CNI ADD binds to the persistent Port for its VM instead of claiming a
	// fresh one, so the VPC IP + MAC survive pod churn and live migration. The
	// persistent-Port controller selects on this to drive migration cutover and GC.
	LabelVMName = "sdn.cozystack.io/vm-name"

	// KubeVirt labels on a virt-launcher pod, read to recognize a VM NIC and drive
	// migration. The stable VM identity is (namespace, KubeVirtLabelVMName); the
	// pod carrying the active binding has KubeVirtLabelNodeName equal to its own
	// node (KubeVirt sets it on the migration target only after cutover).
	KubeVirtLabelApp      = "kubevirt.io" // value "virt-launcher" on VM pods
	KubeVirtLabelVMName   = "vm.kubevirt.io/name"
	KubeVirtLabelNodeName = "kubevirt.io/nodeName"
	KubeVirtLabelVMIUID   = "kubevirt.io/created-by" // the VMI UID (stable across migration)

	// FinalizerSever holds a Port until the agent on its node has severed the
	// live datapath (or confirmed there is nothing to sever). A revocation
	// that lands while that agent is down therefore waits, still terminating,
	// and is replayed when the agent comes back — the informer's initial sync
	// delivers the terminating Port. The controller strips the finalizer when
	// the Port's node no longer exists.
	FinalizerSever = "sdn.cozystack.io/sever"
)
