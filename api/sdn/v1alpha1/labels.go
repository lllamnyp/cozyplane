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

	// LabelVPC is the referenced VPC's name.
	LabelVPC = "sdn.cozystack.io/vpc"
	// LabelVPCNamespace is the referenced VPC's (owner) namespace.
	LabelVPCNamespace = "sdn.cozystack.io/vpc-namespace"
	// LabelPodNamespace is the attached pod's namespace (the consumer side).
	LabelPodNamespace = "sdn.cozystack.io/pod-namespace"
	// LabelPodName is the attached pod's name.
	LabelPodName = "sdn.cozystack.io/pod-name"
	// LabelPodUID is the attached pod's UID (stable across name reuse).
	LabelPodUID = "sdn.cozystack.io/pod-uid"
)
