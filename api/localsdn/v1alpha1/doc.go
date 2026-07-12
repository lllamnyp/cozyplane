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

// +k8s:deepcopy-gen=package
// +groupName=local.sdn.cozystack.io

// Package v1alpha1 is the local (CRD-served) half of the cozyplane API — the
// layer whose dependency floor is the kube API and nothing else
// (docs/api-groups.md).
//
// Everything here is served by CustomResourceDefinitions that ship with the
// CNI, so it works before cert-manager, before etcd, and before cozyplane's own
// aggregated apiserver — all of which run as default-network pods and therefore
// sit ON TOP of this layer. There is no conversion-gen and no internal version:
// CRDs serve the versioned types directly.
//
// The tenant-facing API (VPCs, Ports, policies) lives in the SEPARATE
// sdn.cozystack.io group, served only by the aggregated apiserver. The groups
// hold disjoint kinds on purpose: one group served by two mechanisms makes the
// kube-apiserver's OpenAPI merge collide on duplicated paths, which silently
// breaks `kubectl apply` for every object in the group.
package v1alpha1
