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

// EffectiveDefaultTable returns the VPC's default RouteTable among `tables`: the
// oldest with spec.default, ties broken by name (docs/vpc-egress.md §2.2), or
// nil. It lives here because the controller, which reports the verdict, and the
// agent, which programs it, must agree without coordinating.
func EffectiveDefaultTable(tables []*RouteTable, vpcName string) *RouteTable {
	var best *RouteTable
	for _, t := range tables {
		if t.Spec.VPCRef.Name != vpcName || !t.Spec.Default || !t.DeletionTimestamp.IsZero() {
			continue
		}
		if best == nil || t.CreationTimestamp.Before(&best.CreationTimestamp) ||
			(t.CreationTimestamp.Equal(&best.CreationTimestamp) && t.Name < best.Name) {
			best = t
		}
	}
	return best
}
