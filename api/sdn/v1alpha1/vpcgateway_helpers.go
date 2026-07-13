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

// EffectiveGateway returns the VPC's one legitimate boundary: the OLDEST
// VPCGateway naming it. Nil means the VPC has no boundary — no way out (no NAT
// egress) and no way in (no LoadBalancer ingress), and no owner for the bytes
// that would have crossed.
//
// It lives here, not in a controller, because three independent things must agree
// on the answer — the controller that realizes the gateway pod, the CNI that gives
// that pod its VPC leg, and the agent that opens the ingress gate — and they must
// agree even before any status has been written. "Oldest wins" is computable from
// the objects alone, so it is not something they can disagree about.
func EffectiveGateway(gws []VPCGateway, vpcName string) *VPCGateway {
	var best *VPCGateway
	for i := range gws {
		g := &gws[i]
		if g.Spec.VPCRef.Name != vpcName || !g.DeletionTimestamp.IsZero() {
			continue
		}
		if best == nil ||
			g.CreationTimestamp.Time.Before(best.CreationTimestamp.Time) ||
			(g.CreationTimestamp.Equal(&best.CreationTimestamp) && g.Name < best.Name) {
			best = g
		}
	}
	return best
}
