#!/usr/bin/env bash
# Act 2 — peer the two VPCs; the same pings start working.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 2: VPC peering"

note "a peering is two halves — each tenant consents in its own namespace:"
kubectl apply -f - <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: red-to-blue, namespace: $RED_NS}
spec: {vpcRef: {name: $RED_VPC}, peerRef: {namespace: $BLUE_NS, name: $BLUE_VPC}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: blue-to-red, namespace: $BLUE_NS}
spec: {vpcRef: {name: $BLUE_VPC}, peerRef: {namespace: $RED_NS, name: $RED_VPC}}
EOF

for _ in $(seq 30); do
  p1=$(kubectl -n "$RED_NS"  get vpcpeering red-to-blue -o jsonpath='{.status.phase}' 2>/dev/null || true)
  p2=$(kubectl -n "$BLUE_NS" get vpcpeering blue-to-red -o jsonpath='{.status.phase}' 2>/dev/null || true)
  [ "$p1" = Ready ] && [ "$p2" = Ready ] && break
  sleep 1
done
note "phases: red-to-blue=$p1  blue-to-red=$p2 (both must be Ready)"
try "kubectl get vpcpeerings -A"

BLUE1=$(vpcip blue-1); RED1=$(vpcip red-1)

note "back in red-1 — the ping that just failed now works:"
try "ping -c3 $BLUE1     # blue-1, across VPCs"
note "and it is symmetric; from blue-1, red-1 answers too:"
try "kubectl -n $BLUE_NS exec -it blue-1 -- ping -c3 $RED1"

note "worth saying out loud:"
plain "- one half alone stays Pending — no unilateral access; either side deletes"
plain "  its half and the path closes again."
plain "- peering requires disjoint CIDRs (overlapping VPCs are refused: the"
plain "  controller keeps the peering Pending), which is why red is $RED_CIDR"
plain "  and blue is $BLUE_CIDR."
