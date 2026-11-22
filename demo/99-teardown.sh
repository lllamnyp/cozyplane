#!/usr/bin/env bash
# Tear the whole demo down. Safe to run at any point.
cd "$(dirname "$0")" && . ./lib.sh

banner "Teardown"

# VM and its PortClaim first: deleting the claim releases the pinned Port.
kubectl -n "$RED_NS" delete vm "$VM" --ignore-not-found --wait=true
kubectl -n "$RED_NS" delete portclaim "$VM" --ignore-not-found --wait=true
kubectl delete ns "$RED_NS" "$BLUE_NS" --ignore-not-found --wait=true
note "namespaces gone; Ports are owner-referenced and follow their pods/VPCs."
try "kubectl get ports   # nothing of demo-red/demo-blue should remain"
