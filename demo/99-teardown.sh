#!/usr/bin/env bash
# Tear the whole demo down. Safe to run at any point.
cd "$(dirname "$0")" && . ./lib.sh

banner "Teardown"

# VM first: deleting it terminates the launcher pod and lets the
# persistent-Port controller GC the pinned Port.
kubectl -n "$RED_NS" delete vm "$VM" --ignore-not-found --wait=true
kubectl delete ns "$RED_NS" "$BLUE_NS" --ignore-not-found --wait=true
note "namespaces gone; Ports are owner-referenced and follow their pods/VPCs."
try "kubectl get ports   # nothing of demo-red/demo-blue should remain"
