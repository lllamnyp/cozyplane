#!/usr/bin/env bash
# Act 1 — two tenants, two VPCs, and isolation that ignores placement.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 1: two VPCs, three pods"

read -r NODE1 NODE2 <<<"$(two_nodes | tr '\n' ' ')"
[ -n "${NODE2:-}" ] || { echo "need at least two Ready nodes"; exit 1; }

kubectl create ns "$RED_NS"  --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl create ns "$BLUE_NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

kubectl apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: $RED_VPC, namespace: $RED_NS}
spec: {cidrs: ["$RED_CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: $RED_VPC, namespace: $RED_NS}
spec: {vpcRef: {namespace: $RED_NS, name: $RED_VPC}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: $BLUE_VPC, namespace: $BLUE_NS}
spec: {cidrs: ["$BLUE_CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: $BLUE_VPC, namespace: $BLUE_NS}
spec: {vpcRef: {namespace: $BLUE_NS, name: $BLUE_VPC}}
EOF

# red-1 and blue-1 deliberately share a node; red-2 is across the overlay.
netshoot_pod "$RED_NS"  red-1  "$NODE1" "$RED_VPC"
netshoot_pod "$RED_NS"  red-2  "$NODE2" "$RED_VPC"
netshoot_pod "$BLUE_NS" blue-1 "$NODE1" "$BLUE_VPC"

note "waiting for pods (first run pulls netshoot)..."
kubectl -n "$RED_NS"  wait --for=condition=Ready pod/red-1 pod/red-2 --timeout=180s >/dev/null
kubectl -n "$BLUE_NS" wait --for=condition=Ready pod/blue-1          --timeout=180s >/dev/null

RED1=$(vpcip red-1); RED2=$(vpcip red-2); BLUE1=$(vpcip blue-1)

note "what exists now:"
printf '        %-8s %-11s %-14s %-12s %s\n' POD VPC "VPC IP" NODE ""
printf '        %-8s %-11s %-14s %-12s %s\n' red-1  "$RED_NS/$RED_VPC"   "$RED1"  "$NODE1" ""
printf '        %-8s %-11s %-14s %-12s %s\n' red-2  "$RED_NS/$RED_VPC"   "$RED2"  "$NODE2" "<- other node"
printf '        %-8s %-11s %-14s %-12s %s\n' blue-1 "$BLUE_NS/$BLUE_VPC" "$BLUE1" "$NODE1" "<- SAME node as red-1"

note "the tenant objects, if you want to show them:"
try "kubectl -n $RED_NS get vpc,vpcbinding,pods -o wide && kubectl get ports"

note "hop into red-1:"
try "kubectl -n $RED_NS exec -it red-1 -- bash"

note "inside a VPC, across nodes — this works (Geneve overlay, node1 -> node2):"
try "ping -c3 $RED2      # red-2"

note "across VPCs — this dies, even though blue-1 is on the SAME node as red-1:"
try "ping -c3 $BLUE1     # blue-1: default-deny at the VPC boundary"

note "the point: isolation keys on identity (VPC/VNI), never on placement or IP ranges."
note "no NetworkPolicy, no SecurityGroup, no iptables rule was created for this."
