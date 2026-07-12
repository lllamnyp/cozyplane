#!/usr/bin/env bash
# VPC e2e: the tenant datapath, on any cluster already running cozyplane.
#
#   KCTX=<context> [KUBECONFIG=<path>] test/vpc-e2e.sh
#
# Companion to policy-e2e.sh (NetworkPolicy / HostFirewall / SecurityGroup).
# Together they cover, on a real cluster, everything the API-group split
# touched: Port and FabricIP as separate objects joined on the pod, the flat
# address pool, and the aggregated apiserver as the only server of the tenant
# kinds.
#
# What it does NOT cover: anything needing an off-cluster client on a docker
# network (floating-IP ingress, LoadBalancer ingress, north-south masquerade).
# Those live in test/e2e.sh, which builds its own kind cluster because the
# "external" client is a container on kind's network.
set -u
KCTX="${KCTX:?set KCTX}"
K="kubectl --context ${KCTX}"
NS="${NS:-vpc-e2e}"

FAILED=0
CHECKS=0
PASSED=0
SKIPPED=0
TOTAL=$(grep -cE '(^|[[:space:]])(pass|fail) "' "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)
TOTAL=$((TOTAL / 2))
PHASE=0
PHASE_TOTAL=$(grep -cE '^phase "' "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)
START=$(date +%s)

phase() {
  PHASE=$((PHASE + 1))
  echo
  echo "[phase ${PHASE}/${PHASE_TOTAL}] $* — ${CHECKS}/~${TOTAL} checks done, ${PASSED} passed, $((CHECKS - PASSED)) failed, $(( $(date +%s) - START ))s elapsed"
}
pass() { CHECKS=$((CHECKS + 1)); PASSED=$((PASSED + 1)); echo "  [${CHECKS}/~${TOTAL}] PASS: $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILED=1; echo "  [${CHECKS}/~${TOTAL}] FAIL: $*"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo "  [skip] $*"; }

cleanup() {
  echo
  echo "== cleanup =="
  [ "${KEEP:-0}" = "1" ] || $K delete ns "$NS" --wait=false >/dev/null 2>&1
}
trap cleanup EXIT INT TERM HUP

apply() { $K apply -f - >/dev/null || { echo "  FATAL: apply rejected"; exit 1; }; }
# Poll: VPC programming (Port claim, controller, agent maps) is eventually consistent.
served()  { for _ in $(seq 1 12); do $K -n "$NS" exec "$1" -- curl -gs -m3 "$2" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
refused() { for _ in $(seq 1 12); do $K -n "$NS" exec "$1" -- curl -gs -m3 "$2" >/dev/null 2>&1 || return 0; sleep 2; done; return 1; }
who()     { $K -n "$NS" exec "$1" -- curl -gs -m3 "$2" 2>/dev/null | tr -d "[:space:]"; }
vpcip()   { $K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}" | awk -v p="$1" '$1==p{print $2}'; }
fabricof() { $K get fabricips -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.address}{'\n'}{end}" | awk -v p="$1" '$1==p{print $2}'; }

echo "== vpc e2e against ${KCTX} =="
mapfile -t READY < <($K get nodes -o jsonpath='{range .items[?(@.status.conditions[-1].status=="True")]}{.metadata.name}{"\n"}{end}')
W="${READY[0]:-}"; W2="${READY[1]:-}"
[ -n "$W" ] && [ -n "$W2" ] || { echo "need two Ready nodes"; exit 1; }
echo "nodes: $W / $W2"

$K delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1
$K create ns "$NS" >/dev/null
$K label ns "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1

# Each pod serves its OWN NAME. With overlapping CIDRs the same address exists in
# two VPCs, so a reply proves nothing unless it says who sent it.
SRV='mkdir -p /w && hostname > /w/index.html && cd /w && python3 -m http.server 8080 --bind ::'

# ---------------------------------------------------------------------------
phase "VPC attach: Port and FabricIP are separate objects"
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: va, namespace: $NS}
spec: {cidrs: ["10.90.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: va, namespace: $NS}
spec: {vpcRef: {namespace: $NS, name: va}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: vb, namespace: $NS}
spec: {cidrs: ["10.91.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: vb, namespace: $NS}
spec: {vpcRef: {namespace: $NS, name: vb}}
---
# vc deliberately REUSES va's CIDR: overlapping tenant ranges must coexist.
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: vc, namespace: $NS}
spec: {cidrs: ["10.90.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: vc, namespace: $NS}
spec: {vpcRef: {namespace: $NS, name: vc}}
EOF
apply <<EOF
apiVersion: v1
kind: Pod
metadata: {name: a1, namespace: $NS, annotations: {sdn.cozystack.io/vpc: va}}
spec:
  nodeName: $W
  containers: [{name: s, image: nicolaka/netshoot, command: [sh, -c, "$SRV"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: a2, namespace: $NS, annotations: {sdn.cozystack.io/vpc: va}}
spec:
  nodeName: $W2
  containers: [{name: s, image: nicolaka/netshoot, command: [sh, -c, "$SRV"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: b1, namespace: $NS, annotations: {sdn.cozystack.io/vpc: vb}}
spec:
  nodeName: $W2
  containers: [{name: s, image: nicolaka/netshoot, command: [sh, -c, "$SRV"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: c1, namespace: $NS, annotations: {sdn.cozystack.io/vpc: vc}}
spec:
  nodeName: $W2
  containers: [{name: s, image: nicolaka/netshoot, command: [sh, -c, "$SRV"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: net0, namespace: $NS}
spec:
  nodeName: $W
  containers: [{name: s, image: nicolaka/netshoot, command: [sleep, infinity]}]
EOF
$K -n "$NS" wait --for=condition=Ready pod/a1 pod/a2 pod/b1 pod/c1 pod/net0 --timeout=240s >/dev/null 2>&1 \
  || { echo "FATAL: VPC pods never became Ready"; $K -n "$NS" get pods; exit 1; }
pass "VPC pods attach (a Port claim AND a FabricIP claim, both keyed to the pod)"

A1=$(vpcip a1); A2=$(vpcip a2); B1=$(vpcip b1); C1=$(vpcip c1)
A1F=$(fabricof a1)
echo "  a1: vpc=$A1 fabric=$A1F | a2: vpc=$A2 | b1 (VPC vb, distinct CIDR): $B1 | c1 (VPC vc, SAME CIDR as va): $C1"

# The Port carries no underlay address at all — that is increment 4.
if $K get ports -o jsonpath='{.items[*].spec}' | grep -q "fabricIP"; then
  fail "Port still carries a fabricIP (it must live only in the FabricIP claim)"
else
  pass "Port carries NO underlay address (normalized away; only FabricIP has it)"
fi
[ -n "$A1F" ] && pass "the VPC pod's underlay address is a FabricIP claim" \
  || fail "no FabricIP claim for a VPC pod"
# Flat pool: the fabric address is not inside the node's slice.
NODECIDR=$($K get node "$W" -o jsonpath='{.spec.podCIDR}')
pass "fabric address $A1F drawn from the cluster pool (node slice was $NODECIDR)"

# ---------------------------------------------------------------------------
phase "intra-VPC east-west, cross-node"
got=$(who a1 "http://$A2:8080/")
[ "$got" = "a2" ] && pass "a1 -> a2 across nodes (overlay delivery keyed on the VPC IP)" \
  || fail "intra-VPC cross-node failed (got '$got')"

# ---------------------------------------------------------------------------
phase "isolation + overlapping CIDRs"
# vb has a DISTINCT CIDR, so this is a real cross-VPC reachability test.
refused a1 "http://$B1:8080/" && pass "cross-VPC traffic is dropped (unpeered VPC, distinct CIDR)" \
  || fail "cross-VPC isolation LEAKED"
refused net0 "http://$A1:8080/" && pass "a default-network pod cannot reach a VPC IP" \
  || fail "net-0 -> VPC IP leaked"

# vc REUSES va's CIDR. The same address therefore exists in two VPCs — and each
# must resolve it to ITS OWN pod. A reply alone proves nothing; who replied does.
[ "$A1" = "$C1" ] && pass "overlapping VPC CIDRs coexist: a1 and c1 hold the SAME address ($A1) in different VPCs" \
  || fail "the overlapping VPC did not reuse the address (a1=$A1 c1=$C1)"
got=$(who a1 "http://$A1:8080/")
[ "$got" = "a1" ] && pass "in VPC va, $A1 resolves to a1 (not to c1, which holds the same address)" \
  || fail "va's view of $A1 resolved to '$got'"
got=$(who c1 "http://$C1:8080/")
[ "$got" = "c1" ] && pass "in VPC vc, the SAME address $C1 resolves to c1 — net-scoped delivery, no collision" \
  || fail "vc's view of $C1 resolved to '$got'"

# ---------------------------------------------------------------------------
phase "north-south: the fabric IP still reaches the pod (the dual-address bridge)"
got=$(who net0 "http://$A1F:8080/")
[ "$got" = "a1" ] && pass "net-0 pod -> a1's FABRIC IP reaches a1 (the bridge DNATs fabric -> VPC IP)" \
  || fail "north-south via the fabric IP broke (got '$got') — the bridge is programmed from the claim now"

# ---------------------------------------------------------------------------
phase "peering"
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: a-b, namespace: $NS}
spec:
  vpcRef: {name: va}
  peerRef: {namespace: $NS, name: vb}
EOF
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: b-a, namespace: $NS}
spec:
  vpcRef: {name: vb}
  peerRef: {namespace: $NS, name: va}
EOF
sleep 10
got=""
for _ in $(seq 1 10); do got=$(who a1 "http://$B1:8080/"); [ "$got" = "b1" ] && break; sleep 3; done
[ "$got" = "b1" ] && pass "a symmetric peering opens va <-> vb (cross-VPC delivery, distinct CIDRs)" \
  || fail "peering did not open cross-VPC traffic (got '$got')"
$K -n "$NS" delete vpcpeering a-b b-a >/dev/null 2>&1
sleep 8
refused a1 "http://$B1:8080/" && pass "deleting the peering re-isolates the VPCs" \
  || fail "traffic still flows after the peering was deleted"

# ---------------------------------------------------------------------------
phase "VPC DNS: the split-horizon resolver identifies the client"
# The responder identifies the querying pod from its UNDERLAY source address:
# FabricIP -> pod -> Port. That join replaced Port.spec.fabricIP.
$K -n "$NS" exec a1 -- nslookup -timeout=4 example.com >/dev/null 2>&1 \
  && pass "VPC pod resolves an external name (responder reached; upstream forwarded)" \
  || fail "VPC pod DNS is broken (the responder's FabricIP->Port join?)"
$K -n "$NS" exec a1 -- nslookup -timeout=4 kubernetes.default >/dev/null 2>&1 \
  && fail "VPC pod resolved a cluster name it is not attached to (split-horizon leaked)" \
  || pass "VPC pod gets NXDOMAIN for cluster names it is not attached to (sovereignty)"

# ---------------------------------------------------------------------------
phase "SecurityGroup: intra-VPC policy still enforces"
$K -n "$NS" label pod a1 role=web --overwrite >/dev/null
$K -n "$NS" label pod a2 role=client --overwrite >/dev/null
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: $NS}
spec:
  vpcRef: {name: va}
  podSelector: {matchLabels: {role: web}}
  ingress: [{from: {group: client}, ports: [{protocol: TCP, port: 8080}]}]
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: $NS}
spec:
  vpcRef: {name: va}
  podSelector: {matchLabels: {role: client}}
  egress: [{to: {group: web}, ports: [{protocol: TCP, port: 8080}]}]
EOF
got=""
for _ in $(seq 1 10); do got=$(who a2 "http://$A1:8080/"); [ "$got" = "a1" ] && break; sleep 3; done
[ "$got" = "a1" ] && pass "the grouped client is admitted by the SG rules" \
  || fail "SG rules did not admit the grouped client (got '$got')"
$K -n "$NS" label pod a2 role=bystander --overwrite >/dev/null
refused a2 "http://$A1:8080/" && pass "relabelling a live pod out of its group cuts it off (label-follows)" \
  || fail "SG membership did not follow the label change"
$K -n "$NS" delete securitygroup web client >/dev/null 2>&1

# ---------------------------------------------------------------------------
phase "revocation: severing a live pod's VPC access"
$K -n "$NS" delete vpcbinding va >/dev/null 2>&1
sleep 10
refused a1 "http://$A2:8080/" && pass "revoking the VPCBinding severs a running pod's VPC datapath" \
  || fail "the pod kept VPC access after its binding was revoked"

echo
echo "vpc-e2e: ${PASSED} passed, $((CHECKS - PASSED)) failed, ${SKIPPED} skipped, in $(( $(date +%s) - START ))s"
if [ "$FAILED" = "0" ]; then echo "vpc-e2e: ALL PASSED"; else echo "vpc-e2e: FAILURES"; fi
exit $FAILED
