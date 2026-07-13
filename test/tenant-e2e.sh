#!/usr/bin/env bash
# Multi-tenancy e2e (docs/multitenancy.md): the tenant persona.
#
#   KCTX=<context> [KUBECONFIG=<path>] test/tenant-e2e.sh
#
# Two properties, and they are the whole of R1 and R2:
#
#   R1  a tenant can learn the network identity of its OWN workload — because
#       status.podIP is the FABRIC IP, and the VPC address it actually has lives
#       only on the cluster-scoped Port, which it may never read.
#
#   R2  a tenant holding the FULL tenant role can discover nothing about any other
#       tenant. Not "does not happen to"; CANNOT. A RoleBinding grants no access to
#       a cluster-scoped resource, so `list ports` is unreachable by construction.
set -u
KCTX="${KCTX:?set KCTX}"
K="kubectl --context ${KCTX}"
A="tenant-a"
B="tenant-b"

FAILED=0
CHECKS=0
PASSED=0
pass() { CHECKS=$((CHECKS + 1)); PASSED=$((PASSED + 1)); echo "  [${CHECKS}] PASS: $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILED=1; echo "  [${CHECKS}] FAIL: $*"; }
phase() { echo; echo "== $* =="; }

cleanup() {
  echo
  echo "== cleanup =="
  [ "${KEEP:-0}" = "1" ] || $K delete ns "$A" "$B" --wait=false >/dev/null 2>&1
}
trap cleanup EXIT INT TERM HUP

apply() { $K apply -f - >/dev/null || { echo "  FATAL: apply rejected"; exit 1; }; }

echo "== tenant e2e against ${KCTX} =="
$K delete ns "$A" "$B" --ignore-not-found --wait=true --timeout=180s >/dev/null 2>&1
$K create ns "$A" >/dev/null
$K create ns "$B" >/dev/null
$K label ns "$A" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1
$K label ns "$B" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1

# Two tenants, each a ServiceAccount holding the FULL tenant surface in its own
# namespace — the aggregated `admin` role, which cozyplane's tenant rules
# aggregate into. This is the most a tenant can ever hold.
for ns in "$A" "$B"; do
  $K -n "$ns" create sa tenant >/dev/null 2>&1
  $K -n "$ns" create rolebinding tenant-admin --clusterrole=admin --serviceaccount="${ns}:tenant" >/dev/null 2>&1
done
TA="system:serviceaccount:${A}:tenant"
TB="system:serviceaccount:${B}:tenant"

can()    { $K auth can-i "$1" "$2" --as="$3" ${4:+-n "$4"} 2>/dev/null; }
cannot() { [ "$(can "$1" "$2" "$3" "${4:-}")" = "no" ]; }

# ---------------------------------------------------------------------------
phase "the tenant persona exists at all"
[ "$(can create vpcs "$TA" "$A")" = "yes" ] \
  && pass "a tenant can create a VPC in its own namespace" \
  || fail "a tenant cannot create a VPC — there is no tenant persona"
[ "$(can create vpcgateways "$TA" "$A")" = "yes" ] \
  && pass "a tenant can open its own VPC's boundary (VPCGateway)" \
  || fail "a tenant cannot create a VPCGateway"
[ "$(can create securitygroups "$TA" "$A")" = "yes" ] \
  && pass "a tenant can write its own SecurityGroups" \
  || fail "a tenant cannot write SecurityGroups"
# `export` on its OWN VPCs — without it a tenant cannot attach a pod even to a VPC
# it owns (attach is default-deny; a VPCBinding is required in every case).
[ "$(can export vpcs "$TA" "$A")" = "yes" ] \
  && pass "a tenant may 'export' its OWN VPCs (a RoleBinding cannot reach another namespace's)" \
  || fail "a tenant cannot export its own VPC — it could not attach a pod to it"

# ---------------------------------------------------------------------------
phase "R2: a tenant enumerates nothing it does not own"
# The cluster-scoped kinds. These are the leak: one `list ports` hands over every
# tenant's pod names, VPC addresses, MACs and node placement.
for r in ports servicevips externalpools hostfirewalls; do
  cannot list "$r" "$TA" \
    && pass "a tenant CANNOT list $r (cluster-scoped — unreachable from a RoleBinding)" \
    || fail "a tenant CAN list $r — the fleet's topology is readable"
done
cannot list fabricips "$TA" \
  && pass "a tenant CANNOT list fabricips (the underlay pool)" \
  || fail "a tenant CAN list fabricips"

# The other tenant's namespace.
cannot list vpcs "$TA" "$B" \
  && pass "a tenant CANNOT list another tenant's VPCs" \
  || fail "a tenant CAN read another tenant's VPCs"
cannot get secrets "$TA" "$B" \
  && pass "a tenant CANNOT read another tenant's namespace at all" \
  || fail "cross-namespace read is open"

# Operator-only surfaces.
cannot create hostfirewalls "$TA" \
  && pass "a tenant CANNOT create a HostFirewall (operator-only)" \
  || fail "a tenant CAN create a HostFirewall"
cannot create externalpools "$TA" \
  && pass "a tenant CANNOT mint an ExternalPool (it may open a door, not what is behind it)" \
  || fail "a tenant CAN create an ExternalPool"
cannot attach externalpools "$TA" \
  && pass "a tenant does NOT hold 'attach' on a pool by default (it is an operator's grant)" \
  || fail "a tenant holds 'attach' without being granted it"

# ---------------------------------------------------------------------------
phase "R1: a tenant can learn the identity of its own workload"
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: va, namespace: $A}
spec: {cidrs: ["10.90.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: va, namespace: $A}
spec: {vpcRef: {namespace: $A, name: va}}
---
apiVersion: v1
kind: Pod
metadata: {name: app, namespace: $A, annotations: {sdn.cozystack.io/vpc: va}}
spec:
  containers: [{name: c, image: nicolaka/netshoot, command: [sleep, infinity]}]
EOF
$K -n "$A" wait --for=condition=Ready pod/app --timeout=240s >/dev/null 2>&1 \
  || { echo "FATAL: the tenant's pod never became Ready"; $K -n "$A" get pods; exit 1; }

# What kubernetes shows the tenant, and what it actually means.
PODIP=$($K -n "$A" get pod app -o jsonpath='{.status.podIP}')
VPCIP=""
for _ in $(seq 1 10); do
  VPCIP=$($K -n "$A" get pod app -o jsonpath='{.metadata.annotations.sdn\.cozystack\.io/vpc-ip}' 2>/dev/null)
  [ -n "$VPCIP" ] && break
  sleep 2
done
VPCMAC=$($K -n "$A" get pod app -o jsonpath='{.metadata.annotations.sdn\.cozystack\.io/vpc-mac}' 2>/dev/null)
# The truth, from the cluster-scoped Port the tenant may not read.
TRUE_IP=$($K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}" | awk '$1=="app"{print $2}')
echo "  status.podIP (the FABRIC ip): $PODIP"
echo "  annotated VPC ip / mac:       $VPCIP / $VPCMAC"
echo "  the Port's truth:             $TRUE_IP"

[ -n "$VPCIP" ] \
  && pass "the tenant can read its own VPC address from its own pod" \
  || fail "the tenant cannot discover its own VPC address (R1 unmet)"
[ "$VPCIP" = "$TRUE_IP" ] \
  && pass "the stamped address matches the Port (the source of truth)" \
  || fail "the stamped address ($VPCIP) disagrees with the Port ($TRUE_IP)"
[ -n "$VPCMAC" ] \
  && pass "the tenant can read its own MAC (a VM's pinned identity)" \
  || fail "no MAC stamped"
[ "$VPCIP" != "$PODIP" ] \
  && pass "and it is NOT status.podIP — which is the fabric address, the reason R1 exists" \
  || fail "the VPC address equals status.podIP; something is wrong with the dual-address model"

# The tenant reads its OWN identity through an object it already owns — no new
# surface, so R2 cannot be weakened by R1.
[ "$(can get pods "$TA" "$A")" = "yes" ] && cannot list ports "$TA" \
  && pass "R1 is served through the pod the tenant already owns — R2 stays intact" \
  || fail "R1 required widening the tenant's reads"

echo
echo "tenant-e2e: ${PASSED} passed, $((CHECKS - PASSED)) failed"
[ "$FAILED" = "0" ] && echo "tenant-e2e: ALL PASSED" || echo "tenant-e2e: FAILURES"
exit "$FAILED"
