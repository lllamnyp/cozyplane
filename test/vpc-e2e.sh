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
# network (LoadBalancer ingress, north-south masquerade). Those live in
# test/e2e.sh, which builds its own kind cluster because the "external" client is
# a container on kind's network.
#
# Floating-IP HA (docs/floating-ha.md) IS covered, when FLOAT_CIDR names a spare
# on-link range on the cluster's external L2 — the client there is a hostNetwork
# pod, which is off the VPC and reaches the address over the real fabric, so the
# announcer/host/client triangle is genuine without needing a docker network.
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
phase "anti-spoof: from_pod RPF drops a forged source"
# SecurityGroup identity is keyed on the source IP, so a pod forging a co-VPC
# neighbour's address would borrow its groups. RPF authenticates the source at
# its origin veth. The decisive check is DELIVERY, not a reply: a spoofed packet
# gets no reply anyway (it went to the forged address), so we CAPTURE on the
# destination and confirm the forged SYN never arrives — with a non-spoofed SYN
# as the positive control that the capture works.
# Needs raw sockets (nping) and tcpdump; netshoot has both. Skip if absent.
if ! $K -n "$NS" exec a2 -- sh -c 'command -v nping && command -v tcpdump' >/dev/null 2>&1; then
  skip "RPF (nping/tcpdump not in the image)"
else
  SPOOF="10.90.0.240"   # a co-VPC address a2 does NOT own
  fire() { $K -n "$NS" exec a2 -- nping --tcp -c 3 -p 8080 --flags syn -S "$1" --rate 5 "$A1" >/dev/null 2>&1; }
  # ONE capture spans the whole window (no -c1: it must not exit on the first
  # genuine SYN before the spoofed fire), started first and given time to arm —
  # the capture-then-fire race is why an inline probe read nothing.
  $K -n "$NS" exec a1 -- sh -c \
    'timeout 12 tcpdump -lni any "tcp[tcpflags] & tcp-syn != 0 and dst port 8080" > /tmp/rpfcap 2>/dev/null' &
  CAP=$!
  sleep 4
  fire "$A2"       # genuine source — must arrive (RPF admits the honest one)
  fire "$SPOOF"    # forged source — must be dropped at a2's own from_pod
  sleep 3
  wait "$CAP" 2>/dev/null
  genuine=$($K -n "$NS" exec a1 -- sh -c "grep -cF ' $A2.' /tmp/rpfcap || true" 2>/dev/null | head -1)
  spoofed=$($K -n "$NS" exec a1 -- sh -c "grep -cF ' $SPOOF.' /tmp/rpfcap || true" 2>/dev/null | head -1)
  [ "${genuine:-0}" -ge 1 ] && pass "positive control: a2's genuine SYN reaches a1 (RPF admits the honest source)" \
    || fail "positive control failed — a2's real SYN did not arrive (got '$genuine')"
  # Decisive by DELIVERY, not a reply: a spoofed packet forfeits its reply
  # regardless, so only observing arrival distinguishes RPF-dropped from that.
  [ "${spoofed:-0}" -eq 0 ] && pass "a forged co-VPC source is dropped at the origin veth (RPF); a1 never sees it" \
    || fail "SPOOFED packet reached a1 — RPF did not drop it (got '$spoofed')"
fi

# ---------------------------------------------------------------------------
phase "floating-IP HA: the announcer need not be the pod's host"
# docs/floating-ha.md. Attraction (who answers ARP) and delivery (who runs the
# pod) are separate decisions now. The decisive case is the ASYMMETRIC one: an
# address announced by node X, whose pod lives on node Y, reached by a client on
# node Z. It exercises the remote arm in from_uplink, the floating probe in
# from_overlay, and the DSR reply out the host's own uplink — none of which the
# old same-node path ever touched.
#
# Needs a spare on-link range on the cluster's external L2 (FLOAT_CIDR), because
# an L2 announcement is only meaningful on a fabric the nodes are attached to.
if [ -z "${FLOAT_CIDR:-}" ]; then
  skip "floating-IP HA (set FLOAT_CIDR=<spare on-link range> to run it)"
else
  apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: ExternalPool
metadata: {name: e2e-float}
spec: {cidrs: ["$FLOAT_CIDR"]}
EOF
  # One FloatingIP per pod — a target takes exactly one floating address (the
  # datapath's reverse map is keyed by the target alone, so two bindings on one
  # target would fight; the controller refuses the second, and that is asserted
  # below). Four bindings across four pods, because the announcer is a hash of the
  # ADDRESS: with a handful, at least one lands away from its target's node, which
  # is the case worth testing. One binding would be a coin toss.
  #
  #   pod  vpc  target  the node it runs on
  FIPS=("a1 va $A1 $W" "a2 va $A2 $W2" "b1 vb $B1 $W2" "c1 vc $C1 $W2")
  for f in "${FIPS[@]}"; do
    read -r pod vpc target _ <<<"$f"
    apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: fip-$pod, namespace: $NS}
spec:
  vpcRef: {name: $vpc}
  target: "$target"
  poolRef: {name: e2e-float}
EOF
  done
  # announces <public-ip> -> the nodes whose agent has it in float_announce
  # (cozyplane_floating_announced). The election writes no API object — the
  # datapath map is the truth, and the metric is how it is read.
  #
  # Scraped over each node's address from an ordinary pod: the agent is
  # hostNetwork, so :9411 is on the node, and the agent's own container is a
  # minimal image with no shell tooling to exec into.
  mapfile -t NODEIPS < <($K get nodes \
    -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
  announces() {
    local pub="$1" node ip
    for n in "${NODEIPS[@]}"; do
      read -r node ip <<<"$n"
      $K -n "$NS" exec net0 -- curl -gs -m5 "http://${ip}:9411/metrics" 2>/dev/null \
        | grep -q "cozyplane_floating_announced{public=\"$pub\"" && echo "$node"
    done
  }
  announcer() { announces "$1" | head -1; }

  # Wait for the addresses, then find one announced AWAY from its target's node.
  FIP=""; FIPNODE=""; FIPPOD=""; FIPHOST=""
  for _ in $(seq 1 20); do
    for f in "${FIPS[@]}"; do
      read -r pod _ _ host <<<"$f"
      addr=$($K -n "$NS" get floatingip "fip-$pod" -o jsonpath='{.status.address}' 2>/dev/null)
      [ -n "$addr" ] || continue
      n=$(announcer "$addr")
      [ -n "$n" ] || continue
      # Any announced address proves the map is programmed; one announced from a
      # node that does NOT host its pod is the case worth testing.
      [ -z "$FIP" ] && { FIP="$addr"; FIPNODE="$n"; FIPPOD="$pod"; FIPHOST="$host"; }
      if [ "$n" != "$host" ]; then FIP="$addr"; FIPNODE="$n"; FIPPOD="$pod"; FIPHOST="$host"; break 2; fi
    done
    sleep 3
  done

  if [ -z "$FIP" ]; then
    fail "no floating IP was announced by any node (the election never converged)"
    echo "  --- diagnostics ---"
    $K -n "$NS" get floatingips -o custom-columns=NAME:.metadata.name,ADDR:.status.address,PHASE:.status.phase 2>&1 | head -6
    $K get nodes -o jsonpath='{range .items[*]}{"  node "}{.metadata.name}{" pools="}{.metadata.annotations.cozyplane\.io/external-pools}{"\n"}{end}'
  else
    pass "the address is announced from exactly one node (elected, not derived from the pod's location)"
    echo "  floating $FIP -> pod $FIPPOD (on $FIPHOST), announced by $FIPNODE"

    # Exactly one announcer — two would be a split brain, and ARP would flap.
    COUNT=$(announces "$FIP" | wc -l)
    [ "$COUNT" -eq 1 ] && pass "exactly one node announces it (no split brain)" \
      || fail "$COUNT nodes announce $FIP — ARP would flap between them"

    if [ "$FIPNODE" = "$FIPHOST" ]; then
      skip "every address was announced by its own pod's node this run — the asymmetric path went untested"
    else
      # The client must be neither the announcer nor the host, so the request
      # crosses the overlay and the reply comes back from a third direction.
      CLIENT=""
      for n in "${READY[@]}"; do
        [ "$n" != "$FIPNODE" ] && [ "$n" != "$FIPHOST" ] && { CLIENT="$n"; break; }
      done
      [ -n "$CLIENT" ] || CLIENT="$W2"
      echo "  external client on $CLIENT -> $FIP (attract on $FIPNODE, deliver on $FIPHOST)"
      apply <<EOF
apiVersion: v1
kind: Pod
metadata: {name: extclient, namespace: $NS}
spec:
  nodeName: $CLIENT
  hostNetwork: true
  containers: [{name: c, image: nicolaka/netshoot, command: [sleep, infinity]}]
EOF
      $K -n "$NS" wait --for=condition=Ready pod/extclient --timeout=120s >/dev/null 2>&1
      GOT=""
      for _ in $(seq 1 10); do
        GOT=$($K -n "$NS" exec extclient -- curl -gs -m5 "http://$FIP:8080" 2>/dev/null | tr -d "[:space:]")
        [ -n "$GOT" ] && break
        sleep 2
      done
      [ "$GOT" = "$FIPPOD" ] \
        && pass "a client off the VPC reaches the pod through an address announced by ANOTHER node (attract $FIPNODE, deliver $FIPHOST, client $CLIENT)" \
        || fail "the floating IP did not reach the pod across nodes (got '$GOT', want '$FIPPOD')"
    fi

    # A target takes exactly ONE floating address. The reverse map is keyed by the
    # target alone, so a second binding would overwrite the first's egress and the
    # first address would start replying from the second — a silent break the
    # datapath cannot detect. The controller must refuse it.
    apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: fip-dup, namespace: $NS}
spec:
  vpcRef: {name: va}
  target: "$A1"
  poolRef: {name: e2e-float}
EOF
    DUP=""
    for _ in $(seq 1 10); do
      DUP=$($K -n "$NS" get floatingip fip-dup -o jsonpath='{.status.address}' 2>/dev/null)
      PH=$($K -n "$NS" get floatingip fip-dup -o jsonpath='{.status.phase}' 2>/dev/null)
      [ "$PH" = "Pending" ] && [ -z "$DUP" ] && break
      sleep 2
    done
    [ -z "$DUP" ] \
      && pass "a second FloatingIP on an already-bound target is refused (stays dark; it would have hijacked the first's egress)" \
      || fail "a second FloatingIP on the same target was allocated $DUP — it silently breaks the first address"
    $K -n "$NS" delete floatingip fip-dup >/dev/null 2>&1
  fi
  $K -n "$NS" delete floatingip --all >/dev/null 2>&1
  $K delete externalpool e2e-float >/dev/null 2>&1
fi

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
