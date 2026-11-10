#!/usr/bin/env bash
#
# VPC egress e2e on kind (docs/vpc-egress.md): NAT gateways, route tables, the
# internet target, and the leased port blocks — with an external target on the
# kind docker network, which is why this suite builds its own kind cluster.
#
# Usage:
#   test/egress-e2e.sh            # build image, create kind, run, tear down
#   KEEP=1 test/egress-e2e.sh     # leave the cluster up on exit
#   REUSE=1 test/egress-e2e.sh    # run against the current cluster/install
set -uo pipefail

CLUSTER="${CLUSTER:-cozyplane-egress}"
IMAGE="${IMAGE:-ghcr.io/lllamnyp/cozyplane:e2e}"
KCTX="${KCTX:-kind-${CLUSTER}}"
K="kubectl --context ${KCTX}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NS=eg
FAILED=0
CHECKS=0

pass() { CHECKS=$((CHECKS + 1)); echo "  [${CHECKS}] PASS: $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILED=1; echo "  [${CHECKS}] FAIL: $*"; }
phase() { echo; echo "== $* =="; }
check_ok() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d (unexpectedly failed)"; fi; }
check_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d (unexpectedly succeeded)"; else pass "$d"; fi; }
# retry <tries> <cmd...>: succeed if the command succeeds within <tries> 2 s rounds.
retry() { local n="$1"; shift; for _ in $(seq 1 "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

cleanup() {
  docker rm -f egtgt egcap >/dev/null 2>&1
  [ "${KEEP:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
}

if [ "${REUSE:-0}" != "1" ]; then
  trap cleanup EXIT
  if [ -z "${IMAGE_PREBUILT:-}" ] && [ "${IMAGE}" = "ghcr.io/lllamnyp/cozyplane:e2e" ]; then
    echo "== building image =="
    docker build -t "$IMAGE" "$ROOT" >/dev/null || exit 1
  fi
  echo "== creating kind cluster =="
  kind create cluster --name "$CLUSTER" --config "$ROOT/test/kind.yaml" >/dev/null || exit 1
  kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null || exit 1
  echo "== installing cozyplane =="
  # The CNI first: until the agent runs, every node is tainted not-ready and
  # the aggregated apiserver cannot schedule. The agent and the controller wait
  # for the sdn group on their own.
  $K apply -f "$ROOT/config/crd/" >/dev/null
  for f in agent controller authz; do sed "s#ghcr.io/lllamnyp/cozyplane:dev#${IMAGE}#g" "$ROOT/deploy/$f.yaml" | $K apply -f - >/dev/null; done
  $K -n kube-system rollout status ds/cozyplane-agent --timeout=180s || exit 1
  sed "s#ghcr.io/lllamnyp/cozyplane:dev#${IMAGE}#g" "$ROOT/deploy/apiserver.yaml" | $K apply -f - >/dev/null
  $K -n kube-system rollout status deploy/cozyplane-apiserver --timeout=180s || exit 1
  for _ in $(seq 1 30); do $K get vpcs.sdn.cozystack.io >/dev/null 2>&1 && break; sleep 2; done
  $K -n kube-system rollout status deploy/cozyplane-controller --timeout=120s || exit 1
fi
W="${CLUSTER}-worker"; W2="${CLUSTER}-worker2"; ATT="${CLUSTER}-control-plane"

# Two addresses on the kind network that nothing uses: the NAT gateway's and a
# FloatingIP's. Each is attracted the way a CCM would: configured on a node
# (the control plane, which hosts no test pod, so every reply crosses nodes).
KNET4=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' | tr ' ' '\n' | grep -v : | head -1)
P4=$(echo "${KNET4%/*}" | cut -d. -f1-2)
NATIP="$P4.250.10"; NATIP2="$P4.250.11"; FIP="$P4.250.20"

podyaml() { # podyaml <name> <node> [route-table]
  local ann="sdn.cozystack.io/vpc: v"
  [ -n "${3:-}" ] && ann="$ann, sdn.cozystack.io/route-table: $3"
  $K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: $NS, annotations: {$ann}}
spec:
  nodeName: $2
  containers: [{name: c, image: busybox:1.36, command: ["sleep", "3600"]}]
EOF
}

phase "fixtures"
$K create ns $NS >/dev/null 2>&1
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: v, namespace: $NS}
spec: {cidrs: ["10.30.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: v, namespace: $NS}
spec: {vpcRef: {namespace: $NS, name: v}}
EOF
podyaml p1 "$W"
podyaml p2 "$W2"
podyaml pf "$W" public
podyaml pn "$W" nope
for p in p1 p2 pf pn; do $K -n $NS wait --for=condition=Ready pod/$p --timeout=120s >/dev/null; done
docker run -d --rm --name egtgt --network kind busybox:1.36 \
  sh -c 'mkdir -p /w && echo tgt > /w/index.html && httpd -f -p 80 -h /w' >/dev/null
docker run -d --rm --name egcap --net container:egtgt nicolaka/netshoot \
  sh -c 'tcpdump -lnni eth0 "tcp port 80 or icmp" > /tmp/cap.txt 2>&1' >/dev/null
TGT=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' egtgt)
sleep 3
get() { $K -n $NS exec "$1" -- wget -qO- -T3 "http://$TGT/" 2>/dev/null | grep -q tgt; }
seen() { docker exec egcap grep -q "IP $1\." /tmp/cap.txt; }

phase "no route table: no internet"
check_fail "p1 (no table) cannot reach the external target" get p1

phase "NAT gateway"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: NATGateway
metadata: {name: egress, namespace: $NS}
spec: {vpcRef: {name: v}}
EOF
SVC=""; for _ in $(seq 1 15); do
  SVC=$($K -n $NS get svc -l sdn.cozystack.io/nat-gateway=egress -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$SVC" ] && break; sleep 2
done
[ -n "$SVC" ] && pass "the NAT gateway created its LoadBalancer Service ($SVC)" || fail "no NAT gateway Service"
$K -n $NS patch svc "$SVC" --subresource=status --type=merge -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$NATIP\"}]}}}" >/dev/null
docker exec "$ATT" ip addr add "$NATIP/32" dev eth0 2>/dev/null
check_ok "NATGateway status carries $NATIP" retry 15 bash -c "[ \"\$($K -n $NS get natgateway egress -o jsonpath='{.status.address}')\" = $NATIP ]"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: RouteTable
metadata: {name: main, namespace: $NS}
spec: {vpcRef: {name: v}, default: true}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: Route
metadata: {name: default, namespace: $NS}
spec: {routeTableRef: {name: main}, destination: 0.0.0.0/0, target: {natGateway: {name: egress}}}
EOF
check_ok "the default route is Active" retry 15 bash -c "[ \"\$($K -n $NS get route default -o jsonpath='{.status.state}')\" = Active ]"
check_ok "p1 (node $W) reaches the target through the NAT gateway" retry 20 get p1
check_ok "p2 (node $W2) reaches the target through the NAT gateway" retry 20 get p2
check_ok "the target saw the NAT gateway address $NATIP as the source" seen "$NATIP"
check_ok "p1 pings the target through the NAT gateway (ICMP echo)" $K -n $NS exec p1 -- ping -c2 -W2 "$TGT"
LEASES=$($K get natportblocks -o jsonpath='{range .items[*]}{.spec.node}{" "}{.status.acks[*].node}{"\n"}{end}' 2>/dev/null)
echo "$LEASES" | grep -q "^$W " && echo "$LEASES" | grep -q "^$W2 " \
  && pass "nodes $W and $W2 each hold a leased block" || fail "leases: $LEASES"
echo "$LEASES" | awk 'NF<4{bad=1} END{exit bad}' \
  && pass "every lease is acked by all three nodes" || fail "unacked leases: $LEASES"
# ICMP errors about a NATed flow come back to the pod: the last hop of a UDP
# traceroute is the target's port-unreachable, translated through the NAT gateway.
LAST=$($K -n $NS exec p1 -- traceroute -n -q1 -w2 -m4 "$TGT" 2>/dev/null | tail -1)
echo "$LAST" | grep -q "$TGT" && pass "UDP traceroute through the NAT gateway reaches $TGT (ICMP error reverse path)" \
  || fail "UDP traceroute through the NAT gateway (last hop: $LAST)"
check_fail "an unsolicited packet to the NAT gateway address is not delivered" \
  docker run --rm --network kind curlimages/curl:8.11.0 -s -m3 "http://$NATIP/"

phase "blackhole route"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: Route
metadata: {name: drop-tgt, namespace: $NS}
spec: {routeTableRef: {name: main}, destination: $TGT/32, target: {blackhole: {}}}
EOF
check_ok "a /32 blackhole beats the default route" retry 10 bash -c "! $K -n $NS exec p1 -- wget -qO- -T2 http://$TGT/ >/dev/null 2>&1"
$K -n $NS delete route drop-tgt >/dev/null
check_ok "removing the blackhole restores egress" retry 10 get p1

phase "missing table"
check_fail "pn (names a table that does not exist) has no internet" get pn

phase "internet target and FloatingIP"
PF=$($K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}" | awk '$1=="pf"{print $2}')
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: pf, namespace: $NS}
spec: {vpcRef: {name: v}, target: "$PF"}
EOF
FSVC=""; for _ in $(seq 1 15); do
  FSVC=$($K -n $NS get svc -l sdn.cozystack.io/floating-ip=pf -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$FSVC" ] && break; sleep 2
done
$K -n $NS patch svc "$FSVC" --subresource=status --type=merge -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$FIP\"}]}}}" >/dev/null 2>&1
docker exec "$ATT" ip addr add "$FIP/32" dev eth0 2>/dev/null
check_fail "pf (table public, not created yet) has no internet" get pf
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: RouteTable
metadata: {name: public, namespace: $NS}
spec: {vpcRef: {name: v}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: Route
metadata: {name: public-default, namespace: $NS}
spec: {routeTableRef: {name: public}, destination: 0.0.0.0/0, target: {internet: {}}}
EOF
docker exec egcap sh -c ': > /tmp/cap.txt'
check_ok "pf reaches the target through the internet route" retry 20 get pf
check_ok "the target saw the FloatingIP $FIP as pf's source" seen "$FIP"
check_ok "an external client reaches pf on its FloatingIP" retry 10 \
  bash -c "docker run --rm --network kind busybox:1.36 ping -c1 -W2 $FIP"
# The partner case: pf leaves as its FloatingIP in general, as the NAT gateway
# toward one prefix.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: Route
metadata: {name: partner, namespace: $NS}
spec: {routeTableRef: {name: public}, destination: $TGT/32, target: {natGateway: {name: egress}}}
EOF
check_ok "the partner route is Active" retry 15 bash -c "[ \"\$($K -n $NS get route partner -o jsonpath='{.status.state}')\" = Active ]"
docker exec egcap sh -c ': > /tmp/cap.txt'
check_ok "pf reaches the target through the partner route" retry 20 get pf
check_ok "toward the partner prefix pf's source is the NAT gateway $NATIP" seen "$NATIP"

phase "VPCGateway transition"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: legacy, namespace: $NS}
spec: {cidrs: ["10.31.0.0/24"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: legacy, namespace: $NS}
spec: {vpcRef: {namespace: $NS, name: legacy}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCGateway
metadata: {name: door, namespace: $NS}
spec: {vpcRef: {name: legacy}, nat: {enabled: true}}
EOF
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: pl, namespace: $NS, annotations: {sdn.cozystack.io/vpc: legacy}}
spec:
  nodeName: $W2
  containers: [{name: c, image: busybox:1.36, command: ["sleep", "3600"]}]
EOF
$K -n $NS wait --for=condition=Ready pod/pl --timeout=120s >/dev/null
check_ok "nat.enabled created a NATGateway named after the VPCGateway" retry 15 $K -n $NS get natgateway door
LSVC=""; for _ in $(seq 1 15); do
  LSVC=$($K -n $NS get svc -l sdn.cozystack.io/nat-gateway=door -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
  [ -n "$LSVC" ] && break; sleep 2
done
$K -n $NS patch svc "$LSVC" --subresource=status --type=merge -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$NATIP2\"}]}}}" >/dev/null 2>&1
docker exec "$ATT" ip addr add "$NATIP2/32" dev eth0 2>/dev/null
check_ok "the transition created the default route" retry 20 bash -c "[ \"\$($K -n $NS get route door-default-ipv4 -o jsonpath='{.status.state}')\" = Active ]"
check_ok "VPCGateway status mirrors $NATIP2" retry 15 bash -c "[ \"\$($K -n $NS get vpcgateway door -o jsonpath='{.status.natAddress}')\" = $NATIP2 ]"
docker exec egcap sh -c ': > /tmp/cap.txt'
check_ok "pl (VPCGateway VPC) reaches the target" retry 20 get pl
check_ok "pl's source is the transition's NAT gateway $NATIP2" seen "$NATIP2"

echo
if [ "$FAILED" = 0 ]; then echo "ALL ${CHECKS} CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$FAILED"
