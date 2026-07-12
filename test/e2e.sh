#!/usr/bin/env bash
#
# End-to-end test for cozyplane on a kind cluster. Locks the behaviour matrix
# that would otherwise be hand-verified every milestone: the default network,
# VPC isolation and default-deny attachment, intra-VPC and peered connectivity,
# overlapping-CIDR delivery (the eBPF bridge under same-node VPC-IP collisions),
# egress via the per-VPC gateway, and revocation.
#
# Usage:
#   test/e2e.sh                 # build image, create kind, run, tear down
#   IMAGE=... test/e2e.sh       # use a prebuilt image (skip docker build)
#   KEEP=1 test/e2e.sh          # leave the cluster up on exit
#   REUSE=1 test/e2e.sh         # use the current cluster/install as-is
set -uo pipefail

CLUSTER="${CLUSTER:-cozyplane-e2e}"
IMAGE="${IMAGE:-ghcr.io/lllamnyp/cozyplane:e2e}"
KCTX="kind-${CLUSTER}"
K="kubectl --context ${KCTX}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAILED=0

# --- progress harness -------------------------------------------------------
# Long runs must show they are alive even when everything passes: every check
# prints its running index, and every phase prints how far through the suite it
# is. TOTAL is derived from the script itself (the number of pass/fail call
# sites is the check ceiling; conditional checks make the real count <= it), so
# it never goes stale as checks are added.
CHECKS=0
PASSED=0
SKIPPED=0
TOTAL=$(grep -cE '(^|[[:space:]])(pass|fail) "' "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)
TOTAL=$((TOTAL / 2)) # each check has a pass and a fail arm
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
skip() { SKIPPED=$((SKIPPED + 1)); echo "  [skip] $* (not available in this environment)"; }

# check <description> <expected> <cmd...> : run cmd, compare trimmed stdout.
check() {
  local desc="$1" want="$2"; shift 2
  local got; got="$("$@" 2>/dev/null | tr -d '[:space:]')"
  [ "$got" = "$want" ] && pass "$desc" || fail "$desc (want '$want', got '$got')"
}

# check_ok <description> <cmd...> : the command must succeed (exit 0).
check_ok() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc (unexpectedly failed)"; fi
}

# check_fail <description> <cmd...> : the command must NOT succeed (isolation).
check_fail() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then fail "$desc (unexpectedly succeeded)"; else pass "$desc"; fi
}

httpid() { $K -n "$1" exec "$2" -- wget -qO- -T4 "http://$3/" 2>/dev/null; }
fabric() { $K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.fabricIP}{'\n'}{end}" | awk -v p="$1" '$1==p{print $2}'; }
vpcip()  { $K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}"       | awk -v p="$1" '$1==p{print $2}'; }

SRV='mkdir -p /w && hostname > /w/index.html && httpd -f -p 80 -h /w'

idpod() { # idpod <ns> <name> <node> [vpc-annotation]
  local ann=""
  [ -n "${4:-}" ] && ann="annotations: {sdn.cozystack.io/vpc: $4}"
  $K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $2, namespace: $1, $ann}
spec:
  nodeName: $3
  containers: [{name: c, image: busybox:1.36, command: ["sh","-c","$SRV"]}]
EOF
}

vpc()     { $K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: $2, namespace: $1}
spec: {cidrs: ["$3"]}
EOF
}
binding() { $K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: $2, namespace: $1}
spec: {vpcRef: {namespace: $1, name: $2}}
EOF
}

cleanup() {
  docker rm -f v6tgt >/dev/null 2>&1
  [ "${KEEP:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
}

# ---- bring-up -------------------------------------------------------------
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
  $K apply -f "$ROOT/config/crd/" >/dev/null
  # The tenant kinds are served ONLY by the aggregated apiserver now — they have
  # no CRDs (docs/api-groups.md) — so the suite runs the real server. It
  # self-signs and uses a single ephemeral etcd (deploy/apiserver.yaml), so this
  # needs neither cert-manager nor the etcd operator.
  sed "s#ghcr.io/lllamnyp/cozyplane:dev#${IMAGE}#g" "$ROOT/deploy/apiserver.yaml" | $K apply -f - >/dev/null
  $K -n kube-system rollout status deploy/cozyplane-apiserver --timeout=180s || exit 1
  for _ in $(seq 1 30); do $K get vpcs.sdn.cozystack.io >/dev/null 2>&1 && break; sleep 2; done
  # Point every image reference at the e2e image.
  for f in agent controller authz; do sed "s#ghcr.io/lllamnyp/cozyplane:dev#${IMAGE}#g" "$ROOT/deploy/$f.yaml" | $K apply -f - >/dev/null; done
  $K -n kube-system rollout status ds/cozyplane-agent --timeout=180s || exit 1
  $K -n kube-system rollout status deploy/cozyplane-controller --timeout=120s || exit 1
fi

W="${CLUSTER}-worker"; W2="${CLUSTER}-worker2"
echo "== fixtures =="
$K create ns team-a >/dev/null 2>&1; $K create ns team-b >/dev/null 2>&1
# Two VPCs with the SAME CIDR (overlap), plus a disjoint one for peering.
vpc team-a vpc-a 10.0.0.0/24; binding team-a vpc-a
vpc team-b vpc-b 10.0.0.0/24; binding team-b vpc-b
vpc team-a vpc-c 10.1.0.0/24; binding team-a vpc-c
# IPv6 VPCs (disjoint), same tenant as a v4 VPC -> mixed-family multi-tenancy in
# one cluster/one map set. v6 rides the v4 Geneve underlay (v6-inner/v4-outer).
vpc team-a vpc6a fd00:a::/64; binding team-a vpc6a
vpc team-a vpc6b fd00:b::/64; binding team-a vpc6b
# Colliding pods: a1 (vpc-a) and bw1 (vpc-b) both land .2 on the same node.
idpod team-a a1  "$W"  vpc-a
idpod team-a a2  "$W2" vpc-a
idpod team-b bw1 "$W"  vpc-b
idpod team-b bw2 "$W"  vpc-b
idpod team-a c1  "$W2" vpc-c
# v6 pods: v6a1/v6a2 in vpc6a on different nodes (cross-node overlay), v6b1 in
# vpc6b (isolation, then peering).
idpod team-a v6a1 "$W"  vpc6a
idpod team-a v6a2 "$W2" vpc6a
idpod team-a v6b1 "$W2" vpc6b
# cli is pinned to W2, AWAY from the W-pinned VPC pods it probes: the v6
# north-south reply rides the kernel FORWARD path only cross-node, and an
# unpinned cli landing on W made the ip6tables-ACCEPT regression invisible in
# half the runs.
$K run cli --image=busybox:1.36 --restart=Never \
  --overrides="{\"spec\":{\"nodeName\":\"$W2\"}}" --command -- sleep 3600 >/dev/null 2>&1
# A pod annotated for vpc-a but in a namespace with NO binding -> default-deny.
$K create ns team-x >/dev/null 2>&1
idpod team-x nobind "$W" team-a/vpc-a

for p in a1 a2 c1 v6a1 v6a2 v6b1; do $K -n team-a wait --for=condition=Ready pod/$p --timeout=120s >/dev/null; done
for p in bw1 bw2; do $K -n team-b wait --for=condition=Ready pod/$p --timeout=120s >/dev/null; done
$K wait --for=condition=Ready pod/cli --timeout=120s >/dev/null

echo "== assertions =="

phase "default network"
CD=$($K -n kube-system get pods -l k8s-app=kube-dns -o jsonpath='{.items[0].status.podIP}')
check_ok "cli -> coredns (default overlay)" $K exec cli -- ping -c2 -W2 "$CD"
# A mis-masked fe80::1/0 on a host veth makes the kernel install
# `default dev cphX` (metric 256), outranking the host's RA default and
# hijacking node v6 egress. Guard: no node routes v6 default via a pod veth.
for n in $(kind get nodes --name "$CLUSTER" 2>/dev/null); do
  check_fail "no v6 default route via a cozyplane veth on $n" \
    bash -c "docker exec $n ip -6 route show default | grep -qE 'dev (cph|cpg)'"
done

phase "default-deny attachment"
check_fail "pod without a VPCBinding never becomes Ready" \
  $K -n team-x wait --for=condition=Ready pod/nobind --timeout=20s

phase "overlapping CIDRs: the same VPC IP resolves within each VPC"
# IPAM order isn't fixed, so resolve a2's real IP and prove that same numeric
# address is also assigned in vpc-b to a *different* pod. Delivery from each VPC
# must reach that VPC's pod (net-scoped), never cross the CIDR collision.
A2=$(vpcip a2)
check "a1 -> $A2 reaches a2 (vpc-a)" "a2" httpid team-a a1 "$A2"
BPEER=""; for p in bw1 bw2; do [ "$(vpcip "$p")" = "$A2" ] && BPEER=$p; done
BSRC=$([ "$BPEER" = bw1 ] && echo bw2 || echo bw1)
check "$BSRC -> $A2 reaches $BPEER (vpc-b), not a2" "$BPEER" httpid team-b "$BSRC" "$A2"

phase "north-south bridge to same-node same-IP pods"
check "cli -> a1.fabric  ($(fabric a1))"  "a1"  bash -c "$K exec cli -- wget -qO- -T4 http://$(fabric a1)/  2>/dev/null"
check "cli -> bw1.fabric ($(fabric bw1))" "bw1" bash -c "$K exec cli -- wget -qO- -T4 http://$(fabric bw1)/ 2>/dev/null"
check "cli -> a2.fabric  ($(fabric a2))"  "a2"  bash -c "$K exec cli -- wget -qO- -T4 http://$(fabric a2)/  2>/dev/null"
# ICMP echo through the bridge (the id stands in for the L4 port).
check_ok "cli -> a1.fabric ping (north-south ICMP)" $K exec cli -- ping -c2 -W3 "$(fabric a1)"
# Genuinely NODE-originated (host netns, not a pod): needs the fabric IP's
# permanent neighbour — the pod's interface carries only the VPC IP, so
# nothing answers ARP for the fabric address and, without the pinned entry,
# kubelet-probe-style traffic dies in FAILED resolution before to_pod's DNAT.
check "node($W) -> a1.fabric (node-originated bridge, fabric neighbour)" "a1" \
  bash -c "docker run --rm --net container:$W curlimages/curl:8.11.0 -s -m4 http://$(fabric a1)/"

phase "isolation"
check_fail "cli(default) -> VPC IP 10.0.0.2 directly" bash -c "$K exec cli -- wget -qO- -T3 http://10.0.0.2/ 2>/dev/null | grep -q ."

phase "peering: disjoint peers, overlapping cannot"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: a-to-c, namespace: team-a}
spec: {vpcRef: {name: vpc-a}, peerRef: {namespace: team-a, name: vpc-c}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: c-to-a, namespace: team-a}
spec: {vpcRef: {name: vpc-c}, peerRef: {namespace: team-a, name: vpc-a}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: a-to-b, namespace: team-a}
spec: {vpcRef: {name: vpc-a}, peerRef: {namespace: team-b, name: vpc-b}}
EOF
sleep 5
check "a1(vpc-a) -> c1(vpc-c, peered disjoint)" "c1" httpid team-a a1 "$(vpcip c1)"
check "overlapping a<->b peering stays Pending" "Pending" \
  $K -n team-a get vpcpeering a-to-b -o jsonpath='{.status.phase}'

phase "IPv6 VPC overlay: intra-VPC cross-node, isolation, peering"
V6A2=$(vpcip v6a2); V6B1=$(vpcip v6b1)
# Intra-VPC across nodes: proves v6 inner over the v4 Geneve underlay (encap +
# from_overlay delivery on the 128-bit maps).
check "v6a1 -> v6a2 (v6 intra-VPC, cross-node overlay)" "v6a2" httpid team-a v6a1 "[$V6A2]"
# Isolation: a different v6 VPC is unreachable until peered (same check the v4
# path makes, now on native v6 addresses).
check_fail "v6a1(vpc6a) -> v6b1(vpc6b) blocked (cross-VPC v6 isolation)" \
  bash -c "$K -n team-a exec v6a1 -- wget -qO- -T3 http://[$V6B1]/ 2>/dev/null | grep -q ."
# Peering two disjoint v6 VPCs opens the path both ways (peers map is family-agnostic).
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: v6a-to-v6b, namespace: team-a}
spec: {vpcRef: {name: vpc6a}, peerRef: {namespace: team-a, name: vpc6b}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCPeering
metadata: {name: v6b-to-v6a, namespace: team-a}
spec: {vpcRef: {name: vpc6b}, peerRef: {namespace: team-a, name: vpc6a}}
EOF
sleep 5
check "v6a1(vpc6a) -> v6b1(vpc6b) after peering (v6 peering)" "v6b1" httpid team-a v6a1 "[$V6B1]"

phase "IPv6 north-south: default client -> v6 fabric IP"
# v6a1's fabric IP is a v6 address from the node's v6 pod CIDR; a default-network
# client (dual-stack cli) reaches it, and to_pod's bridge_forward6 DNATs
# fabric->VPC while masquerading the client to fe80::1 (reversed in from_pod).
V6AFAB=$(fabric v6a1)
check "cli(default) -> v6a1 v6 fabric ($V6AFAB) (north-south TCP)" "v6a1" httpid default cli "[$V6AFAB]"
check_ok "cli(default) -> v6a1 v6 fabric ping (north-south ICMPv6)" \
  $K exec cli -- ping -c2 -W3 "$V6AFAB"

phase "egress via per-VPC gateway"
$K -n team-a patch vpc vpc-a --type=merge -p '{"spec":{"egress":{"natGateway":true}}}' >/dev/null
$K -n kube-system wait --for=condition=Ready pod -l app=cozyplane-gateway --timeout=120s >/dev/null 2>&1 || sleep 15
check "a1(vpc-a, egress on) -> internet 1.1.1.1" "" bash -c "$K -n team-a exec a1 -- ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 && echo"
check_fail "bw1(vpc-b, no egress) -> internet 1.1.1.1" bash -c "$K -n team-b exec bw1 -- ping -c1 -W2 1.1.1.1 >/dev/null 2>&1"
# v6 gateway egress: a v6 VPC's off-net traffic exits via its gateway pod
# (v6 .1 leg, ip6tables masquerade in the pod) and then the node's v6 bpf
# masquerade — the pod ULA is no more routable outside than the v4 pod CIDR.
# The target is an external container's ULA on the kind L2 (the docker bridge
# itself carries no v6 gateway address to ping).
docker run -d --rm --name v6tgt --network kind busybox:1.36 sleep 900 >/dev/null 2>&1
EGW6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' v6tgt 2>/dev/null)
$K -n team-a patch vpc vpc6a --type=merge -p '{"spec":{"egress":{"natGateway":true}}}' >/dev/null
$K -n kube-system wait --for=condition=Ready pod -l "app=cozyplane-gateway,sdn.cozystack.io/vpc=vpc6a" --timeout=120s >/dev/null 2>&1 || sleep 15
check_ok "v6a1(vpc6a, egress on) -> off-cluster v6 $EGW6 (gateway + masq6)" \
  $K -n team-a exec v6a1 -- ping -6 -c3 -W3 "$EGW6"
check_fail "v6b1(vpc6b, no egress) -> off-cluster v6 $EGW6" \
  bash -c "$K -n team-a exec v6b1 -- ping -6 -c1 -W2 $EGW6 >/dev/null 2>&1"

phase "bpf cluster-egress masquerade (#10): netfilter does no NAT"
# --masquerade defaults to bpf: the agent removes the kernel MASQUERADE rule
# and SNATs pod egress in the datapath at the uplink. Assert the kernel rule
# is gone on every node while egress still works — TCP, ICMP echo, and the
# ICMP-error path: traceroute's hop 2 is the docker gateway, whose
# time-exceeded arrives at the NODE address and must be un-SNAT'd (embedded
# header included) back to the pod.
for n in $(kind get nodes --name "$CLUSTER" 2>/dev/null); do
  check_fail "no COZYPLANE-MASQ nat rule on $n" \
    bash -c "docker exec $n iptables -t nat -S 2>/dev/null | grep -q COZYPLANE-MASQ"
done
check_ok "cli -> internet ping (bpf masq, ICMP echo)" $K exec cli -- ping -c2 -W3 1.1.1.1
check_ok "cli -> internet TCP connect (bpf masq)" \
  bash -c "$K exec cli -- sh -c 'nc -w3 1.1.1.1 80 </dev/null'"
MKNET=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -v : | head -1)
MKGW="$(echo "${MKNET:-172.18.0.0/16}" | cut -d. -f1-2).0.1"
check "cli traceroute hop2 = docker gw $MKGW (masq ICMP-error un-SNAT)" "ok" \
  bash -c "$K exec cli -- traceroute -q1 -w3 -m2 1.1.1.1 2>/dev/null | grep -q \"($MKGW)\" && echo ok"
# The v6 twin: a default pod's off-cluster v6 egress rides masq_snat6 to the
# node's v6 address (pod ULAs are unroutable outside), and the reply
# un-SNATs through masq_reverse6. Same external container as the gateway test.
check_ok "cli -> external v6 $EGW6 ping (bpf masq6, ICMPv6 echo)" \
  $K exec cli -- ping -6 -c2 -W3 "$EGW6"

phase "stale gateway .1 claim: abandoned-port GC unwedges the replacement"
# A gateway pod that dies uncleanly (node reboot) never runs CNI DEL, so its
# fixed .1 Port survives with a claimant that no longer exists; the replacement
# then loops on AlreadyExists forever. Fabricate exactly that: a stale .1 Port
# for vpc-c whose claimant pod is gone, then enable vpc-c's egress. The
# controller's abandoned-port GC must free the claim (through the sever
# finalizer) and the gateway must still come up and route.
CVNI=$($K -n team-a get vpc vpc-c -o jsonpath='{.status.vni}')
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: Port
metadata:
  name: v${CVNI}.10-1-0-1
  finalizers: [sdn.cozystack.io/sever]
  labels:
    sdn.cozystack.io/vpc-namespace: team-a
    sdn.cozystack.io/vpc: vpc-c
    sdn.cozystack.io/pod-namespace: kube-system
    sdn.cozystack.io/pod-name: cozyplane-gateway-dead-beef
    sdn.cozystack.io/pod-uid: 00000000-dead-beef-0000-000000000000
spec:
  vpcRef: {namespace: team-a, name: vpc-c}
  ip: 10.1.0.1
  node: ${W}
  podNamespace: kube-system
  podName: cozyplane-gateway-dead-beef
  gateway: true
EOF
$K -n team-a patch vpc vpc-c --type=merge -p '{"spec":{"egress":{"natGateway":true}}}' >/dev/null
check_ok "vpc-c gateway Ready despite the stale .1 claim (GC freed it)" \
  $K -n kube-system wait --for=condition=Ready pod -l "app=cozyplane-gateway,sdn.cozystack.io/vpc=vpc-c" --timeout=120s
check "c1(vpc-c, egress on) -> internet 1.1.1.1" "" bash -c "$K -n team-a exec c1 -- ping -c2 -W3 1.1.1.1 >/dev/null 2>&1 && echo"

phase "v6 floating IP: NDP advertisement, stateless DNAT, EIP egress"
# The v6 twin of the floating phase: the pool sits inside the kind network's
# on-link ULA /64, so the external client resolves the address by NDP — which
# only works if from_uplink's floating_ndp answers the solicitation.
KNET6=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}}
{{end}}' 2>/dev/null | grep : | head -1)
V6PFX=${KNET6%%::*}
FIP6="${V6PFX}:f10a::10"
V6A2IP=$(vpcip v6a2)
docker run -d --rm --name nacap --network kind nicolaka/netshoot \
  sh -c "tcpdump -lnni eth0 icmp6 > /tmp/cap.txt 2>&1" >/dev/null 2>&1
sleep 2
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: ExternalPool
metadata: {name: e2e-pub6}
spec: {cidrs: ["${V6PFX}:f10a::/96"], advertisement: L2}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: v6a2-fip, namespace: team-a}
spec: {vpcRef: {name: vpc6a}, target: "$V6A2IP", address: "$FIP6", poolRef: {name: e2e-pub6}}
EOF
$K -n team-a wait --for=jsonpath='{.status.phase}'=Ready floatingip/v6a2-fip --timeout=30s >/dev/null 2>&1
check "v6a2-fip Ready with $FIP6" "Ready" $K -n team-a get floatingip v6a2-fip -o jsonpath='{.status.phase}'
sleep 3
na=$(docker exec nacap grep -ciE "neighbor advertisement.*tgt is $FIP6" /tmp/cap.txt 2>/dev/null)
docker rm -f nacap >/dev/null 2>&1
[ "${na:-0}" -ge 1 ] && pass "unsolicited NA announced $FIP6 on programming" || fail "unsolicited NA announced $FIP6 on programming (saw ${na:-0})"
got6=""; for _ in $(seq 1 12); do got6=$(docker run --rm --network kind curlimages/curl:8.11.0 -s -m3 -g "http://[$FIP6]/" 2>/dev/null | tr -d '[:space:]'); [ "$got6" = "v6a2" ] && break; sleep 2; done
[ "$got6" = "v6a2" ] && pass "external v6 client -> [$FIP6] reaches v6a2 (NDP + DNAT)" || fail "external v6 client -> [$FIP6] reaches v6a2 (got '$got6')"
gotp6=""; for _ in $(seq 1 8); do docker run --rm --network kind busybox:1.36 ping -6 -c1 -W2 "$FIP6" >/dev/null 2>&1 && { gotp6=ok; break; }; sleep 2; done
[ "$gotp6" = ok ] && pass "external v6 ping -> $FIP6 (floating ICMPv6 echo)" || fail "external v6 ping -> $FIP6 (floating ICMPv6 echo)"
# EIP egress: v6a2's outbound to an external v6 listener must carry the
# floating source (floating_egress_snat6), not the VPC or fabric address.
docker run -d --rm --name eipcap6 --network kind nicolaka/netshoot \
  sh -c 'tcpdump -lnni eth0 "port 9998" > /tmp/cap.txt 2>&1' >/dev/null 2>&1
sleep 3
EIP6IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' eipcap6 2>/dev/null)
for _ in 1 2 3 4; do $K -n team-a exec v6a2 -- wget -qO- -T2 "http://[$EIP6IP]:9998/" >/dev/null 2>&1; sleep 1; done
srcseen6=$(docker exec eipcap6 grep -oiE "$FIP6" /tmp/cap.txt 2>/dev/null | head -1)
docker rm -f eipcap6 >/dev/null 2>&1
[ -n "$srcseen6" ] && pass "v6a2 outbound source = floating $FIP6 (v6 EIP egress)" || fail "v6a2 outbound source = floating $FIP6 (v6 EIP egress, saw '$srcseen6')"
# Errors out through the v6 floating path: external traceroute6's probes
# elicit ICMPv6 port-unreachable from v6a2's kernel; the embedded destination
# must be swapped VPC->public or the probes never correlate.
extlast6=$(docker run --rm --network kind nicolaka/netshoot traceroute6 -q1 -w3 -m6 "$FIP6" 2>/dev/null | tail -1)
if echo "$extlast6" | grep -qi "$FIP6"; then pass "external traceroute6 reaches $FIP6 (v6 floating error rewrite)"; else fail "external traceroute6 reaches $FIP6 (last hop: $extlast6)"; fi

phase "ICMP errors through the bridge (#3): traceroute correlates embedded headers"
# A UDP traceroute prints a hop only when the returned ICMP error's EMBEDDED
# packet matches the probe it sent, so reaching the destination proves the
# error path end to end — including the embedded-header NAT (a bad checksum
# would be dropped by the receiving kernel before traceroute ever saw it).
A1FAB=$(fabric a1)
check "cli UDP-traceroute reaches a1.fabric (bridge error un-NAT)" "ok" \
  bash -c "$K exec cli -- traceroute -q1 -w3 -m4 $A1FAB 2>/dev/null | grep -q \"($A1FAB)\" && echo ok"
# And the v6 twin: the pod's ICMPv6 port-unreachable traverses
# bridge_reverse6_icmp_err with the embedded header un-NAT'd; the ICMPv6
# checksum (pseudo-header included) is kernel-verified on receipt.
V6FAB=$(fabric v6a1)
check "cli UDP-traceroute6 reaches v6a1's v6 fabric (v6 bridge error un-NAT)" "ok" \
  bash -c "$K exec cli -- traceroute6 -q1 -w3 -m4 $V6FAB 2>/dev/null | grep -q \"($V6FAB)\" && echo ok"

phase "VPC DNS: split-horizon resolver (services-in-vpc.md, increment 1)"
# A VPC pod can't reach kube-dns (default-deny precedes everything), so the
# datapath steers its cluster-DNS queries to the node-local resolver: src ->
# the pod's fabric IP (the per-Port identity handle), dst -> node:15353, both
# halves stateless. The resolver answers headless Services annotated into the
# querying VPC with backend VPC IPs, NXDOMAINs every other cluster-domain name
# (never forwarded: tenants must stay unprovable), and forwards non-cluster
# names to the node's own upstreams.
dnspod() { # dnspod <name> <node> — labeled + hostname'd, an extra httpd on :53
  $K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: team-a, labels: {app: websvc}, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec:
  nodeName: $2
  hostname: $1
  containers: [{name: c, image: busybox:1.36, command: ["sh","-c","mkdir -p /w && hostname > /w/index.html && httpd -p 53 -h /w && httpd -f -p 80 -h /w"]}]
EOF
}
dnspod dns1 "$W"
dnspod dns2 "$W2"
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: websvc, namespace: team-a, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec: {clusterIP: None, selector: {app: websvc}, ports: [{name: http, port: 80}]}
---
apiVersion: v1
kind: Service
metadata: {name: plainsvc, namespace: team-a}
spec: {clusterIP: None, selector: {app: websvc}, ports: [{name: http, port: 80}]}
EOF
$K -n team-a wait --for=condition=Ready pod/dns1 pod/dns2 --timeout=120s >/dev/null
sleep 3 # endpointslice + resolver informer settle
WEB=websvc.team-a.svc.cluster.local
check "a1 -> $WEB (headless A -> VPC IPs, delivered end-to-end)" "ok" \
  bash -c "$K -n team-a exec a1 -- wget -qO- -T4 http://$WEB/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
check "a1 -> dns1.$WEB (per-hostname record)" "dns1" httpid team-a a1 "dns1.$WEB"
check "a1 -> dns2.$WEB (per-hostname record, cross-node)" "dns2" httpid team-a a1 "dns2.$WEB"
# The answer must be the VPC IP, not the fabric IP — the whole point of the
# split horizon (a fabric answer would leak the underlay and need the bridge).
check "dns1.$WEB resolves to the VPC IP $(vpcip dns1)" "ok" \
  bash -c "$K -n team-a exec a1 -- nslookup dns1.$WEB 2>/dev/null | grep -q '$(vpcip dns1)' && echo ok"
check_fail "bw1(vpc-b) cannot resolve vpc-a's $WEB (split horizon)" \
  bash -c "$K -n team-b exec bw1 -- nslookup $WEB >/dev/null 2>&1"
check_fail "a1 cannot resolve the unannotated plainsvc (nothing auto-projects)" \
  bash -c "$K -n team-a exec a1 -- nslookup plainsvc.team-a.svc.cluster.local >/dev/null 2>&1"
check_fail "a1 cannot resolve kube-dns.kube-system (cluster domain is authoritative, never forwarded)" \
  bash -c "$K -n team-a exec a1 -- nslookup kube-dns.kube-system.svc.cluster.local >/dev/null 2>&1"
# Non-cluster names defer upstream (the node's own resolv.conf). Must be a
# dotted name: busybox nslookup never queries a bare single-label name. The
# suite already requires internet (image pulls, the 1.1.1.1 egress checks).
check_ok "a1 resolves the off-cluster name example.com (upstream forwarder)" \
  $K -n team-a exec a1 -- nslookup example.com
# Steering matches only the cluster DNS address: a tenant's own :53 (here an
# httpd on 53 behind a VPC IP) is never hijacked — dstnet != 0 skips the steer.
check "a1 -> dns1's own :53 untouched (intra-VPC port 53 not hijacked)" "dns1" \
  httpid team-a a1 "$(vpcip dns1):53"
# Default-network pods are not steered; kube-dns serves them as before.
# Retried: busybox nslookup's short timeout flakes when the host is under
# image-pull/build load — the retries distinguish that from a real break.
check_ok "cli(default network) still resolves via kube-dns (not steered)" \
  bash -c "for i in 1 2 3; do $K exec cli -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1 && exit 0; sleep 3; done; exit 1"
# Peered-VPC resolution: names follow reachability. vpc-a and vpc-c are peered
# (disjoint CIDRs), so vpc-c's attached service resolves from a1 and the
# backends (vpc-c VPC IPs) deliver natively across the peering; vpc-b is not
# peered and must keep getting NXDOMAIN — indistinguishable from nonexistence.
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: cpeer, namespace: team-a, labels: {app: peersvc}, annotations: {sdn.cozystack.io/vpc: vpc-c}}
spec:
  nodeName: $W2
  hostname: cpeer
  containers: [{name: c, image: busybox:1.36, command: ["sh","-c","mkdir -p /w && hostname > /w/index.html && httpd -f -p 80 -h /w"]}]
---
apiVersion: v1
kind: Service
metadata: {name: peersvc, namespace: team-a, annotations: {sdn.cozystack.io/vpc: vpc-c}}
spec: {clusterIP: None, selector: {app: peersvc}, ports: [{name: http, port: 80}]}
EOF
$K -n team-a wait --for=condition=Ready pod/cpeer --timeout=120s >/dev/null
sleep 3
check "a1(vpc-a) -> peersvc (attached to peered vpc-c) resolves and delivers" "cpeer" \
  httpid team-a a1 peersvc.team-a.svc.cluster.local
check_fail "bw1(vpc-b, unpeered) cannot resolve vpc-c's peersvc" \
  bash -c "$K -n team-b exec bw1 -- nslookup peersvc.team-a.svc.cluster.local >/dev/null 2>&1"

phase "ServiceVIP: ClusterIP-equivalent inside a VPC (services-in-vpc.md, increment 2)"
# An attached non-headless Service gets a VIP from the VPC's OWN space (never
# the cluster ClusterIP): the controller materializes a ServiceVIP (allocated
# from the top of the CIDR; the CNI walks bottom-up), the resolver answers the
# name with it, and from_pod DNATs vip:port -> a backend VPC IP with per-flow
# pinning; the reply is rev-SNAT'd at the client's to_pod.
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: vipsvc, namespace: team-a, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec: {selector: {app: websvc}, ports: [{name: http, port: 80}]}
---
apiVersion: v1
kind: Pod
metadata: {name: viph, namespace: team-a, labels: {app: viph}, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec:
  nodeName: $W
  hostname: viph
  containers: [{name: c, image: busybox:1.36, command: ["sh","-c","mkdir -p /w && hostname > /w/index.html && httpd -f -p 80 -h /w"]}]
---
apiVersion: v1
kind: Service
metadata: {name: viphsvc, namespace: team-a, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec: {selector: {app: viph}, ports: [{name: http, port: 80}]}
EOF
$K -n team-a wait --for=condition=Ready pod/viph --timeout=120s >/dev/null
sleep 6 # controller allocation + agent map sync + resolver informer
VIPADDR=$($K get servicevips.sdn.cozystack.io -o jsonpath="{range .items[*]}{.spec.serviceRef.name}{' '}{.spec.ip}{'\n'}{end}" 2>/dev/null | awk '$1=="vipsvc"{print $2}')
check "vipsvc got a VIP from vpc-a's own space (top-down)" "ok" \
  bash -c "echo '$VIPADDR' | grep -q '^10\.0\.0\.' && echo ok"
check "a1 resolves vipsvc to the VIP (never the cluster ClusterIP)" "ok" \
  bash -c "$K -n team-a exec a1 -- nslookup vipsvc.team-a.svc.cluster.local 2>/dev/null | grep -q '$VIPADDR' && echo ok"
check "a1 -> vipsvc by name (VIP DNAT + LB, delivered)" "ok" \
  bash -c "$K -n team-a exec a1 -- wget -qO- -T4 http://vipsvc.team-a.svc.cluster.local/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
check "a1 -> the VIP address directly (data plane, no DNS)" "ok" \
  bash -c "$K -n team-a exec a1 -- wget -qO- -T4 http://$VIPADDR/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
check "cpeer(vpc-c, peered) -> vipsvc (VIP across the peering)" "ok" \
  bash -c "$K -n team-a exec cpeer -- wget -qO- -T4 http://vipsvc.team-a.svc.cluster.local/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
# Load balancing: 12 fresh flows from one client must reach BOTH backends
# (found live: a hash that only mixed the source port into the high bits made
# every flow from a client sticky to one backend).
check "VIP load-balances across backends (12 flows hit both)" "2" \
  bash -c "for i in \$(seq 1 12); do $K -n team-a exec cpeer -- wget -qO- -T4 http://vipsvc.team-a.svc.cluster.local/ 2>/dev/null; done | sort -u | grep -cE '^dns[12]\$'"
check_fail "bw1(vpc-b, unpeered) cannot resolve vipsvc" \
  bash -c "$K -n team-b exec bw1 -- nslookup vipsvc.team-a.svc.cluster.local >/dev/null 2>&1"
# Hairpin: the only backend of viphsvc dials its own service — the self-flow
# is loopback-SNAT'd out and back in on one veth (169.254.42.1).
check "viph -> its own service (hairpin self-dial)" "viph" \
  httpid team-a viph viphsvc.team-a.svc.cluster.local
# Session affinity (ClientIP): with sessionAffinity set, all of ONE client's
# fresh flows pin to a single backend (the source port drops from the hash).
# Affinity governs only NEW flows, so use a client that has never dialed the
# VIP — cpeer/a1 above left flow-pins that would mask it.
idpod team-a affcli "$W2" vpc-a
$K -n team-a wait --for=condition=Ready pod/affcli --timeout=120s >/dev/null
$K patch service vipsvc -n team-a --type=merge -p '{"spec":{"sessionAffinity":"ClientIP"}}' >/dev/null
# Poll for the controller to stamp affinity onto the ServiceVIP, then let the
# agent re-sync the map flag.
for _ in $(seq 1 10); do
  [ "$($K get servicevips.sdn.cozystack.io -o jsonpath="{range .items[*]}{.spec.serviceRef.name}{' '}{.spec.sessionAffinity}{'\n'}{end}" 2>/dev/null | awk '$1=="vipsvc"{print $2}')" = "ClientIP" ] && break
  sleep 2
done
sleep 3
check "affinity: 12 fresh flows from affcli pin to ONE backend" "1" \
  bash -c "for i in \$(seq 1 12); do $K -n team-a exec affcli -- wget -qO- -T4 http://vipsvc.team-a.svc.cluster.local/ 2>/dev/null; done | sort -u | grep -cE '^dns[12]\$'"
$K patch service vipsvc -n team-a --type=merge -p '{"spec":{"sessionAffinity":"None"}}' >/dev/null

phase "net-0 ClusterIP DNAT (kube-proxy-replacement.md, increment 3 Half A)"
# svc_forward/svc_return un-gated for net 0 serve default-network ClusterIPs
# per-packet — the path a bridge-bound VM guest takes (its traffic never makes
# a host socket syscall, so socket-LB can't rewrite it; this harness attaches
# no socket-LB at all, so a plain wget models it exactly). Isolation from the
# kube-proxy that runs here: the VIP under test is OUTSIDE the service CIDR and
# fed straight into the pinned svc_vips map at net 0 (as cozyplane-kpr does in
# production) — kube-proxy knows nothing of it and no route delivers it, so a
# response can only be the eBPF DNAT, in both directions.
idpod default n0web "$W"      # default-network backend (no vpc annotation)
$K wait --for=condition=Ready pod/n0web --timeout=120s >/dev/null
N0IP=$($K get pod n0web -o jsonpath='{.status.podIP}')
FAKEVIP=10.97.99.1            # outside the 10.96.0.0/16 service subnet

# A static bpftool (the CI/debug-recipe build) writes the map on the CLIENT's
# node — from_pod looks up svc_vips where the client runs (cli is on $W2).
BPFTOOL=/tmp/cozyplane-e2e-bpftool
if [ ! -x "$BPFTOOL" ]; then
  curl -sL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz | tar xz -C /tmp bpftool && mv /tmp/bpftool "$BPFTOOL" && chmod +x "$BPFTOOL"
fi
docker cp "$BPFTOOL" "$W2:/bpftool" >/dev/null
nat64hex() { local a b c d; IFS=. read -r a b c d <<<"$1"; printf '00 64 ff 9b 00 00 00 00 00 00 00 00 %02x %02x %02x %02x' "$a" "$b" "$c" "$d"; }
# svc_key {net=0, vip, TCP, port 80 network-order}; svc_val {n=1, flags=0,
# be[0]={backend ip, port 80}, 15 zero backends} — layouts from bpf/overlay.c.
KEYHEX="00 00 00 00 $(nat64hex "$FAKEVIP") 06 00 00 50"
VALHEX="01 00 00 00 00 00 00 00 $(nat64hex "$N0IP") 00 50 00 00 $(printf '00 %.0s' $(seq 1 300))"
docker exec "$W2" /bpftool map update pinned /sys/fs/bpf/cozyplane/svc_vips key hex $KEYHEX value hex $VALHEX any

check "net-0 client -> fake ClusterIP $FAKEVIP (svc_forward DNAT + svc_return un-DNAT; kube-proxy blind to it)" "n0web" \
  bash -c "$K exec cli -- wget -qO- -T4 http://$FAKEVIP/ 2>/dev/null"
docker exec "$W2" /bpftool map delete pinned /sys/fs/bpf/cozyplane/svc_vips key hex $KEYHEX
check_fail "the fake VIP goes dark once its net-0 svc_vips entry is removed (it WAS the eBPF path)" \
  bash -c "$K exec cli -- timeout 3 wget -qO- http://$FAKEVIP/ >/dev/null 2>&1"
$K delete pod n0web --wait=false >/dev/null 2>&1

phase "per-VPC traffic counters (#2): the datapath meters east-west by VPC"
# The agent serves per-VPC byte/packet counters on each node's :9411 (the
# DaemonSet is hostNetwork). Generate sustained intra-VPC traffic a1->a2 and
# assert vpc-a's tx bytes were metered on a1's node (W).
metrics() { docker run --rm --net "container:$1" nicolaka/netshoot curl -s -m4 http://localhost:9411/metrics 2>/dev/null; }
txval() { printf '%s' "$1" | grep 'cozyplane_vpc_tx_bytes_total{' | grep 'vpc="vpc-a"' | awk '{print $NF}' | head -1; }
before=$(txval "$(metrics "$W")")
$K -n team-a exec a1 -- sh -c "for i in \$(seq 1 30); do wget -qO- -T2 http://$A2/ >/dev/null 2>&1; done"
M=$(metrics "$W")
after=$(txval "$M")
if [ -n "$after" ] && [ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null; then
  pass "vpc-a tx bytes metered on $W (${before:-0} -> $after)"
else
  fail "vpc-a tx bytes metered on $W (before='${before:-}' after='${after:-}')"
fi
# The metric carries the VPC identity (name + namespace), not just the VNI.
ns=$(printf '%s' "$M" | grep 'cozyplane_vpc_rx_bytes_total{' | grep 'vpc="vpc-a"' | grep -oE 'vpc_namespace="[^"]+"' | head -1 | cut -d'"' -f2)
[ "$ns" = "team-a" ] && pass "metrics label vpc-a with namespace team-a" || fail "metrics label vpc-a namespace (got '$ns')"
# The default network (net 0) is never metered — no series with vni 0.
if printf '%s' "$M" | grep 'cozyplane_vpc_tx_bytes_total{' | grep -q 'vni="0"'; then
  fail "default network (vni 0) is not metered (a vni=0 series exists)"
else
  pass "default network (vni 0) is not metered"
fi

phase "guest autoconfiguration (#8): RA (M=1) + DHCPv6 hand out the pinned /128"
# Linux ignores a /128 Prefix Information Option (addrconf requires /64 on
# ethernet), so the agent's RA sets the Managed flag and a per-veth DHCPv6
# server answers with the exact pinned address — the same mechanism KubeVirt's
# masquerade binding uses. Simulate a guest: flush the static address, verify
# the RA route arrives, run the stock busybox DHCPv6 client, and the lease
# must carry the pinned address.
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: v6ra, namespace: team-a, annotations: {sdn.cozystack.io/vpc: vpc6a}}
spec:
  nodeName: $W
  containers:
    - name: c
      image: busybox:1.36
      command: ["sh","-c","mkdir -p /w && hostname > /w/index.html && httpd -f -p 80 -h /w"]
      securityContext: {privileged: true}
EOF
$K -n team-a wait --for=condition=Ready pod/v6ra --timeout=120s >/dev/null
V6RAIP=$(vpcip v6ra)
# RA: enable accept_ra and bounce the link; the kernel installs a proto-ra
# default route from the agent's advertisement.
$K -n team-a exec v6ra -- sh -c "echo 2 > /proc/sys/net/ipv6/conf/eth0/accept_ra; ip link set eth0 down; ip link set eth0 up" 2>/dev/null
# busybox's minimal `ip` prints no proto; an RA-installed default route is
# recognizable by its expiry (static routes never carry one).
got=""; for _ in $(seq 1 8); do $K -n team-a exec v6ra -- ip -6 route show default 2>/dev/null | grep -q "expires" && { got=ok; break; }; sleep 2; done
[ "$got" = ok ] && pass "v6ra received the RA (expiring default route)" || fail "v6ra received the RA (no expiring route)"
# DHCPv6: the stock client must be leased the exact pinned address. udhcpc6
# renders the address long-form, so install the lease and let the kernel
# canonicalize before comparing (a real guest's client installs it the same
# way).
$K -n team-a exec v6ra -- sh -c 'printf "#!/bin/sh\nset > /tmp/env6\n" > /tmp/s6.sh && chmod +x /tmp/s6.sh && ip -6 addr flush dev eth0 scope global && udhcpc6 -i eth0 -n -q -t 5 -T 2 -s /tmp/s6.sh >/dev/null 2>&1; leased=$(grep -oE "fd00[0-9a-f:]+" /tmp/env6 | head -1); [ -n "$leased" ] && ip -6 addr add "$leased/128" dev eth0 2>/dev/null' 
check "DHCPv6 leased the pinned address $V6RAIP" "ok" \
  bash -c "$K -n team-a exec v6ra -- ip -6 addr show dev eth0 2>/dev/null | grep -q '$V6RAIP/128' && echo ok"
sleep 2
check "v6a1 -> v6ra after re-acquisition (datapath unchanged)" "v6ra" httpid team-a v6a1 "[$V6RAIP]"

phase "stale locals pruning: a dead veth's entry must not shadow a reallocated IP"
# A pod that dies uncleanly leaves its locals/ports/bridges entries behind
# (no CNI DEL ran). The leak turns into a blackhole when its VPC IP is later
# reallocated to a pod on ANOTHER node: same-node senders hit the stale locals
# entry (dead ifindex) instead of the remote route. The agent prunes stale
# entries at start. Reproduce: kill cx's veth out-of-band, roll the agents
# (maps intact -> rebuild + prune), free cx's IP, let cy on another node claim
# it, and prove a same-node sender (cz) reaches cy.
idpod team-a cx "$W" vpc-c
idpod team-a cz "$W" vpc-c
$K -n team-a wait --for=condition=Ready pod/cx pod/cz --timeout=120s >/dev/null
CXIP=$(vpcip cx)
CXVETH=$(docker exec "$W" sh -c "grep -l 'ips=${CXIP}$' /sys/class/net/cph*/ifalias 2>/dev/null" | head -1 | cut -d/ -f5)
docker exec "$W" ip link del "$CXVETH"
# Piggyback on this restart: break a veth's fe80::1 to the historical /0 form
# (what the pre-fix CNI wrote); the agent's rebuild must heal it back to /64
# and remove the hijacking `default dev` route.
CLIVETH=$(docker exec "$W2" sh -c 'grep -l "10.244" /sys/class/net/cph*/ifalias 2>/dev/null | head -1' | cut -d/ -f5)
docker exec "$W2" sh -c "ip -6 addr del fe80::1/64 dev $CLIVETH 2>/dev/null; ip -6 addr add fe80::1/0 dev $CLIVETH nodad"
$K -n kube-system rollout restart ds/cozyplane-agent >/dev/null
$K -n kube-system rollout status ds/cozyplane-agent --timeout=180s >/dev/null 2>&1
sleep 3
check "agent healed the mis-masked fe80::1 back to /64" "1" \
  bash -c "docker exec $W2 ip -6 addr show dev $CLIVETH | grep -c 'fe80::1/64'"
check_fail "no default route left via $CLIVETH after the heal" \
  bash -c "docker exec $W2 ip -6 route show default | grep -q $CLIVETH"
$K -n team-a delete pod cx --now >/dev/null 2>&1
sleep 4
idpod team-a cy "$W2" vpc-c
$K -n team-a wait --for=condition=Ready pod/cy --timeout=120s >/dev/null
CYIP=$(vpcip cy)
[ "$CYIP" = "$CXIP" ] || echo "  note: cy got $CYIP (cx had $CXIP) — reuse not exercised"
check "cz($W) -> $CYIP reaches cy($W2) (stale local pruned, remote wins)" "cy" httpid team-a cz "$CYIP"

phase "floating IP: external ingress, source-preserving"
# Bind a public IP to a1's VPC IP; an off-cluster client (a container on the
# kind L2, off the overlay) must reach a1 through it. Exercises from_uplink ->
# to_pod floating DNAT -> pod, the source-preserving reply, and ARP advertisement
# from a1's node. The public IP is drawn from the kind subnet's high /24 (kind's
# DHCP allocates low), so the client resolves it by ARP on the shared bridge.
KNET=$(docker network inspect kind -f '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -v : | head -1)
KPFX=$(echo "${KNET:-172.18.0.0/16}" | cut -d. -f1-2)
FIP="${KPFX}.240.10"
A1IP=$(vpcip a1)
# Watch for the gratuitous ARP the agent emits when the address becomes local
# (the nudge that fixes external L2 caches when a floating IP moves nodes).
docker run -d --rm --name garpcap --network kind nicolaka/netshoot \
  sh -c "tcpdump -lnni eth0 arp > /tmp/cap.txt 2>&1" >/dev/null 2>&1
sleep 2
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: ExternalPool
metadata: {name: e2e-pub}
spec: {cidrs: ["${KPFX}.240.0/24"], advertisement: L2}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: a1-fip, namespace: team-a}
spec: {vpcRef: {name: vpc-a}, target: "$A1IP", address: "$FIP", poolRef: {name: e2e-pub}}
EOF
$K -n team-a wait --for=jsonpath='{.status.phase}'=Ready floatingip/a1-fip --timeout=30s >/dev/null 2>&1
check "a1-fip Ready with $FIP" "Ready" $K -n team-a get floatingip a1-fip -o jsonpath='{.status.phase}'
sleep 3
garp=$(docker exec garpcap grep -cE "Request who-has $FIP .*tell $FIP" /tmp/cap.txt 2>/dev/null)
docker rm -f garpcap >/dev/null 2>&1
[ "${garp:-0}" -ge 1 ] && pass "gratuitous ARP announced $FIP on programming" || fail "gratuitous ARP announced $FIP on programming (saw ${garp:-0})"
# External client: a throwaway container on the kind network, not a cluster node.
extget() { docker run --rm --network kind curlimages/curl:8.11.0 -s -m3 "$1" 2>/dev/null; }
got=""; for _ in $(seq 1 12); do got=$(extget "http://$FIP/" | tr -d '[:space:]'); [ "$got" = "a1" ] && break; sleep 2; done
[ "$got" = "a1" ] && pass "external client -> $FIP reaches a1" || fail "external client -> $FIP reaches a1 (got '$got')"
# ICMP echo through the floating IP (external ping, source-preserving).
gotp=""; for _ in $(seq 1 8); do docker run --rm --network kind busybox:1.36 ping -c1 -W2 "$FIP" >/dev/null 2>&1 && { gotp=ok; break; }; sleep 2; done
[ "$gotp" = ok ] && pass "external client ping -> $FIP (floating ICMP)" || fail "external client ping -> $FIP (floating ICMP)"
# EIP egress: a1 (floating-bound) initiates outbound; the remote must see the
# floating IP as the source, not the node/gateway address.
docker run -d --rm --name eipcap --network kind nicolaka/netshoot \
  sh -c 'tcpdump -lnni eth0 "port 9999" > /tmp/cap.txt 2>&1' >/dev/null 2>&1
sleep 3
EIPIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' eipcap 2>/dev/null)
for _ in 1 2 3 4; do $K -n team-a exec a1 -- wget -qO- -T2 "http://$EIPIP:9999/" >/dev/null 2>&1; sleep 1; done
srcseen=$(docker exec eipcap grep -oE "$FIP" /tmp/cap.txt 2>/dev/null | head -1)
docker rm -f eipcap >/dev/null 2>&1
[ "$srcseen" = "$FIP" ] && pass "a1 outbound source = floating IP $FIP (EIP egress)" || fail "a1 outbound source = floating IP $FIP (EIP egress, saw '$srcseen')"
# ICMP errors out through the floating path (#3): the external traceroute's
# probes elicit port-unreachable from a1's kernel; floating_egress_snat must
# rewrite the embedded destination vpc->public or traceroute can't correlate
# its probes and never prints the hop.
extlast=$(docker run --rm --network kind nicolaka/netshoot traceroute -q1 -w3 -m6 "$FIP" 2>/dev/null | tail -1)
if echo "$extlast" | grep -q "$FIP"; then pass "external UDP-traceroute reaches $FIP (floating error rewrite)"; else fail "external UDP-traceroute reaches $FIP (last hop: $extlast)"; fi

phase "map recreation: agent restart heals existing pods (no reboot)"
# Simulate the effect of a map-ABI upgrade: remove the CNI-written pinned maps
# (exactly what reconcilePins does to incompatible pins — the load then creates
# them fresh and empty) on every node, and roll the agents. The restarted agents
# must rebuild ports/locals/bridges from the veth alias records and re-attach
# the classifiers, so the EXISTING pods — not recreated — keep full
# connectivity, isolation included (issue #7).
for n in $(kind get nodes --name "$CLUSTER" 2>/dev/null); do
  docker exec "$n" sh -c 'rm -f /sys/fs/bpf/cozyplane/locals /sys/fs/bpf/cozyplane/bridges /sys/fs/bpf/cozyplane/ports /sys/fs/bpf/cozyplane/fabric_of'
done
$K -n kube-system rollout restart ds/cozyplane-agent >/dev/null
$K -n kube-system rollout status ds/cozyplane-agent --timeout=180s >/dev/null 2>&1
sleep 5
check "a1 -> a2 after map recreation (VPC cross-node, rebuilt locals)" "a2" httpid team-a a1 "$A2"
check "$BSRC -> $A2 still reaches $BPEER (net scoping survived the ports rebuild)" "$BPEER" httpid team-b "$BSRC" "$A2"
check "cli -> a1.fabric after map recreation (rebuilt bridges)" "a1" bash -c "$K exec cli -- wget -qO- -T4 http://$(fabric a1)/ 2>/dev/null"
check "v6a1 -> v6a2 after map recreation (v6 VPC, 128-bit rebuild)" "v6a2" httpid team-a v6a1 "[$V6A2]"
check_ok "cli -> coredns after map recreation (default network)" $K exec cli -- ping -c2 -W2 "$CD"
check "a1 -> $WEB after map recreation (rebuilt fabric_of, DNS steering intact)" "ok" \
  bash -c "$K -n team-a exec a1 -- wget -qO- -T4 http://$WEB/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
check "a1 -> vipsvc after map recreation (agents re-sync svc_vips)" "ok" \
  bash -c "$K -n team-a exec a1 -- wget -qO- -T4 http://vipsvc.team-a.svc.cluster.local/ 2>/dev/null | grep -qE '^dns[12]\$' && echo ok"
check_fail "cli(default) -> VPC IP still blocked after map recreation" \
  bash -c "$K exec cli -- wget -qO- -T3 http://10.0.0.2/ 2>/dev/null | grep -q ."

phase "security groups: intra-VPC policy (#7)"
# Labeled pods in vpc-a (all run the identity httpd on :80). Membership is
# claim-time from the pod labels the CNI stamps, so the labels must be set here.
sglpod() { # sglpod <name> <label-yaml>
  $K -n team-a apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $1, namespace: team-a, labels: {$2}, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec:
  nodeName: $W
  containers: [{name: c, image: busybox:1.36, command: ["sh","-c","$SRV"]}]
EOF
}
sglpod sgweb  "role: web"
sglpod sgcli  "role: client"
sglpod sgnone "sg: none"
$K -n team-a wait --for=condition=Ready pod/sgweb pod/sgcli pod/sgnone --timeout=60s >/dev/null 2>&1
SGWEB=$(vpcip sgweb)
# Baseline: no groups yet -> legacy allow-all intra-VPC.
check "sgcli -> sgweb (baseline, no groups: allow)"  "sgweb" httpid team-a sgcli  "$SGWEB"
check "sgnone -> sgweb (baseline, no groups: allow)" "sgweb" httpid team-a sgnone "$SGWEB"
# Apply policy: web admits client on TCP 80 only.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: client}}
  # Egress is symmetric default-deny (v2): client must be allowed to reach web.
  egress: [{to: {group: web}, ports: [{protocol: TCP, port: 80}]}]
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: web}}
  ingress: [{from: {group: client}, ports: [{protocol: TCP, port: 80}]}]
EOF
# Wait for id allocation + membership resolution.
for i in $(seq 1 20); do
  g=$($K get ports -o jsonpath="{range .items[*]}{.spec.podName}{'='}{.status.groups}{'\n'}{end}" | awk -F= '$1=="sgweb"{print $2}')
  [ -n "$g" ] && [ "$g" != "[]" ] && break; sleep 1
done
check "web/client groups allocated distinct ids" "1" bash -c "$K -n team-a get securitygroups -o jsonpath='{.items[*].status.id}' | tr ' ' '\n' | sort -u | wc -l | grep -q 2 && echo 1"
check "sgcli -> sgweb:80 (client admitted by rule)"        "sgweb" httpid team-a sgcli "$SGWEB"
check_fail "sgnone -> sgweb (ungrouped source, default-deny)" \
  bash -c "$K -n team-a exec sgnone -- wget -qO- -T3 http://$SGWEB/ 2>/dev/null | grep -q ."
check_fail "sgweb -> sgcli (client has no ingress, default-deny)" \
  bash -c "$K -n team-a exec sgweb -- wget -qO- -T3 http://$(vpcip sgcli)/ 2>/dev/null | grep -q ."

phase "security groups: egress (v2, symmetric default-deny)"
# Drop client's egress rule: sgcli can no longer reach web even though web's
# ingress still admits client (both directions must allow).
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: team-a}
spec: {vpcRef: {name: vpc-a}, podSelector: {matchLabels: {role: client}}}
EOF
sleep 3
check_fail "sgcli -> sgweb:80 with no client egress rule (egress default-deny)" \
  bash -c "$K -n team-a exec sgcli -- wget -qO- -T3 http://$SGWEB/ 2>/dev/null | grep -q ."
# Restore client's egress to web:80.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: client}}
  egress: [{to: {group: web}, ports: [{protocol: TCP, port: 80}]}]
EOF
sleep 3
check "sgcli -> sgweb:80 after restoring client egress (both directions allow)" "sgweb" httpid team-a sgcli "$SGWEB"

phase "security groups: north-south egress to.cidr (v2)"
# sgcli is grouped (client) with only an east-west egress rule, so its off-VPC
# egress (through vpc-a's NAT gateway, enabled far above) is default-denied.
# This is the hop the off-VPC-transit fix rescued: the pod->gateway delivery
# lands on the gateway pod's veth with a non-VPC destination, and without the
# fix the east-west egress check dropped it (grouped source -> ungrouped dst) —
# breaking all TCP/UDP north-south egress. TCP, not ICMP: ICMP is never gated.
check_fail "sgcli -> 1.1.1.1:80 TCP with no egress cidr rule (north-south default-deny)" \
  bash -c "$K -n team-a exec sgcli -- nc -w3 1.1.1.1 80 </dev/null"
# Open external egress for the client group with a to:{cidr} rule.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: client}}
  egress:
  - {to: {group: web}, ports: [{protocol: TCP, port: 80}]}
  - {to: {cidr: 0.0.0.0/0}, ports: [{protocol: TCP, port: 80}]}
EOF
sleep 3
check_ok "sgcli -> 1.1.1.1:80 TCP after to:{cidr:0.0.0.0/0} (north-south egress opens)" \
  bash -c "$K -n team-a exec sgcli -- nc -w3 1.1.1.1 80 </dev/null"
# Restore client to east-west-only egress for the assertions that follow.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: client}}
  egress: [{to: {group: web}, ports: [{protocol: TCP, port: 80}]}]
EOF
sleep 3

phase "security groups: peered-group reference (v2, Geneve TLV)"
# A labeled pod in the peered vpc-c, on the OTHER worker so its traffic to sgweb
# ($W) crosses a node and exercises the TLV path (from_pod stamps, from_overlay
# enforces). vpc-c is peered with vpc-a (a-to-c above).
# NOTE: the pod is sgpeer, NOT cpeer — a pod named cpeer already exists (the
# ServiceVIP section's, with an immutable hostname), and applying a different
# spec over it is rejected, leaving a pod without this section's role label.
$K -n team-a apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: sgpeer, namespace: team-a, labels: {role: cpeer}, annotations: {sdn.cozystack.io/vpc: vpc-c}}
spec: {nodeName: $W2, containers: [{name: c, image: busybox:1.36, command: ["sh","-c","$SRV"]}]}
EOF
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: cpeer, namespace: team-a}
spec:
  vpcRef: {name: vpc-c}
  podSelector: {matchLabels: {role: cpeer}}
  # Peer egress: cpeer (vpc-c) must be allowed to reach web in the peered vpc-a.
  egress: [{to: {group: web, vpc: {namespace: team-a, name: vpc-a}}, ports: [{protocol: TCP, port: 80}]}]
EOF
$K -n team-a wait --for=condition=Ready pod/sgpeer --timeout=60s >/dev/null 2>&1
# Before a peer rule: peered traffic to grouped sgweb is default-denied.
check_fail "sgpeer(vpc-c) -> sgweb before peer rule (cross-peer default-deny)" \
  bash -c "$K -n team-a exec sgpeer -- wget -qO- -T3 http://$SGWEB/ 2>/dev/null | grep -q ."
# web now also admits vpc-c's cpeer group (peer reference).
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: web}}
  ingress:
  - from: {group: client}
    ports: [{protocol: TCP, port: 80}]
  - from: {group: cpeer, vpc: {namespace: team-a, name: vpc-c}}
    ports: [{protocol: TCP, port: 80}]
EOF
for i in $(seq 1 20); do
  g=$($K get ports -o jsonpath="{range .items[*]}{.spec.podName}{'='}{.status.groups}{'\n'}{end}" | awk -F= '$1=="sgpeer"{print $2}')
  [ -n "$g" ] && [ "$g" != "[]" ] && break; sleep 1
done
check "sgpeer(vpc-c) -> sgweb:80 admitted by peer rule (cross-node, TLV authoritative)" "sgweb" httpid team-a sgpeer "$SGWEB"
check "same-VPC sgcli -> sgweb:80 still admitted alongside the peer rule" "sgweb" httpid team-a sgcli "$SGWEB"

phase "security groups: north-south from.cidr (v2)"
SGWEBFAB="$(fabric sgweb)"
# sgweb (grouped, no cidr rule) is default-denied to a default-network client.
check_fail "cli(default) -> sgweb.fabric before a cidr rule (N-S default-deny)" \
  bash -c "$K exec cli -- wget -qO- -T3 http://$SGWEBFAB/ 2>/dev/null | grep -q ."
# Invariant #7: a grouped pod with a TCP readiness probe must still go Ready —
# the kubelet probe reaches the fabric IP via the kernel route (unmarked), exempt.
$K -n team-a apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: probed, namespace: team-a, labels: {role: web}, annotations: {sdn.cozystack.io/vpc: vpc-a}}
spec:
  nodeName: $W
  containers:
  - {name: c, image: busybox:1.36, command: ["sh","-c","$SRV"], readinessProbe: {tcpSocket: {port: 80}, initialDelaySeconds: 2, periodSeconds: 2, failureThreshold: 3}}
EOF
$K -n team-a wait --for=condition=Ready pod/probed --timeout=40s >/dev/null 2>&1
check "grouped pod with a readiness probe stays Ready (kubelet exempt, invariant #7)" "true" \
  $K -n team-a get pod probed -o jsonpath='{.status.containerStatuses[0].ready}'
# Reopen north-south with from: {cidr: 0.0.0.0/0}.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: web}}
  ingress:
  - from: {group: client}
    ports: [{protocol: TCP, port: 80}]
  - from: {group: cpeer, vpc: {namespace: team-a, name: vpc-c}}
    ports: [{protocol: TCP, port: 80}]
  - from: {cidr: 0.0.0.0/0}
    ports: [{protocol: TCP, port: 80}]
EOF
sleep 4
check "cli(default) -> sgweb.fabric after from:{cidr:0.0.0.0/0} (north-south reopened)" "sgweb" \
  bash -c "$K exec cli -- wget -qO- -T4 http://$SGWEBFAB/ 2>/dev/null"

# Specific CIDR (LPM): admit only cli's own /32, deny an unrelated /32.
CLIIP="$($K get pod cli -o jsonpath='{.status.podIP}')"
websg() { $K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: team-a}
spec:
  vpcRef: {name: vpc-a}
  podSelector: {matchLabels: {role: web}}
  ingress: [{from: {cidr: $1}, ports: [{protocol: TCP, port: 80}]}]
EOF
}
websg "$CLIIP/32"; sleep 4
check "cli -> sgweb.fabric with from:{cidr:cli/32} (specific CIDR admits)" "sgweb" \
  bash -c "$K exec cli -- wget -qO- -T4 http://$SGWEBFAB/ 2>/dev/null"
websg "10.255.255.0/24"; sleep 4
check_fail "cli -> sgweb.fabric with from:{cidr:unrelated/24} (specific CIDR denies)" \
  bash -c "$K exec cli -- wget -qO- -T3 http://$SGWEBFAB/ 2>/dev/null | grep -q ."


phase "LoadBalancer ingress: delivery for a status LB IP (lb-ingress.md)"
# cozyplane consumes status.loadBalancer.ingress as written — here patched by
# hand, simulating ANY provider (CCM, MetalLB, a human with a console) — and
# delivers per externalTrafficPolicy: Local at from_uplink, client source
# preserved end to end. The backend echoes the peer address it saw, so source
# preservation is a body assertion. kpr feeds the per-node local-backend rows;
# deployed late in the suite so its socket-LB can't perturb earlier checks.
if [ -z "${KPR_IMAGE:-}" ]; then
  echo "== building cozyplane-kpr =="
  (cd "$ROOT" && CGO_ENABLED=0 go -C kpr build -o cozyplane-kpr . \
    && docker build -q -t cozyplane-kpr:dev -f kpr/Dockerfile kpr >/dev/null) \
    || fail "cozyplane-kpr image build"
  KPR_IMAGE=cozyplane-kpr:dev
fi
kind load docker-image "$KPR_IMAGE" --name "$CLUSTER" >/dev/null 2>&1
sed "s#image: cozyplane-kpr:dev#image: ${KPR_IMAGE}#" "$ROOT/deploy/kpr-daemonset.yaml" | $K apply -f - >/dev/null
$K -n kube-system rollout status ds/cozyplane-kpr --timeout=180s >/dev/null 2>&1 || fail "cozyplane-kpr rollout"

# TEST-NET-2: deliberately NOT on the kind L2 — nothing ARPs for it; the
# client routes it via a node, exactly what a provider's attraction does.
LBIP="198.51.100.7"
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: lbweb, namespace: default, labels: {app: lbweb}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command:
        - sh
        - -c
        - socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo HTTP/1.0 200 OK; echo; echo saw \$SOCAT_PEERADDR'
---
apiVersion: v1
kind: Service
metadata: {name: lbweb, namespace: default}
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  selector: {app: lbweb}
  ports: [{port: 80, targetPort: 8080}]
EOF
$K -n default wait --for=condition=Ready pod/lbweb --timeout=120s >/dev/null 2>&1
$K -n default patch svc lbweb --subresource=status --type=merge \
  -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$LBIP\"}]}}}" >/dev/null

# v4 InternalIP only: dual-stack kind reports both families and a mixed
# next-hop list breaks `ip route add`.
WIP=$($K get node "$W" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v : | head -1)
W2IP=$($K get node "$W2" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v : | head -1)
docker run -d --rm --name lbcli --cap-add NET_ADMIN --network kind nicolaka/netshoot sleep 600 >/dev/null 2>&1
LBCLIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' lbcli 2>/dev/null)
docker exec lbcli ip route add "$LBIP/32" via "$WIP" >/dev/null 2>&1
got=""
for _ in $(seq 1 12); do
  got=$(docker exec lbcli curl -s -m3 "http://$LBIP/" 2>/dev/null | tr -d '\r')
  echo "$got" | grep -q "saw" && break
  sleep 2
done
if [ "$got" = "saw $LBCLIP" ]; then
  pass "external client -> LB IP $LBIP served by the local backend, source preserved (backend saw $LBCLIP)"
else
  fail "external client -> LB IP $LBIP source-preserving delivery (got '$got', client $LBCLIP)"
fi
# etp: Local's contract — a node without local ready backends must NOT serve.
docker exec lbcli ip route replace "$LBIP/32" via "$W2IP" >/dev/null 2>&1
check_fail "LB IP via the backend-less node does not serve (etp: Local)" \
  docker exec lbcli curl -s -m3 "http://$LBIP/"
docker exec lbcli ip route replace "$LBIP/32" via "$WIP" >/dev/null 2>&1

# loadBalancerSourceRanges: a firewall on the LB IP, enforced at the DNAT
# point (lb_src LPM). Admit the client's /32 -> works; an unrelated range ->
# dropped before any flow state; cleared -> works again.
$K -n default patch svc lbweb --type=merge -p "{\"spec\":{\"loadBalancerSourceRanges\":[\"$LBCLIP/32\"]}}" >/dev/null
sleep 3
got=$(docker exec lbcli curl -s -m3 "http://$LBIP/" 2>/dev/null | tr -d '\r')
[ "$got" = "saw $LBCLIP" ] && pass "sourceRanges admits the declared client /32" \
  || fail "sourceRanges admits the declared client /32 (got '$got')"
$K -n default patch svc lbweb --type=merge -p '{"spec":{"loadBalancerSourceRanges":["192.0.2.0/24"]}}' >/dev/null
sleep 3
check_fail "sourceRanges drops an undeclared client" \
  docker exec lbcli curl -s -m3 "http://$LBIP/"
$K -n default patch svc lbweb --type=json -p '[{"op":"remove","path":"/spec/loadBalancerSourceRanges"}]' >/dev/null
sleep 3

# External NodePort: the same rows keyed by the node's own address. The
# kube-proxy NODEPORTS counter must stay flat — tc runs before netfilter, so
# a served curl that leaves it unmoved was served by cozyplane.
NP=$($K -n default get svc lbweb -o jsonpath='{.spec.ports[0].nodePort}')
npcount() { docker exec "$W" iptables -t nat -L KUBE-NODEPORTS -v -x 2>/dev/null | awk 'NR>2{n+=$1}END{print n+0}'; }
np0=$(npcount)
got=$(docker exec lbcli curl -s -m3 "http://$WIP:$NP/" 2>/dev/null | tr -d '\r')
[ "$got" = "saw $LBCLIP" ] && pass "external NodePort $WIP:$NP served, source preserved" \
  || fail "external NodePort $WIP:$NP served, source preserved (got '$got')"
np1=$(npcount)
[ "$np0" = "$np1" ] && pass "kube-proxy KUBE-NODEPORTS counter flat: cozyplane served it" \
  || fail "kube-proxy KUBE-NODEPORTS counter moved ($np0 -> $np1): kube-proxy served it"
check_fail "NodePort on the backend-less node does not serve (etp: Local)" \
  docker exec lbcli curl -s -m3 "http://$W2IP:$NP/"

# v6 LB IP: same composition through the v6 halves (lb_ingress is
# family-agnostic; the reply resolves via the FIB like the floating v6 exit).
WIP6=$($K get node "$W" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep : | head -1)
LBIP6="2001:db8:42::7"
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: lbweb6, namespace: default, labels: {app: lbweb6}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command:
        - sh
        - -c
        - socat TCP6-LISTEN:8080,fork,reuseaddr SYSTEM:'echo HTTP/1.0 200 OK; echo; echo saw \$SOCAT_PEERADDR'
---
apiVersion: v1
kind: Service
metadata: {name: lbweb6, namespace: default}
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  ipFamilies: [IPv6]
  selector: {app: lbweb6}
  ports: [{port: 80, targetPort: 8080}]
EOF
$K -n default wait --for=condition=Ready pod/lbweb6 --timeout=120s >/dev/null 2>&1
$K -n default patch svc lbweb6 --subresource=status --type=merge \
  -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$LBIP6\"}]}}}" >/dev/null
LBCLIP6=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' lbcli 2>/dev/null)
docker exec lbcli ip -6 route add "$LBIP6/128" via "$WIP6" >/dev/null 2>&1
got=""
for _ in $(seq 1 10); do
  got=$(docker exec lbcli curl -gs -m3 "http://[$LBIP6]/" 2>/dev/null | tr -d '\r')
  echo "$got" | grep -q "saw" && break
  sleep 2
done
# socat reports the v6 peer bracketed and fully expanded; normalize both
# sides to the canonical form before comparing.
gotip=$(echo "$got" | sed -n 's/^saw \[\(.*\)\]$/\1/p')
gotnorm=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))" "$gotip" 2>/dev/null)
wantnorm=$(python3 -c "import ipaddress,sys; print(ipaddress.ip_address(sys.argv[1]))" "$LBCLIP6" 2>/dev/null)
[ -n "$gotnorm" ] && [ "$gotnorm" = "$wantnorm" ] && pass "v6 LB IP $LBIP6 served, source preserved (backend saw $gotnorm)" \
  || fail "v6 LB IP $LBIP6 source-preserving delivery (got '$got', client $LBCLIP6)"

# A VPC-pod backend: the row carries the pod's fabric address; lb_ingress
# takes the bridges hop and DNATs straight to the VPC IP with NO client
# masquerade — the tenant pod sees the real external caller.
LBIP2="198.51.100.8"
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: lbvpc
  namespace: team-a
  labels: {app: lbvpc}
  annotations: {sdn.cozystack.io/vpc: vpc-a}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command:
        - sh
        - -c
        - socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo HTTP/1.0 200 OK; echo; echo saw \$SOCAT_PEERADDR'
---
apiVersion: v1
kind: Service
metadata: {name: lbvpc, namespace: team-a}
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  selector: {app: lbvpc}
  ports: [{port: 80, targetPort: 8080}]
EOF
$K -n team-a wait --for=condition=Ready pod/lbvpc --timeout=120s >/dev/null 2>&1
$K -n team-a patch svc lbvpc --subresource=status --type=merge \
  -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$LBIP2\"}]}}}" >/dev/null
docker exec lbcli ip route add "$LBIP2/32" via "$WIP" >/dev/null 2>&1
got=""
for _ in $(seq 1 10); do
  got=$(docker exec lbcli curl -s -m3 "http://$LBIP2/" 2>/dev/null | tr -d '\r')
  echo "$got" | grep -q "saw" && break
  sleep 2
done
[ "$got" = "saw $LBCLIP" ] && pass "VPC-pod backend behind LB IP $LBIP2: delivered into the VPC, source preserved" \
  || fail "VPC-pod backend behind LB IP $LBIP2 (got '$got', client $LBCLIP)"

# etp: Cluster — DSR. The backend lives only on $W; the client enters via
# $W2, which Local provably refuses (checked above). The ingress node DNATs
# with the client source untouched and DSR-encapsulates to $W with the
# frontend identity in a Geneve option; the reply exits $W's own uplink
# already answering as the LB IP. The backend must still see the REAL client.
LBIP3="198.51.100.9"
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: lbclu, namespace: default, labels: {app: lbclu}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command:
        - sh
        - -c
        - socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo HTTP/1.0 200 OK; echo; echo saw \$SOCAT_PEERADDR'
---
apiVersion: v1
kind: Service
metadata: {name: lbclu, namespace: default}
spec:
  type: LoadBalancer
  selector: {app: lbclu}
  ports: [{port: 80, targetPort: 8080}]
EOF
$K -n default wait --for=condition=Ready pod/lbclu --timeout=120s >/dev/null 2>&1
$K -n default patch svc lbclu --subresource=status --type=merge \
  -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$LBIP3\"}]}}}" >/dev/null
docker exec lbcli ip route add "$LBIP3/32" via "$W2IP" >/dev/null 2>&1
# DSR is strictly opt-in and the DS ships CLUSTER_DSR=false: while gated
# off, cozyplane writes no row on the backend-less node, so no
# source-preserving delivery can happen. (This kind cluster still runs
# kube-proxy, so the un-intercepted traffic falls through to its iptables
# — served, but masqueraded. The preserved client source is DSR's
# unforgeable signature; on a cozyplane-only cluster the node refuses.)
sleep 5
got=$(docker exec lbcli curl -s -m3 "http://$LBIP3/" 2>/dev/null | tr -d '\r')
[ "$got" = "saw $LBCLIP" ] && fail "etp Cluster gated off, yet delivery preserved the source (DSR leaked past the gate)" \
  || pass "etp Cluster gated off (CLUSTER_DSR=false): no source-preserving delivery (got '${got:-nothing}')"
$K -n kube-system set env ds/cozyplane-kpr -c kpr CLUSTER_DSR=true >/dev/null
$K -n kube-system rollout status ds/cozyplane-kpr --timeout=180s >/dev/null 2>&1 \
  || fail "cozyplane-kpr rollout after CLUSTER_DSR=true"
got=""
for _ in $(seq 1 10); do
  got=$(docker exec lbcli curl -s -m3 "http://$LBIP3/" 2>/dev/null | tr -d '\r')
  echo "$got" | grep -q "saw" && break
  sleep 2
done
[ "$got" = "saw $LBCLIP" ] && pass "etp Cluster via the backend-less node: DSR to the backend, source preserved" \
  || fail "etp Cluster DSR delivery (got '$got', client $LBCLIP)"
# NodePort under Cluster (the upstream default) serves from ANY node.
NP3=$($K -n default get svc lbclu -o jsonpath='{.spec.ports[0].nodePort}')
got=$(docker exec lbcli curl -s -m3 "http://$W2IP:$NP3/" 2>/dev/null | tr -d '\r')
[ "$got" = "saw $LBCLIP" ] && pass "default-policy NodePort $W2IP:$NP3 (Cluster) served from the backend-less node" \
  || fail "default-policy NodePort via backend-less node (got '$got', client $LBCLIP)"
docker rm -f lbcli >/dev/null 2>&1

# --- Default-net NetworkPolicy (docs/network-policy.md, increment 1) ---
# Upstream networking.k8s.io/v1 policies compiled to identity-pair rules,
# enforced destination-side in to_pod at net 0. Server on $W with a readiness
# probe (the node-exemption canary); a same-node allowed peer, a cross-node
# client whose label flips prove label-follows both ways.
phase "NetworkPolicy: default-net (network-policy.md)"
$K create ns nptest >/dev/null
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: npsrv, namespace: nptest, labels: {app: npsrv}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
      readinessProbe: {tcpSocket: {port: 8080}, periodSeconds: 2}
---
apiVersion: v1
kind: Pod
metadata: {name: npcli, namespace: nptest, labels: {role: cli}}
spec:
  nodeName: $W2
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
---
apiVersion: v1
kind: Pod
metadata: {name: npsame, namespace: nptest, labels: {role: allowed}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
EOF
$K -n nptest wait --for=condition=Ready pod/npsrv pod/npcli pod/npsame --timeout=120s >/dev/null 2>&1
NPSRV=$($K -n nptest get pod npsrv -o jsonpath='{.status.podIP}')
NPSRV6=$($K -n nptest get pod npsrv -o jsonpath='{.status.podIPs[*].ip}' | tr ' ' '\n' | grep : | head -1)

np_served() { # ns pod url — poll until the request serves
  for _ in $(seq 1 10); do
    $K -n "$1" exec "$2" -- curl -gs -m3 "$3" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
np_refused() { # ns pod url — poll until the request stops serving
  for _ in $(seq 1 10); do
    $K -n "$1" exec "$2" -- curl -gs -m3 "$3" >/dev/null 2>&1 || return 0
    sleep 2
  done
  return 1
}

np_served nptest npcli "http://$NPSRV:8080/" && pass "npsrv serves npcli before any policy" \
  || fail "npsrv unreachable before any policy"

$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ingress, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: allowed}}}]
      ports: [{port: 8080}]
EOF
np_refused nptest npcli "http://$NPSRV:8080/" && pass "isolated npsrv refuses the unlabeled client" \
  || fail "npsrv still serves npcli under the role=allowed-only policy"
np_served nptest npsame "http://$NPSRV:8080/" && pass "same-node allowed peer served" \
  || fail "same-node allowed peer refused"
[ -n "$NPSRV6" ] && { np_refused nptest npcli "http://[$NPSRV6]:8080/" \
  && pass "v6 delivery gated by the same policy" || fail "v6 leaked past the policy"; }

# Label-follows, both directions: relabel the client into the allowed set and
# back out — upstream semantics SG v1 deliberately lacked.
$K -n nptest label pod npcli role=allowed --overwrite >/dev/null
np_served nptest npcli "http://$NPSRV:8080/" && pass "relabeled client admitted (label-follows)" \
  || fail "relabel to role=allowed did not open the path"
$K -n nptest label pod npcli role=cli --overwrite >/dev/null
np_refused nptest npcli "http://$NPSRV:8080/" && pass "relabel back re-isolates (label-follows both ways)" \
  || fail "relabel back to role=cli did not close the path"

# Kubelet probes are node-origin plumbing and bypass policy: the isolated
# server must still be Ready (its probe has been firing throughout).
sleep 4
ready=$($K -n nptest get pod npsrv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$ready" = "True" ] && pass "isolated npsrv stays Ready (kubelet probe exempt)" \
  || fail "kubelet probe blocked by policy (Ready=$ready)"

# An ingress-isolated pod's UDP DNS still works: the query's egress pins
# np_ct on the pod's node, the reply enters on the pin (upstream-stateful
# UDP without a policy conntrack).
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npcli-lockdown, namespace: nptest}
spec:
  podSelector: {matchLabels: {role: cli}}
  policyTypes: [Ingress]
EOF
sleep 4
dnsok=0
for _ in $(seq 1 5); do
  $K -n nptest exec npcli -- nslookup -timeout=3 kubernetes.default >/dev/null 2>&1 && { dnsok=1; break; }
  sleep 2
done
[ "$dnsok" = "1" ] && pass "ingress-isolated pod's UDP DNS works (np_ct reply-pin)" \
  || fail "isolated pod's DNS reply dropped (reply-pin broken)"

# An empty from: rule admits everything (NP_SRC_ANY) — policies union.
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-open, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress: [{}]
EOF
np_served nptest npcli "http://$NPSRV:8080/" && pass "empty-from rule reopens npsrv (NP_SRC_ANY union)" \
  || fail "empty-from rule did not admit the client"

# --- increment 2: ipBlock + egress (network-policy.md) ---
# External clients reach pods via the sanctioned paths only (LB/NodePort), so
# the ipBlock tests ride a hand-provisioned LB IP (the thought-experiment
# path): status patched by hand, client routed at a node, lb_ingress DNATs
# with the source preserved — exactly what ipBlock evaluates.
$K -n nptest delete networkpolicy npsrv-open >/dev/null
NPLB="198.51.100.20"
NPWIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$W")
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Service
metadata: {name: npsrv, namespace: nptest}
spec:
  type: LoadBalancer
  externalTrafficPolicy: Local
  selector: {app: npsrv}
  ports: [{port: 8080, targetPort: 8080}]
EOF
$K -n nptest patch svc npsrv --subresource=status --type=merge \
  -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$NPLB\"}]}}}" >/dev/null
docker run -d --rm --name npext --cap-add NET_ADMIN --network kind nicolaka/netshoot \
  sh -c 'python3 -m http.server 8080 --bind :: >/dev/null 2>&1 & sleep 600' >/dev/null 2>&1
NPEXTIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' npext)
docker exec npext ip route add "$NPLB/32" via "$NPWIP" >/dev/null 2>&1

npext_refused() {
  for _ in $(seq 1 10); do
    docker exec npext curl -s -m3 "http://$NPLB:8080/" >/dev/null 2>&1 || return 0
    sleep 2
  done
  return 1
}
npext_served() {
  for _ in $(seq 1 10); do
    docker exec npext curl -s -m3 "http://$NPLB:8080/" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

npext_refused && pass "isolated backend refuses the external LB client (no ipBlock)" \
  || fail "external client served without an ipBlock rule"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ext, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{ipBlock: {cidr: $NPEXTIP/32}}]
      ports: [{port: 8080}]
EOF
npext_served && pass "ipBlock admits the declared external client (through lb_ingress, source preserved)" \
  || fail "ipBlock rule did not admit the external client"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ext, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{ipBlock: {cidr: 172.18.0.0/16, except: [$NPEXTIP/32]}}]
      ports: [{port: 8080}]
EOF
npext_refused && pass "ipBlock except masks the client (longer deny prefix wins)" \
  || fail "ipBlock except did not mask the client"

# Egress: pair rule, external default-deny, the canonical DNS rule, ipBlock.
NPSAME=$($K -n nptest get pod npsame -o jsonpath='{.status.podIP}')
np_served nptest npcli "http://$NPSAME:8080/" && pass "npcli reaches npsame before egress policy" \
  || fail "npsame unreachable before egress policy"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: cli-egress, namespace: nptest}
spec:
  podSelector: {matchLabels: {role: cli}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {role: allowed}}}]
      ports: [{port: 8080}]
EOF
dnsdead=0
for _ in $(seq 1 10); do
  $K -n nptest exec npcli -- nslookup -timeout=2 kubernetes.default >/dev/null 2>&1 || { dnsdead=1; break; }
  sleep 2
done
[ "$dnsdead" = "1" ] && pass "egress isolation gates UDP DNS (no rule yet)" \
  || fail "egress-isolated pod still resolves DNS without a rule"
np_served nptest npcli "http://$NPSAME:8080/" && pass "egress pair rule admits the declared destination" \
  || fail "egress pair rule did not admit npsame"
egout=0
$K -n nptest exec npcli -- curl -s -m3 "http://$NPEXTIP:8080/" >/dev/null 2>&1 && egout=1
[ "$egout" = "0" ] && pass "external egress default-deny (no cidr rule)" \
  || fail "egress-isolated pod reached an external destination without a rule"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: cli-egress, namespace: nptest}
spec:
  podSelector: {matchLabels: {role: cli}}
  policyTypes: [Egress]
  egress:
    - to: [{podSelector: {matchLabels: {role: allowed}}}]
      ports: [{port: 8080}]
    - to: [{namespaceSelector: {}}]
      ports: [{protocol: UDP, port: 53}]
    - to: [{ipBlock: {cidr: $NPEXTIP/32}}]
      ports: [{port: 8080}]
EOF
dnsok=0
for _ in $(seq 1 10); do
  $K -n nptest exec npcli -- nslookup -timeout=3 kubernetes.default >/dev/null 2>&1 && { dnsok=1; break; }
  sleep 2
done
[ "$dnsok" = "1" ] && pass "egress DNS rule (ANY_POD destination, UDP 53) restores lookups" \
  || fail "DNS still dead under the egress DNS rule"
egok=0
for _ in $(seq 1 10); do
  $K -n nptest exec npcli -- curl -s -m3 "http://$NPEXTIP:8080/" >/dev/null 2>&1 && { egok=1; break; }
  sleep 2
done
[ "$egok" = "1" ] && pass "egress ipBlock opens the external destination (from_pod gate)" \
  || fail "egress ipBlock did not open the external destination"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: cli-egress, namespace: nptest}
spec:
  podSelector: {matchLabels: {role: cli}}
  policyTypes: [Egress]
  egress: [{}]
EOF
egany=0
for _ in $(seq 1 10); do
  $K -n nptest exec npcli -- curl -s -m3 "http://$NPEXTIP:8080/" >/dev/null 2>&1 && { egany=1; break; }
  sleep 2
done
[ "$egany" = "1" ] && pass "empty egress rule = allow-all destinations (reserved ANY)" \
  || fail "empty egress rule did not allow the external destination"

# endPort ranges (increment 3): the np_allow port-suffix LPM. A range
# covering 8080 admits; sliding it off 8080 refuses.
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-range, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: cli}}}]
      ports: [{port: 8000, endPort: 8999}]
EOF
np_served nptest npcli "http://$NPSRV:8080/" && pass "endPort range 8000-8999 admits port 8080" \
  || fail "endPort range did not admit a port inside it"
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-range, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: cli}}}]
      ports: [{port: 9000, endPort: 9999}]
EOF
np_refused nptest npcli "http://$NPSRV:8080/" && pass "port outside the endPort range refused" \
  || fail "a port outside the endPort range was admitted"
docker rm -f npext >/dev/null 2>&1

# --- NP entities: nodes / local-pods / local-node (policy-layers.md) ---
# The node exemption narrowed to the LOCAL node: a REMOTE node's traffic to an
# isolated pod is now gated, and the `nodes` entity is how a policy readmits it
# (the apiserver->webhook shape). local-pods admits a co-scheduled net-0 pod.
phase "NetworkPolicy entities (policy-layers.md)"
# Start from a clean policy slate: the increment-2 ipBlock policies admit
# 172.18.0.0/16 — which on kind is the NODE subnet, so they would admit the
# remote node and mask the narrowed exemption entirely.
$K -n nptest delete networkpolicy --all >/dev/null 2>&1
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: nphost1, namespace: nptest}
spec:
  nodeName: $W
  hostNetwork: true
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
---
apiVersion: v1
kind: Pod
metadata: {name: nphost2, namespace: nptest}
spec:
  nodeName: $W2
  hostNetwork: true
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
EOF
$K -n nptest wait --for=condition=Ready pod/nphost1 pod/nphost2 --timeout=120s >/dev/null 2>&1

# npsrv (on $W) ingress-isolated by an ordinary pod-selector policy.
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ent, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: allowed}}}]
      ports: [{port: 8080}]
EOF
np_served nptest nphost1 "http://$NPSRV:8080/" && pass "local node still reaches an isolated pod (structural exemption, the kubelet shape)" \
  || fail "local-node origin gated — the plumbing exemption broke"
np_refused nptest nphost2 "http://$NPSRV:8080/" && pass "REMOTE node gated by default (exemption narrowed to the local node)" \
  || fail "remote-node origin is still blanket-exempt"
$K -n nptest get pod npsrv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "isolated pod stays Ready under the narrowed exemption (probes are local-node)" \
  || fail "narrowing the exemption broke kubelet probes"

# The `nodes` entity readmits remote-node origin (the apiserver->webhook shape).
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ent, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {policy.cozyplane.io/entity: nodes}}
      ports: [{port: 8080}]
EOF
np_served nptest nphost2 "http://$NPSRV:8080/" && pass "nodes entity admits the remote node" \
  || fail "nodes entity did not admit remote-node origin"
np_refused nptest npcli "http://$NPSRV:8080/" && pass "nodes entity does not leak to pod sources" \
  || fail "nodes entity admitted an ordinary pod"

# local-pods: npsame is co-scheduled with npsrv on $W; npcli lives on $W2.
$K apply -f - >/dev/null <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: npsrv-ent, namespace: nptest}
spec:
  podSelector: {matchLabels: {app: npsrv}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {policy.cozyplane.io/entity: local-pods}}
      ports: [{port: 8080}]
EOF
np_served nptest npsame "http://$NPSRV:8080/" && pass "local-pods entity admits a co-scheduled pod" \
  || fail "local-pods entity did not admit the same-node pod"
np_refused nptest npcli "http://$NPSRV:8080/" && pass "local-pods entity refuses the cross-node pod (placement, as declared)" \
  || fail "local-pods entity admitted a pod on another node"

$K delete ns nptest --wait=false >/dev/null 2>&1

# --- Host firewall (docs/host-firewall.md) ---
# A HostFirewall selecting $W makes the node itself default-deny for new
# TCP/UDP flows: external and pod sources are gated, node sources / ICMP /
# the overlay / replies stay exempt, and node-originated UDP returns via the
# hf_ct pins (all three write points exercised below).
phase "HostFirewall (host-firewall.md)"
WADDRS=$($K get node "$W" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
WIP4=$(echo "$WADDRS" | tr ' ' '\n' | grep -v : | head -1)
WIP6=$(echo "$WADDRS" | tr ' ' '\n' | grep : | head -1)
$K create ns hftest >/dev/null
$K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: hfsrv, namespace: hftest}
spec:
  nodeName: $W
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "18080", --bind, "::"]
      readinessProbe: {tcpSocket: {port: 18080}, periodSeconds: 2}
---
apiVersion: v1
kind: Pod
metadata: {name: hfcli, namespace: hftest}
spec:
  nodeName: $W2
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
---
apiVersion: v1
kind: Pod
metadata: {name: hfsame, namespace: hftest}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [sh, -c, "socat -T3 UDP4-LISTEN:5354,reuseaddr,fork EXEC:/bin/cat & exec python3 -m http.server 8080 --bind ::"]
      readinessProbe: {tcpSocket: {port: 8080}, periodSeconds: 2}
---
apiVersion: v1
kind: Pod
metadata: {name: hfnode2, namespace: hftest}
spec:
  nodeName: $W2
  hostNetwork: true
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
EOF
$K -n hftest wait --for=condition=Ready pod/hfsrv pod/hfcli pod/hfsame pod/hfnode2 --timeout=120s >/dev/null 2>&1
HFSAME=$($K -n hftest get pod hfsame -o jsonpath='{.status.podIP}')
docker run -d --rm --name hfext --network kind nicolaka/netshoot sleep 900 >/dev/null 2>&1
HFEXTIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' hfext)
docker exec -d hfext socat -T3 "UDP4-LISTEN:5354,reuseaddr,fork" "EXEC:/bin/cat" >/dev/null 2>&1
docker exec -d hfext python3 -m http.server 80 >/dev/null 2>&1

hf_ext_served() {
  for _ in $(seq 1 10); do
    docker exec hfext curl -s -m3 "http://$WIP4:18080/" >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}
hf_ext_refused() {
  for _ in $(seq 1 10); do
    docker exec hfext curl -s -m3 "http://$WIP4:18080/" >/dev/null 2>&1 || return 0
    sleep 2
  done
  return 1
}

hf_ext_served && pass "node service serves the external client before any HostFirewall" \
  || fail "node service unreachable before any HostFirewall"
HFNP=$($K -n default get svc lbclu -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
hfnp_pre=""
[ -n "$HFNP" ] && docker exec hfext curl -s -m3 "http://$WIP4:$HFNP/" >/dev/null 2>&1 && hfnp_pre=ok

$K label node "$W" cozyplane-e2e/hf=isolated --overwrite >/dev/null
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
EOF

hf_ext_refused && pass "isolated node refuses the external client (default-deny)" \
  || fail "isolated node still serves the external client"
np_refused hftest hfcli "http://$WIP4:18080/" && pass "cross-node pod->node refused (from_overlay gate)" \
  || fail "cross-node pod->node still served while isolated"
np_refused hftest hfsame "http://$WIP4:18080/" && pass "same-node pod->node refused (from_pod gate)" \
  || fail "same-node pod->node still served while isolated"
np_served hftest hfnode2 "http://$WIP4:18080/" && pass "node-sourced client exempt (apiserver/kubelet plumbing shape)" \
  || fail "node-sourced client gated (the exemption is broken)"
[ -n "$WIP6" ] && { np_refused hftest hfcli "http://[$WIP6]:18080/" \
  && pass "v6 node address equally isolated" || fail "v6 node address not gated"; }

# The cluster around the isolated node keeps working.
got=$($K -n hftest exec hfcli -- sh -c "echo overlaycheck | socat -T3 - UDP4:$HFSAME:5354" 2>/dev/null)
[ "$got" = "overlaycheck" ] && pass "cross-node pod->pod overlay unharmed while isolated" \
  || fail "overlay pod->pod broken while isolated (got '$got')"
ready=$($K get node "$W" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$ready" = "True" ] && pass "isolated node stays Ready (kubelet->apiserver exempt)" \
  || fail "isolated node went NotReady"
$K -n hftest get pod hfsrv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "hostNetwork pod on the isolated node stays Ready" \
  || fail "hostNetwork pod readiness broke under isolation"
docker exec hfext ping -c1 -W2 "$WIP4" >/dev/null 2>&1 \
  && pass "ICMP to the isolated node passes (never gated)" \
  || fail "ICMP to the isolated node dropped"
if [ "$hfnp_pre" = "ok" ]; then
  docker exec hfext curl -s -m3 "http://$WIP4:$HFNP/" >/dev/null 2>&1 \
    && pass "NodePort still served while isolated (LB interception is not host traffic)" \
    || fail "NodePort gated by the host firewall (it must be intercepted first)"
fi

# Node-originated UDP replies come back through all three pin write points.
dnsok=""
for _ in $(seq 1 10); do
  $K -n hftest exec hfsrv -- nslookup -timeout=3 kubernetes.default.svc.cluster.local >/dev/null 2>&1 && { dnsok=1; break; }
  sleep 2
done
[ -n "$dnsok" ] && pass "hostNetwork cluster DNS works while isolated (node->pod UDP pin)" \
  || fail "hostNetwork cluster DNS broken while isolated"
got=$($K -n hftest exec hfsrv -- sh -c "echo localpin | socat -T3 - UDP4:$HFSAME:5354" 2>/dev/null)
[ "$got" = "localpin" ] && pass "node->local-pod UDP reply admitted (to_pod pin)" \
  || fail "node->local-pod UDP reply dropped (got '$got')"
got=$($K -n hftest exec hfsrv -- sh -c "echo extpin | socat -T3 - UDP4:$HFEXTIP:5354" 2>/dev/null)
[ "$got" = "extpin" ] && pass "node->external UDP reply admitted (uplink pin)" \
  || fail "node->external UDP reply dropped (got '$got')"

# Rules union open: the external client by /32+port, pods by the pod CIDR.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
  ingress:
    - from: [{cidr: $HFEXTIP/32}]
      ports: [{protocol: TCP, port: 18080}]
EOF
hf_ext_served && pass "cidr+port rule admits the external client" \
  || fail "cidr+port rule did not open the node service"
np_refused hftest hfcli "http://$WIP4:18080/" && pass "pod clients still refused (allow scoped to the client /32)" \
  || fail "a /32 allow leaked to pod sources"
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e-pods}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
  ingress:
    - from: [{cidr: 10.244.0.0/16}]
      ports: [{protocol: TCP, port: 18080, endPort: 18083}]
EOF
np_served hftest hfcli "http://$WIP4:18080/" && pass "pod-CIDR rule (second object, endPort range) opens cross-node pod->node" \
  || fail "pod-CIDR rule did not open cross-node pod->node"
np_served hftest hfsame "http://$WIP4:18080/" && pass "pod-CIDR rule opens same-node pod->node" \
  || fail "pod-CIDR rule did not open same-node pod->node"

# except carves the external client back out of a wide allow.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
  ingress:
    - from: [{cidr: 0.0.0.0/0, except: [$HFEXTIP/32]}]
      ports: [{protocol: TCP, port: 18080}]
EOF
hf_ext_refused && pass "except masks the external client inside a wide allow" \
  || fail "except did not mask the external client"
np_served hftest hfcli "http://$WIP4:18080/" && pass "the wide allow still admits pod clients around the except" \
  || fail "the wide allow lost pod clients to the except"

$K delete hostfirewall hf-e2e hf-e2e-pods >/dev/null
hf_ext_served && pass "deleting the HostFirewalls reopens the node" \
  || fail "node still isolated after HostFirewall deletion"

# --- Host firewall EGRESS (host-firewall.md, increment 2) ---
# The node's OWN new flows go default-deny. node->node and node->local-pod stay
# exempt (kubelet<->apiserver, the agent's own API access, kubelet probes) —
# that is what makes egress isolation impossible to self-lock-out with.
phase "HostFirewall egress"
HFCLIIP=$($K -n hftest get pod hfcli -o jsonpath='{.status.podIP}')
HFSAMEIP=$($K -n hftest get pod hfsame -o jsonpath='{.status.podIP}')
np_served hftest hfsrv "http://$HFEXTIP/" && pass "node->external serves before egress isolation" \
  || fail "node->external unreachable before egress isolation"
np_served hftest hfsrv "http://$HFCLIIP:8080/" && pass "node->remote-pod serves before egress isolation" \
  || fail "node->remote-pod unreachable before egress isolation"

$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e-eg}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
  policyTypes: [Egress]
EOF
hf_ext_served && pass "an Egress-only object leaves INGRESS open" \
  || fail "an Egress-only object isolated ingress too"
np_refused hftest hfsrv "http://$HFEXTIP/" && pass "node->external refused (egress default-deny)" \
  || fail "node->external still served under egress isolation"
np_refused hftest hfsrv "http://$HFCLIIP:8080/" && pass "node->remote-pod refused (the from_pod encap gate)" \
  || fail "node->remote-pod still served under egress isolation"

# The cluster survives its own firewall: all three exemptions, live.
np_served hftest hfsrv "http://$HFSAMEIP:8080/" && pass "node->LOCAL-pod stays exempt under egress isolation" \
  || fail "egress isolation gated node->local-pod (kubelet probes are this flow)"
ready=$($K get node "$W" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$ready" = "True" ] && pass "node stays Ready under egress isolation (node->node exempt)" \
  || fail "egress isolation broke kubelet->apiserver (node went NotReady)"
$K -n hftest get pod hfsame -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "kubelet probes still pass on the egress-isolated node" \
  || fail "egress isolation broke kubelet probes to a local pod"
apod=$($K -n kube-system get pods -l app=cozyplane-agent --field-selector "spec.nodeName=$W" -o name 2>/dev/null | head -1)
[ -n "$apod" ] && $K -n kube-system get "$apod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "the agent on the egress-isolated node stays Ready (no self-lockout)" \
  || fail "egress isolation cut the agent off from the apiserver"

# Allow rules reopen, per destination and port.
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: hf-e2e-eg}
spec:
  nodeSelector: {matchLabels: {cozyplane-e2e/hf: isolated}}
  policyTypes: [Egress]
  egress:
    - to: [{cidr: $HFEXTIP/32}]
      ports: [{protocol: TCP, port: 80}]
EOF
np_served hftest hfsrv "http://$HFEXTIP/" && pass "egress cidr+port rule reopens node->external" \
  || fail "the egress allow rule did not reopen the destination"
np_refused hftest hfsrv "http://$HFCLIIP:8080/" && pass "the egress allow is scoped (remote pod still refused)" \
  || fail "an egress /32 allow leaked to other destinations"

$K delete hostfirewall hf-e2e-eg >/dev/null
np_served hftest hfsrv "http://$HFCLIIP:8080/" && pass "deleting the egress object reopens the node's own traffic" \
  || fail "node still egress-isolated after deletion"

$K label node "$W" cozyplane-e2e/hf- >/dev/null 2>&1
docker rm -f hfext >/dev/null 2>&1
$K delete ns hftest --wait=false >/dev/null 2>&1

phase "revocation"
$K -n team-a delete vpcbinding vpc-a >/dev/null
sleep 6
check_fail "a1 severed after its binding is revoked" bash -c "$K -n team-a exec a1 -- ping -c1 -W2 $A2 >/dev/null 2>&1"

echo
echo "e2e: ${PASSED} passed, $((CHECKS - PASSED)) failed, ${SKIPPED} skipped, in $(( $(date +%s) - START ))s"
if [ "$FAILED" = "0" ]; then echo "e2e: ALL PASSED"; else echo "e2e: FAILURES"; fi
exit $FAILED
