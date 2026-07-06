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

pass() { echo "  PASS: $*"; }
fail() { echo "  FAIL: $*"; FAILED=1; }

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

echo "[default network]"
CD=$($K -n kube-system get pods -l k8s-app=kube-dns -o jsonpath='{.items[0].status.podIP}')
check_ok "cli -> coredns (default overlay)" $K exec cli -- ping -c2 -W2 "$CD"
# A mis-masked fe80::1/0 on a host veth makes the kernel install
# `default dev cphX` (metric 256), outranking the host's RA default and
# hijacking node v6 egress. Guard: no node routes v6 default via a pod veth.
for n in $(kind get nodes --name "$CLUSTER" 2>/dev/null); do
  check_fail "no v6 default route via a cozyplane veth on $n" \
    bash -c "docker exec $n ip -6 route show default | grep -qE 'dev (cph|cpg)'"
done

echo "[default-deny attachment]"
check_fail "pod without a VPCBinding never becomes Ready" \
  $K -n team-x wait --for=condition=Ready pod/nobind --timeout=20s

echo "[overlapping CIDRs: the same VPC IP resolves within each VPC]"
# IPAM order isn't fixed, so resolve a2's real IP and prove that same numeric
# address is also assigned in vpc-b to a *different* pod. Delivery from each VPC
# must reach that VPC's pod (net-scoped), never cross the CIDR collision.
A2=$(vpcip a2)
check "a1 -> $A2 reaches a2 (vpc-a)" "a2" httpid team-a a1 "$A2"
BPEER=""; for p in bw1 bw2; do [ "$(vpcip "$p")" = "$A2" ] && BPEER=$p; done
BSRC=$([ "$BPEER" = bw1 ] && echo bw2 || echo bw1)
check "$BSRC -> $A2 reaches $BPEER (vpc-b), not a2" "$BPEER" httpid team-b "$BSRC" "$A2"

echo "[north-south bridge to same-node same-IP pods]"
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

echo "[isolation]"
check_fail "cli(default) -> VPC IP 10.0.0.2 directly" bash -c "$K exec cli -- wget -qO- -T3 http://10.0.0.2/ 2>/dev/null | grep -q ."

echo "[peering: disjoint peers, overlapping cannot]"
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

echo "[IPv6 VPC overlay: intra-VPC cross-node, isolation, peering]"
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

echo "[IPv6 north-south: default client -> v6 fabric IP]"
# v6a1's fabric IP is a v6 address from the node's v6 pod CIDR; a default-network
# client (dual-stack cli) reaches it, and to_pod's bridge_forward6 DNATs
# fabric->VPC while masquerading the client to fe80::1 (reversed in from_pod).
V6AFAB=$(fabric v6a1)
check "cli(default) -> v6a1 v6 fabric ($V6AFAB) (north-south TCP)" "v6a1" httpid default cli "[$V6AFAB]"
check_ok "cli(default) -> v6a1 v6 fabric ping (north-south ICMPv6)" \
  $K exec cli -- ping -c2 -W3 "$V6AFAB"

echo "[egress via per-VPC gateway]"
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

echo "[bpf cluster-egress masquerade (#10): netfilter does no NAT]"
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
MKNET=$(docker network inspect kind -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
MKGW="$(echo "${MKNET:-172.18.0.0/16}" | cut -d. -f1-2).0.1"
check "cli traceroute hop2 = docker gw $MKGW (masq ICMP-error un-SNAT)" "ok" \
  bash -c "$K exec cli -- traceroute -q1 -w3 -m2 1.1.1.1 2>/dev/null | grep -q \"($MKGW)\" && echo ok"
# The v6 twin: a default pod's off-cluster v6 egress rides masq_snat6 to the
# node's v6 address (pod ULAs are unroutable outside), and the reply
# un-SNATs through masq_reverse6. Same external container as the gateway test.
check_ok "cli -> external v6 $EGW6 ping (bpf masq6, ICMPv6 echo)" \
  $K exec cli -- ping -6 -c2 -W3 "$EGW6"

echo "[stale gateway .1 claim: abandoned-port GC unwedges the replacement]"
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

echo "[v6 floating IP: NDP advertisement, stateless DNAT, EIP egress]"
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

echo "[ICMP errors through the bridge (#3): traceroute correlates embedded headers]"
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

echo "[VPC DNS: split-horizon resolver (services-in-vpc.md, increment 1)]"
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

echo "[ServiceVIP: ClusterIP-equivalent inside a VPC (services-in-vpc.md, increment 2)]"
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

echo "[guest autoconfiguration (#8): RA (M=1) + DHCPv6 hand out the pinned /128]"
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

echo "[stale locals pruning: a dead veth's entry must not shadow a reallocated IP]"
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

echo "[floating IP: external ingress, source-preserving]"
# Bind a public IP to a1's VPC IP; an off-cluster client (a container on the
# kind L2, off the overlay) must reach a1 through it. Exercises from_uplink ->
# to_pod floating DNAT -> pod, the source-preserving reply, and ARP advertisement
# from a1's node. The public IP is drawn from the kind subnet's high /24 (kind's
# DHCP allocates low), so the client resolves it by ARP on the shared bridge.
KNET=$(docker network inspect kind -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
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

echo "[map recreation: agent restart heals existing pods (no reboot)]"
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

echo "[revocation]"
$K -n team-a delete vpcbinding vpc-a >/dev/null
sleep 6
check_fail "a1 severed after its binding is revoked" bash -c "$K -n team-a exec a1 -- ping -c1 -W2 $A2 >/dev/null 2>&1"

echo
if [ "$FAILED" = "0" ]; then echo "e2e: ALL PASSED"; else echo "e2e: FAILURES"; fi
exit $FAILED
