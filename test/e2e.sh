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

cleanup() { [ "${KEEP:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1; }

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
$K run cli --image=busybox:1.36 --restart=Never --command -- sleep 3600 >/dev/null 2>&1
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
$K apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: ExternalPool
metadata: {name: e2e-pub}
spec: {cidrs: ["${KPFX}.240.0/24"], advertisement: L2}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: FloatingIP
metadata: {name: a1-fip, namespace: team-a}
spec: {vpcRef: {name: vpc-a}, target: "$A1IP", address: "$FIP"}
EOF
$K -n team-a wait --for=jsonpath='{.status.phase}'=Ready floatingip/a1-fip --timeout=30s >/dev/null 2>&1
check "a1-fip Ready with $FIP" "Ready" $K -n team-a get floatingip a1-fip -o jsonpath='{.status.phase}'
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

echo "[map recreation: agent restart heals existing pods (no reboot)]"
# Simulate the effect of a map-ABI upgrade: remove the CNI-written pinned maps
# (exactly what reconcilePins does to incompatible pins — the load then creates
# them fresh and empty) on every node, and roll the agents. The restarted agents
# must rebuild ports/locals/bridges from the veth alias records and re-attach
# the classifiers, so the EXISTING pods — not recreated — keep full
# connectivity, isolation included (issue #7).
for n in $(kind get nodes --name "$CLUSTER" 2>/dev/null); do
  docker exec "$n" sh -c 'rm -f /sys/fs/bpf/cozyplane/locals /sys/fs/bpf/cozyplane/bridges /sys/fs/bpf/cozyplane/ports'
done
$K -n kube-system rollout restart ds/cozyplane-agent >/dev/null
$K -n kube-system rollout status ds/cozyplane-agent --timeout=180s >/dev/null 2>&1
sleep 5
check "a1 -> a2 after map recreation (VPC cross-node, rebuilt locals)" "a2" httpid team-a a1 "$A2"
check "$BSRC -> $A2 still reaches $BPEER (net scoping survived the ports rebuild)" "$BPEER" httpid team-b "$BSRC" "$A2"
check "cli -> a1.fabric after map recreation (rebuilt bridges)" "a1" bash -c "$K exec cli -- wget -qO- -T4 http://$(fabric a1)/ 2>/dev/null"
check "v6a1 -> v6a2 after map recreation (v6 VPC, 128-bit rebuild)" "v6a2" httpid team-a v6a1 "[$V6A2]"
check_ok "cli -> coredns after map recreation (default network)" $K exec cli -- ping -c2 -W2 "$CD"
check_fail "cli(default) -> VPC IP still blocked after map recreation" \
  bash -c "$K exec cli -- wget -qO- -T3 http://10.0.0.2/ 2>/dev/null | grep -q ."

echo "[revocation]"
$K -n team-a delete vpcbinding vpc-a >/dev/null
sleep 6
check_fail "a1 severed after its binding is revoked" bash -c "$K -n team-a exec a1 -- ping -c1 -W2 $A2 >/dev/null 2>&1"

echo
if [ "$FAILED" = "0" ]; then echo "e2e: ALL PASSED"; else echo "e2e: FAILURES"; fi
exit $FAILED
