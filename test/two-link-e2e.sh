#!/usr/bin/env bash
#
# Two external links on one node: the egress link must be a property of the
# address, not of the node.
#
# A node can carry external addresses on two links at once — an announced pool on
# a secondary NIC, plus the node's own addresses on the default uplink. The
# datapath used to hold ONE node-wide answer for "which link do external replies
# leave by" (CFG_FLOAT_IFINDEX), so whichever link won that cell, traffic for the
# other link's addresses left the wrong segment with a source that segment cannot
# source. The fabric drops it, so the client HANGS rather than being refused —
# which is why it reads as "never intercepted" and sends you to the wrong half of
# the datapath. Measured in the field before it was understood.
#
# test/kind.yaml nodes are docker containers, so a second link is a docker
# network away; this needs no cloud.
#
# What each check covers. The two HTTP checks discriminate for the ARRIVAL-LINK
# selection: once a flow records the interface it arrived on, the reply follows
# that and never consults ext_links. The map-content checks are what cover the
# per-address ext_links selection — including two addresses on one link, which
# the write path got wrong twice.
#
# Usage:
#   test/two-link-e2e.sh            # build image, create cluster, run, tear down
#   IMAGE=... test/two-link-e2e.sh  # use a prebuilt image
#
# Single-node on purpose: lb_ingress delivers to a NODE-LOCAL backend, so the
# link, the backend and the arrival interface all have to be the same node.
#   REUSE=1  test/two-link-e2e.sh   # use the current cluster/install as-is
#   KEEP=1   test/two-link-e2e.sh   # leave the cluster up
set -uo pipefail

CLUSTER="${CLUSTER:-cozyplane-2link}"
IMAGE="${IMAGE:-cozyplane:2link}"
KCTX="${KCTX:-kind-${CLUSTER}}"
K="kubectl --context ${KCTX}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XNET="${XNET:-10.90.0.0/24}"
XBR="${XBR:-${CLUSTER}-xlink}"
FAILED=0
CHECKS=0
FAILS=0

pass() { CHECKS=$((CHECKS+1)); echo "  [${CHECKS}] PASS: $*"; }
fail() { CHECKS=$((CHECKS+1)); FAILS=$((FAILS+1)); FAILED=1; echo "  [${CHECKS}] FAIL: $*"; }
check() { local d="$1" want="$2"; shift 2
  local got; got="$("$@" 2>/dev/null | tr -d '[:space:]')"
  [ "$got" = "$want" ] && pass "$d" || fail "$d (want '$want', got '$got')"; }
phase() { echo; echo "== $* =="; }

cleanup() {
  [ "${KEEP:-0}" = "1" ] && { echo "KEEP=1: ${CLUSTER} left up"; return; }
  [ "${REUSE:-0}" = "1" ] && return
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  docker network rm "$XBR" >/dev/null 2>&1
}
trap cleanup EXIT

# A worker when the cluster has one: lb_ingress delivers node-locally, so the
# second link and the backend have to sit on the same node, and a worker takes a
# pod without needing a control-plane toleration. Resolved only once the cluster
# exists — see resolve_node.
NODE="${CLUSTER}-control-plane"

if [ "${REUSE:-0}" != "1" ]; then
  phase "cluster with a second link"
  [ -n "${IMAGE_PREBUILT:-}" ] || docker build -q -t "$IMAGE" "$ROOT" >/dev/null
  CFG=$(mktemp); cat > "$CFG" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  ipFamily: dual
  podSubnet: "10.244.0.0/16,fd00:10:244::/56"
  serviceSubnet: "10.96.0.0/16,fd00:10:96::/112"
nodes:
  - role: control-plane
YAML
  kind create cluster --name "$CLUSTER" --config "$CFG" >/dev/null
  rm -f "$CFG"
  kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null
  docker network create --subnet "$XNET" "$XBR" >/dev/null 2>&1
  docker network connect "$XBR" "$NODE" >/dev/null
  helm install cozyplane "$ROOT/chart/cozyplane" -n cozy-cozyplane --create-namespace \
    --set image="$IMAGE" --set imagePullPolicy=Never --kube-context "$KCTX" >/dev/null
fi

# Wait for the agent, then for a backend to serve.
for _ in $(seq 1 40); do
  [ "$($K get ds -n cozy-cozyplane -o jsonpath='{.items[0].status.numberReady}' 2>/dev/null)" -ge 1 ] 2>/dev/null && break
  sleep 5
done
check "agent Ready on every node (the verifier accepted the datapath)" "yes" \
  bash -c "r=\$($K get ds/cozyplane-agent -n cozy-cozyplane -o jsonpath='{.status.numberReady}'); d=\$($K get ds/cozyplane-agent -n cozy-cozyplane -o jsonpath='{.status.desiredNumberScheduled}'); [ -n \"\$r\" ] && [ \"\$r\" = \"\$d\" ] && echo yes || echo no"

SEC_IF=$(docker exec "$NODE" sh -c "ip -o -4 addr show | awk '\$4 ~ /^${XNET%%.*}\./ {print \$2}'" | head -1)
[ -n "$SEC_IF" ] || { echo "  no interface on ${XNET}: the second network did not attach"; exit 1; }
SEC_IDX=$(docker exec "$NODE" sh -c "cat /sys/class/net/${SEC_IF}/ifindex" | tr -d '[:space:]')
DEF_IF=$(docker exec "$NODE" sh -c "ip -o route show default | awk '{print \$5}'" | head -1)
DEF_IDX=$(docker exec "$NODE" sh -c "cat /sys/class/net/${DEF_IF}/ifindex" | tr -d '[:space:]')
echo "  default uplink ${DEF_IF} (ifindex ${DEF_IDX}); second link ${SEC_IF} (ifindex ${SEC_IDX})"

XSEC="$(echo "${XNET%/*}" | cut -d. -f1-3).50"             # an address on the SECOND link
XSEC2="$(echo "${XNET%/*}" | cut -d. -f1-3).51"            # a second one, same link
DEF_IP=$(docker exec "$NODE" sh -c "ip -o -4 addr show ${DEF_IF} | awk '{print \$4}'" | head -1 | cut -d/ -f1)
XDEF="$(echo "$DEF_IP" | cut -d. -f1-3).241"               # an address on the DEFAULT uplink

if [ "${REUSE:-0}" != "1" ]; then
  $K create deployment web --image=registry.k8s.io/e2e-test-images/agnhost:2.47 -- \
    /agnhost netexec --http-port=8080 >/dev/null
  $K expose deployment web --port=80 --target-port=8080 --name=web >/dev/null
  # Publishing the SECOND link's address is what makes the agent bind that link,
  # which is what used to capture the node-wide cell.
  # Two addresses on the SAME link: the second is what a per-node write path
  # drops, because it produces an identical binding to the first.
  $K patch svc web --type=merge -p "{\"spec\":{\"externalIPs\":[\"${XSEC}\",\"${XSEC2}\"]}}" >/dev/null
  # Wait for the rollout to settle: the nodeSelector patch replaces the pod, and
  # the old one lingers Terminating with no address.
  $K rollout status deploy/web --timeout=300s >/dev/null 2>&1
fi
# Idempotent, and needed on a reused cluster too: publishing an address the node
# does not carry measures nothing.
docker exec "$NODE" ip addr add "${XSEC}/24" dev "$SEC_IF" 2>/dev/null
docker exec "$NODE" ip addr add "${XSEC2}/24" dev "$SEC_IF" 2>/dev/null
docker exec "$NODE" ip addr add "${XDEF}/16" dev "$DEF_IF" 2>/dev/null
BE=$($K get pod -l app=web --field-selector=status.phase=Running \
  -o jsonpath='{.items[0].status.podIP}' 2>/dev/null)
if [ -z "$BE" ]; then
  echo "  no backend pod IP on ${NODE}; aborting"
  $K get pod -l app=web -o wide 2>&1 | tail -2
  exit 1
fi

phase "ext_links: one entry per link, keyed by the address"
DUMP=$(docker exec "$NODE" sh -c '[ -x /bpftool ] || exit 1; /bpftool map dump pinned /sys/fs/bpf/cozyplane/ext_links' 2>/dev/null)
if [ -z "$DUMP" ]; then
  B=/tmp/cozyplane-e2e-bpftool
  if [ ! -x "$B" ]; then
    curl -sL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz |
      tar xz -C /tmp bpftool || { echo "  cannot fetch bpftool; aborting"; exit 1; }
    mv /tmp/bpftool "$B" && chmod +x "$B"
  fi
  [ -x "$B" ] || { echo "  no bpftool; aborting rather than reporting a datapath fault"; exit 1; }
  docker cp "$B" "$NODE:/bpftool" >/dev/null
  DUMP=$(docker exec "$NODE" /bpftool map dump pinned /sys/fs/bpf/cozyplane/ext_links 2>/dev/null)
fi
# The address's own key must name the SECOND link, not the default uplink. A
# routed pool sits outside the link's subnet, so the subnet key alone misses.
hostkey() { echo "$1" | awk -F. '{printf "%d,%d,%d,%d", $1,$2,$3,$4}'; }
has_entry() { # <vip> : a host key for this address naming the second link
  echo "$DUMP" | tr -d ' \n' | grep -q "$(hostkey "$1")\]}},\"value\":{\"ifindex\":${SEC_IDX}" && echo yes || echo no
}
check "the second link's address maps to its own link (ifindex ${SEC_IDX})" "yes" \
  bash -c "$(declare -f hostkey has_entry); DUMP='$DUMP'; SEC_IDX=$SEC_IDX; has_entry $XSEC"
# The one a per-node write path drops: same link, same gateway, so the binding it
# compares against is byte-identical to the first address's.
check "a SECOND address on that link also maps to it" "yes" \
  bash -c "$(declare -f hostkey has_entry); DUMP='$DUMP'; SEC_IDX=$SEC_IDX; has_entry $XSEC2"

phase "both links serve, at once"
nat64hex() { local a b c d; IFS=. read -r a b c d <<<"$1"
  printf '00 64 ff 9b 00 00 00 00 00 00 00 00 %02x %02x %02x %02x' "$a" "$b" "$c" "$d"; }
# row <vip>: write the svc_vips entry kpr would write, so this script can exercise
# the datapath without standing up kpr. Layouts from bpf/overlay.c:
#   svc_key { net u32 | vip addr128 (NAT64) | proto u8 | pad u8 | port be16 }
#   svc_val { n u32 | flags u32 | be[16] { ip addr128 | port be16 | pad u16 } }
# so the value is n=1, flags=0, one backend, then 300 bytes of empty slots.
row() {
  local k="00 00 00 00 $(nat64hex "$1") 06 00 00 50"
  local v="01 00 00 00 00 00 00 00 $(nat64hex "$BE") 1f 90 00 00 $(printf '00 %.0s' $(seq 1 300))"
  docker exec "$NODE" /bpftool map update pinned /sys/fs/bpf/cozyplane/svc_vips key hex $k value hex $v any
}
row "$XSEC" || { echo "  could not write the svc_vips row for $XSEC"; exit 1; }
row "$XDEF" || { echo "  could not write the svc_vips row for $XDEF"; exit 1; }

# The decisive pair. The node-wide cell now names the SECOND link, so under the
# old selection the DEFAULT uplink's address is the one whose reply leaves the
# wrong link — it times out rather than being refused.
check "address on the second link is served (client on ${XBR})" "web" \
  bash -c "docker run --rm --network $XBR alpine:3.20 wget -qO- -T6 http://$XSEC/hostname 2>/dev/null | cut -c1-3"
check "address on the default uplink is served (client on kind)" "web" \
  bash -c "docker run --rm --network kind alpine:3.20 wget -qO- -T6 http://$XDEF/hostname 2>/dev/null | cut -c1-3"

phase "the cluster-egress masquerade follows the egress link"
# A pod's packet to a host on either link leaves masqueraded to that link's own address.
SEC_IP=$(docker exec "$NODE" sh -c "ip -o -4 addr show ${SEC_IF} | awk '{print \$4}'" | head -1 | cut -d/ -f1)
for net in "$XBR" kind; do
  docker rm -f "${CLUSTER}-tgt-$net" >/dev/null 2>&1
  docker run -d --rm --name "${CLUSTER}-tgt-$net" --network "$net" registry.k8s.io/e2e-test-images/agnhost:2.47 \
    netexec --http-port=8080 >/dev/null
done
trap 'docker rm -f "${CLUSTER}-tgt-$XBR" "${CLUSTER}-tgt-kind" >/dev/null 2>&1; cleanup' EXIT
tgtip() { docker inspect -f "{{(index .NetworkSettings.Networks \"$1\").IPAddress}}" "${CLUSTER}-tgt-$1"; }
TSEC=$(tgtip "$XBR"); TDEF=$(tgtip kind)
$K run masqcli --image=busybox:1.36 --restart=Never -- sleep 3600 >/dev/null 2>&1
$K wait --for=condition=Ready pod/masqcli --timeout=120s >/dev/null
clientip() { $K exec masqcli -- wget -qO- -T6 "http://$1:8080/clientip" 2>/dev/null | cut -d: -f1; }
check "a pod reaches a host on the second link, sourced from ${SEC_IF}'s address" "$SEC_IP" clientip "$TSEC"
check "a pod reaches a host on the default uplink, sourced from ${DEF_IF}'s address" "$DEF_IP" clientip "$TDEF"

echo
echo "two-link e2e: $((CHECKS - FAILS)) of ${CHECKS} checks passed"
[ "$FAILED" = "0" ] && echo "two-link e2e: ALL PASSED" || echo "two-link e2e: FAILURES"
exit $FAILED
