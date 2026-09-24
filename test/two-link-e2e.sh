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
# Usage:
#   test/two-link-e2e.sh            # build image, create cluster, run, tear down
#   IMAGE=... test/two-link-e2e.sh  # use a prebuilt image
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

pass() { CHECKS=$((CHECKS+1)); echo "  [${CHECKS}] PASS: $*"; }
fail() { CHECKS=$((CHECKS+1)); FAILED=1; echo "  [${CHECKS}] FAIL: $*"; }
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

NODE="${CLUSTER}-control-plane"

if [ "${REUSE:-0}" != "1" ]; then
  phase "cluster with a second link on ${NODE}"
  [ -n "${IMAGE_PREBUILT:-}" ] || docker build -q -t "$IMAGE" "$ROOT" >/dev/null
  kind create cluster --name "$CLUSTER" --config "$ROOT/test/kind.yaml" >/dev/null 2>&1 ||
    kind create cluster --name "$CLUSTER" >/dev/null
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
check "agent Ready (the verifier accepted the datapath)" "1" \
  bash -c "$K get ds/cozyplane-agent -n cozy-cozyplane -o jsonpath='{.status.numberReady}'"

SEC_IF=$(docker exec "$NODE" sh -c "ip -o link show | grep -c ':'" >/dev/null 2>&1; docker exec "$NODE" sh -c "ip -o -4 addr show | awk '\$4 ~ /^${XNET%%.*}\./ {print \$2}'" | head -1)
SEC_IDX=$(docker exec "$NODE" sh -c "cat /sys/class/net/${SEC_IF}/ifindex" | tr -d '[:space:]')
DEF_IF=$(docker exec "$NODE" sh -c "ip -o route show default | awk '{print \$5}'" | head -1)
DEF_IDX=$(docker exec "$NODE" sh -c "cat /sys/class/net/${DEF_IF}/ifindex" | tr -d '[:space:]')
echo "  default uplink ${DEF_IF} (ifindex ${DEF_IDX}); second link ${SEC_IF} (ifindex ${SEC_IDX})"

XSEC="$(echo "${XNET%/*}" | cut -d. -f1-3).50"             # an address on the SECOND link
DEF_IP=$(docker exec "$NODE" sh -c "ip -o -4 addr show ${DEF_IF} | awk '{print \$4}'" | head -1 | cut -d/ -f1)
XDEF="$(echo "$DEF_IP" | cut -d. -f1-3).241"               # an address on the DEFAULT uplink

if [ "${REUSE:-0}" != "1" ]; then
  $K create deployment web --image=registry.k8s.io/e2e-test-images/agnhost:2.47 -- \
    /agnhost netexec --http-port=8080 >/dev/null
  $K expose deployment web --port=80 --target-port=8080 --name=web >/dev/null
  # Publishing the SECOND link's address is what makes the agent bind that link,
  # which is what used to capture the node-wide cell.
  $K patch svc web --type=merge -p "{\"spec\":{\"externalIPs\":[\"${XSEC}\"]}}" >/dev/null
  for _ in $(seq 1 40); do
    [ "$($K get deploy web -o jsonpath='{.status.readyReplicas}' 2>/dev/null)" = "1" ] && break
    sleep 5
  done
fi
# Idempotent, and needed on a reused cluster too: publishing an address the node
# does not carry measures nothing.
docker exec "$NODE" ip addr add "${XSEC}/24" dev "$SEC_IF" 2>/dev/null
docker exec "$NODE" ip addr add "${XDEF}/16" dev "$DEF_IF" 2>/dev/null
BE=$($K get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
[ -n "$BE" ] || { echo "  no backend pod IP; aborting"; exit 1; }

phase "ext_links: one entry per link, keyed by the address"
DUMP=$(docker exec "$NODE" sh -c '[ -x /bpftool ] || exit 1; /bpftool map dump pinned /sys/fs/bpf/cozyplane/ext_links' 2>/dev/null)
if [ -z "$DUMP" ]; then
  B=/tmp/cozyplane-e2e-bpftool
  [ -x "$B" ] || curl -sL https://github.com/libbpf/bpftool/releases/download/v7.5.0/bpftool-v7.5.0-amd64.tar.gz |
    tar xz -C /tmp bpftool && mv /tmp/bpftool "$B" && chmod +x "$B"
  docker cp "$B" "$NODE:/bpftool" >/dev/null
  DUMP=$(docker exec "$NODE" /bpftool map dump pinned /sys/fs/bpf/cozyplane/ext_links 2>/dev/null)
fi
# The address's own key must name the SECOND link, not the default uplink. A
# routed pool sits outside the link's subnet, so the subnet key alone misses.
SECHEX=$(echo "$XSEC" | awk -F. '{printf "%d,%d,%d,%d", $1,$2,$3,$4}')
check "the second link's address maps to its own link (ifindex ${SEC_IDX})" "yes" \
  bash -c "echo '$DUMP' | tr -d ' \n' | grep -q '${SECHEX}\]}},\"value\":{\"ifindex\":${SEC_IDX}' && echo yes || echo no"

phase "both links serve, at once"
nat64hex() { local a b c d; IFS=. read -r a b c d <<<"$1"
  printf '00 64 ff 9b 00 00 00 00 00 00 00 00 %02x %02x %02x %02x' "$a" "$b" "$c" "$d"; }
row() { # <vip> : svc_vips {net 0, vip, TCP, :80} -> the backend on :8080
  local k="00 00 00 00 $(nat64hex "$1") 06 00 00 50"
  local v="01 00 00 00 00 00 00 00 $(nat64hex "$BE") 1f 90 00 00 $(printf '00 %.0s' $(seq 1 300))"
  docker exec "$NODE" /bpftool map update pinned /sys/fs/bpf/cozyplane/svc_vips key hex $k value hex $v any
}
row "$XSEC" && row "$XDEF"

# The decisive pair. The node-wide cell now names the SECOND link, so under the
# old selection the DEFAULT uplink's address is the one whose reply leaves the
# wrong link — it times out rather than being refused.
check "address on the second link is served (client on ${XBR})" "web" \
  bash -c "docker run --rm --network $XBR alpine:3.20 wget -qO- -T6 http://$XSEC/hostname 2>/dev/null | cut -c1-3"
check "address on the default uplink is served (client on kind)" "web" \
  bash -c "docker run --rm --network kind alpine:3.20 wget -qO- -T6 http://$XDEF/hostname 2>/dev/null | cut -c1-3"

echo
echo "two-link e2e: $((CHECKS - FAILED)) of ${CHECKS} checks passed"
[ "$FAILED" = "0" ] && echo "two-link e2e: ALL PASSED" || echo "two-link e2e: FAILURES"
exit $FAILED
