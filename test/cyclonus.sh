#!/usr/bin/env bash
# Cyclonus conformance sweep for the default-net NetworkPolicy implementation
# (docs/network-policy.md, increment 3). Creates a kind cluster, installs
# cozyplane, and runs the cyclonus generated suite against it.
#
# Included beyond cyclonus's defaults: end-port (we serve ranges via the
# np_allow port-suffix LPM). Excluded, with reasons:
#   sctp        — protocol not gated (TCP/UDP only; ICMP deliberately open)
#   named-port  — not served: identities are label-sets, there is no pod spec
#                 to resolve a named port against (documented, warned)
#   multi-peer, upstream-e2e, example, namespaces-by-default-label — the
#                 cyclonus defaults (suite-size control), kept
#
#   CLUSTER=... KEEP=1 test/cyclonus.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${CLUSTER:-czp-cyclonus}"
KCTX="kind-${CLUSTER}"
K="kubectl --context ${KCTX}"
IMAGE="${IMAGE:-ghcr.io/lllamnyp/cozyplane:e2e}"
CYCLONUS="${CYCLONUS:-$HOME/go/bin/cyclonus}"

cleanup() {
  [ "${KEEP:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
}
trap cleanup EXIT

if [ -z "${IMAGE_PREBUILT:-}" ]; then
  echo "== building image =="
  docker build -t "$IMAGE" "$ROOT" >/dev/null || exit 1
fi
echo "== creating kind cluster =="
kind create cluster --name "$CLUSTER" --config "$ROOT/test/kind.yaml" >/dev/null || exit 1
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null || exit 1

echo "== installing cozyplane =="
$K apply -f "$ROOT/config/crd/" >/dev/null
for f in agent controller authz; do
  sed "s#ghcr.io/lllamnyp/cozyplane:dev#${IMAGE}#g" "$ROOT/deploy/$f.yaml" | $K apply -f - >/dev/null
done
$K -n kube-system rollout status ds/cozyplane-agent --timeout=180s || exit 1
$K -n kube-system rollout status deploy/cozyplane-controller --timeout=120s || exit 1

echo "== running cyclonus =="
"$CYCLONUS" generate \
  --context "$KCTX" \
  --ignore-loopback \
  --cleanup-namespaces \
  --exclude sctp,named-port,multi-peer,upstream-e2e,example,namespaces-by-default-label
