#!/usr/bin/env bash
# Cyclonus conformance sweep for the default-net NetworkPolicy implementation
# (docs/network-policy.md, increment 3).
#
# Two ways to run:
#   - default: create a kind cluster, install cozyplane, sweep against it.
#   - REUSE=1 with KCTX/KUBECONFIG: sweep an existing cozyplane cluster. A full
#     sweep is hundreds of policies x a 9x9 probe matrix, so it wants a real
#     cluster's headroom.
#
# Probe scope (the two knobs that make the signal meaningful):
#   --server-protocol TCP,UDP  — SCTP is a documented non-goal (we gate only
#       TCP/UDP; ICMP is deliberately open). Probing SCTP flags every cell
#       touching an isolated pod as "wrong" — noise, not a defect. Drop it
#       from the servers so the truth table reflects what we actually enforce.
#   --destination-type pod-ip  — cyclonus hardcodes .svc.cluster.local; on a
#       cluster whose domain differs, every service-name probe NXDOMAINs.
#       Probe pod IPs directly.
# Excluded test tags (with reasons):
#   named-port  — not served: identities are label-sets, there is no pod spec
#                 to resolve a named port against (documented, warned).
#   sctp        — the SCTP-specific generated cases (redundant once SCTP is
#                 out of the server protocols).
#   multi-peer, upstream-e2e, example, namespaces-by-default-label — the
#                 cyclonus defaults (suite-size control), kept.
# end-port is NOT excluded: we serve ranges via the np_allow port-suffix LPM.
#
#   CLUSTER=... KEEP=1 test/cyclonus.sh                 # kind
#   REUSE=1 KCTX=... KUBECONFIG=... test/cyclonus.sh    # existing cluster
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${CLUSTER:-czp-cyclonus}"
KCTX="${KCTX:-kind-${CLUSTER}}"
K="kubectl --context ${KCTX}"
IMAGE="${IMAGE:-ghcr.io/lllamnyp/cozyplane:e2e}"
CYCLONUS="${CYCLONUS:-$HOME/go/bin/cyclonus}"

cleanup() {
  [ "${REUSE:-0}" = "1" ] && return
  [ "${KEEP:-0}" = "1" ] || kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
}
trap cleanup EXIT

if [ "${REUSE:-0}" != "1" ]; then
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
fi

echo "== running cyclonus =="
"$CYCLONUS" generate \
  --context "$KCTX" \
  --ignore-loopback \
  --cleanup-namespaces \
  --destination-type "${DEST_TYPE:-pod-ip}" \
  --server-protocol "${SERVER_PROTO:-TCP,UDP}" \
  --exclude sctp,named-port,multi-peer,upstream-e2e,example,namespaces-by-default-label
