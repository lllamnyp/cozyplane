#!/usr/bin/env bash
# Read only an already-running, fixed-name local product fixture.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
REPORT="$1"; PHASE="$2"
[[ "$REPORT" =~ ^/tmp/cozyplane-ipsec-test/results-[0-9]+-[0-9]+$ && "$PHASE" =~ ^[a-z0-9-]+$ ]] || exit 2
RUN_ID="${REPORT##*/results-}"; NS="ipsec-test-$RUN_ID"
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
K=(kubectl --context kind-cozyplane-ipsec-test)
client_exec() { local index="$1"; shift; docker exec "cozyplane-ipsec-peer-$RUN_ID-$index" "$@"; }
selected_pod() {
  local port; port=$("${K[@]}" -n "$NS" get vpngateway gateway -o jsonpath='{.status.appliancePort}')
  "${K[@]}" get port "$port" -o jsonpath='{.spec.podName}'
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=test/ipsec-packet-counters.sh
source "$ROOT/test/ipsec-packet-counters.sh"
packet_counters "$PHASE"
