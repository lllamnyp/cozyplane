#!/usr/bin/env bash
# Read-only observations from the isolated cluster, without credential logs.
set -euo pipefail
[[ "${HOSTNAME:-}" == ipsec-guest ]] || exit 2
REPORT="$1"
[[ "$REPORT" =~ ^/tmp/cozyplane-ipsec-test/results-[0-9]+-[0-9]+$ ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
K=(kubectl --context kind-cozyplane-ipsec-test)
"${K[@]}" -n kube-system get pods -o json > "$REPORT/control-plane-pods.json"
"${K[@]}" get events -A -o json > "$REPORT/control-plane-events.json"
jq -c '.items[]|select(.metadata.name|test("cozyplane-controller|kube-controller-manager|kube-scheduler"))|{name:.metadata.name,statuses:[.status.containerStatuses[]|{restartCount,ready,state,lastState}]}' "$REPORT/control-plane-pods.json"
for pod in $(jq -r '.items[].metadata.name|select(test("cozyplane-controller|kube-controller-manager|kube-scheduler"))' "$REPORT/control-plane-pods.json"); do
  "${K[@]}" -n kube-system logs "$pod" --previous 2>/dev/null | python3 -c 'import re,sys; [print(re.sub(r"(?i)\b((?:psk|password|secret|token|key)\s*[:=]\s*)\S+",r"\1[REDACTED]",line.rstrip())) for line in sys.stdin if re.search(r"(?i)leader|lease|OOM|fatal|panic|deadline|timeout|killed",line)]' > "$REPORT/$pod-previous-filtered.log" || true
done
