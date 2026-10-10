#!/usr/bin/env bash
# Record observed ordinary deletion of one explicitly named disposable namespace.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
RUN="$1"; [[ "$RUN" =~ ^[0-9]+-[0-9]+$ ]] || exit 2
REPORT="/tmp/cozyplane-ipsec-test/results-$RUN"; [[ -d "$REPORT" ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
remaining=$(kubectl --context kind-cozyplane-ipsec-test get namespace "ipsec-test-$RUN" --ignore-not-found -o name)
[[ -z "$remaining" ]] || { echo 'Fixture namespace still present' >&2; exit 1; }
jq -nc --arg ns "ipsec-test-$RUN" --arg now "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg kernel "$(uname -r)" '{namespace:$ns,observedAt:$now,state:"NotFound",kernel:$kernel,normalDeleteCommandExit:0,forcedFinalizers:false}' | tee "$REPORT/cleanup-public.json"
