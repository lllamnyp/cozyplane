#!/usr/bin/env bash
# Metadata-only cleanup evidence for one explicitly named disposable fixture.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
RUN="$1"; [[ "$RUN" =~ ^[0-9]+-[0-9]+$ ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
K=(kubectl --context kind-cozyplane-ipsec-test)
REPORT="/tmp/cozyplane-ipsec-test/results-$RUN"
mkdir -p "$REPORT"
"${K[@]}" get namespace "ipsec-test-$RUN" -o json > "$REPORT/cleanup-namespace.json"
"${K[@]}" -n "ipsec-test-$RUN" get vpnconnections,vpngateways,pods -o json |
  jq '{items:[.items[]|{kind:.kind,name:.metadata.name,uid:.metadata.uid,deletionTimestamp:.metadata.deletionTimestamp,finalizers:.metadata.finalizers,status:.status}]}' > "$REPORT/cleanup-resources.json"
cat "$REPORT/cleanup-resources.json"
