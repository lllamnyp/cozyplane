#!/usr/bin/env bash
# Public evidence only. Never reads Kubernetes Secrets or appliance config files.
set -euo pipefail
NS="${1:?isolated namespace required}"
[[ "$NS" =~ ^ipsec-test-[0-9]+-[0-9]+$ ]] || exit 2
REPORT="/tmp/cozyplane-ipsec-test/results-${NS#ipsec-test-}"
[[ -d "$REPORT" ]] || exit 2
K=(kubectl --kubeconfig /tmp/cozyplane-ipsec-test/kubeconfig --context kind-cozyplane-ipsec-test -n "$NS")
zcat /proc/config.gz | grep -E 'CONFIG_(XFRM|INET_ESP|INET6_ESP)' > "$REPORT/kernel-xfrm-config.txt"
"${K[@]}" logs deployment/gateway-vpn --tail=10 > "$REPORT/appliance-preflight.log"
"${K[@]}" get pods -o json | jq '[.items[]|{name:.metadata.name,phase:.status.phase,conditions:.status.conditions,containers:.status.containerStatuses}]' > "$REPORT/pods-preflight.json"
printf '%s\n' 'BLOCKED: product appliance rejects unavailable CONFIG_XFRM_INTERFACE before charon startup; no tunnel, load or packet-loss result exists.' >> "$REPORT/checks.log"
python3 /src/test/wireguard-client-report.py "$REPORT"
