#!/usr/bin/env bash
# Read public status and selectors for a single named disposable pool fixture.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
RUN=$1; [[ "$RUN" =~ ^[0-9]+-[0-9]+$ ]] || exit 2
REPORT=/tmp/cozyplane-ipsec-test/results-$RUN
NS=ipsec-test-$RUN
[[ -d "$REPORT" ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
K=(kubectl --context kind-cozyplane-ipsec-test)
DEST="$REPORT/pool-warm-observe-$(date +%s)"; mkdir "$DEST"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$DEST/timestamp.txt"
"${K[@]}" -n "$NS" get vpngateway gateway -o json > "$DEST/gateway.json"
"${K[@]}" -n "$NS" get vpnconnections -o json > "$DEST/peers.json"
"${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json > "$DEST/pods.json"
for pod in $(jq -r '.items[].metadata.name' "$DEST/pods.json"); do
  "${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$pod:9410/proxy/status" > "$DEST/$pod-status.json"
done
docker exec "cozyplane-ipsec-peer-$RUN-1" swanctl --list-sas > "$DEST/client1-sas.txt"
docker exec "cozyplane-ipsec-peer-$RUN-1" ip xfrm policy > "$DEST/client1-policies.txt"
target=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-a" -o json | jq -r '[.items[].spec.ip|select(contains(":")|not)][0]')
docker exec "cozyplane-ipsec-peer-$RUN-1" curl --noproxy '*' -sS --max-time 4 -w '\nHTTP=%{http_code}\n' "http://$target:8080/" > "$DEST/client1-http.txt" 2>&1 || true
echo "Public pool observation: $DEST"
