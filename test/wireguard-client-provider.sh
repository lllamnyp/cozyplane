#!/usr/bin/env bash
# Emulate only the dedicated fixture's missing external LoadBalancer provider.
set -euo pipefail
NS="${1:?isolated namespace required}"
REPORT="${2:?existing result directory required}"
CLUSTER="${FIXTURE_CLUSTER:-cozyplane-wg-client}"
case "$CLUSTER" in
  cozyplane-wg-client) [[ "$NS" =~ ^wg-client-[0-9]+-[0-9]+$ ]] || exit 2;;
  cozyplane-ipsec-test) [[ "$NS" =~ ^ipsec-test-[0-9]+-[0-9]+$ ]] || exit 2;;
  *) exit 2;;
esac
[[ "$REPORT" == /tmp/"$CLUSTER"/results-* && -d "$REPORT" ]] || exit 2
export KUBECONFIG="/tmp/$CLUSTER/kubeconfig"
K=(kubectl --context "kind-$CLUSTER" -n "$NS")
GATEWAY="${FIXTURE_GATEWAY:-gateway}"
[[ "$GATEWAY" =~ ^gateway(-[a-z0-9]+)?$ ]] || exit 2
GATEWAY_UID=$("${K[@]}" get vpngateway "$GATEWAY" -o jsonpath='{.metadata.uid}')
FIP=$(docker network inspect kind | jq -r '.[0].IPAM.Config[] | select(.Subnet|contains(":")|not) | .Subnet' | python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.stdin.read().strip()); print(n[-250])')
reconcile() {
  local floating service
  floating=$("${K[@]}" get floatingip "$GATEWAY-vpn" --ignore-not-found -o json)
  [[ -n "$floating" ]] || return 0
  jq -e --arg uid "$GATEWAY_UID" 'any(.metadata.ownerReferences[]?; .uid==$uid and .controller==true)' <<<"$floating" >/dev/null || return 1
  local uid
  uid=$(jq -r '.metadata.uid' <<<"$floating")
  service=$("${K[@]}" get services -o json | jq -r --arg uid "$uid" '[.items[] | select(.spec.type=="LoadBalancer" and any(.metadata.ownerReferences[]?; .uid==$uid and .controller==true)) | select((.status.loadBalancer.ingress // [])|length==0)] | if length==1 then .[0].metadata.name else empty end')
  [[ -n "$service" ]] || return 0
  "${K[@]}" patch service "$service" --subresource=status --type=merge -p "{\"status\":{\"loadBalancer\":{\"ingress\":[{\"ip\":\"$FIP\"}]}}}" >/dev/null
  jq -nc --arg time "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg service "$service" --arg uid "$uid" --arg ip "$FIP" '{timestamp:$time,service:$service,floatingIPUID:$uid,address:$ip,action:"fixture-provider-address-assigned"}' >> "$REPORT/provider-events.jsonl"
}
if [[ "${3:-}" == --watch ]]; then
  # The full suite includes about 25 minutes of measurement before HA checks.
  # Its parent trap terminates us; retain a bounded fallback for standalone use.
  deadline=$((SECONDS+7200))
  while ((SECONDS < deadline)); do
    [[ ! -f "$REPORT/provider.stop" ]] || break
    current=$("${K[@]}" get vpngateway "$GATEWAY" --ignore-not-found -o jsonpath='{.metadata.uid}')
    [[ "$current" == "$GATEWAY_UID" ]] || break
    reconcile
    sleep 2
  done
else
  reconcile
fi
