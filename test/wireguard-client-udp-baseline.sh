#!/usr/bin/env bash
# Moderate-rate follow-up after the full suite freed its client-2 quota slot.
set -euo pipefail
NS="${1:?isolated namespace required}"
REPORT="${2:?existing result directory required}"
[[ "$NS" =~ ^wg-client-[0-9]+-[0-9]+$ && "$REPORT" == /tmp/cozyplane-wg-client/results-* && -d "$REPORT" ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-wg-client/kubeconfig
K=(kubectl --context kind-cozyplane-wg-client -n "$NS")
NAME="udp-proof-$$"
CLIENT="cozyplane-wgc-${NS#wg-client-}-$NAME"
CREATED=0
PROBE_PID=''
cleanup() {
  if [[ -n "$PROBE_PID" ]]; then kill "$PROBE_PID" >/dev/null 2>&1 || true; wait "$PROBE_PID" 2>/dev/null || true; fi
  docker rm -f "$CLIENT" >/dev/null 2>&1 || true
  if ((CREATED)); then "${K[@]}" delete vpnconnection "$NAME" --ignore-not-found --timeout=180s >/dev/null; fi
}
trap cleanup EXIT
docker run -d --name "$CLIENT" --label cozyplane.test=wireguard-client --cap-add NET_ADMIN --network kind cozyplane-wg-client-bench:local >/dev/null
docker exec "$CLIENT" sh -c 'umask 077; wg genkey > /run/client.key'
PUBLIC=$(docker exec "$CLIENT" sh -c 'wg pubkey < /run/client.key')
"${K[@]}" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: "$NAME"}
spec:
  gatewayRef: {name: gateway}
  wireguard:
    peerPublicKey: "$PUBLIC"
    client: {addressPools: [clients-v4, clients-v6], vpcRefs: [{name: site-a}, {name: site-v6}]}
EOF
CREATED=1
for _ in $(seq 1 150); do
  CONFIG=$("${K[@]}" get vpnconnection "$NAME" -o json)
  if jq -e '. as $c | any(.status.conditions[]?; .type=="ClientConfigured" and .status=="True" and .observedGeneration==$c.metadata.generation)' <<<"$CONFIG" >/dev/null; then break; fi
  sleep 2
done
jq -e '. as $c | any(.status.conditions[]?; .type=="ClientConfigured" and .status=="True" and .observedGeneration==$c.metadata.generation)' <<<"$CONFIG" >/dev/null
ENDPOINT=$(jq -r '.status.clientConfig.endpoint' <<<"$CONFIG")
ENDPOINT_IP="${ENDPOINT%:*}"
[[ "$ENDPOINT_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
SERVER_KEY=$(jq -r '.status.clientConfig.serverPublicKey' <<<"$CONFIG")
MTU=$(jq -r '.status.clientConfig.mtu' <<<"$CONFIG")
ALLOWED=$(jq -r '.status.clientConfig.allowedIPs | join(",")' <<<"$CONFIG")
[[ "$MTU" =~ ^[0-9]+$ ]] || exit 2
jq -e '.status.clientConfig.allowedIPs | sort == ["10.250.1.0/24", "fd42:250:1::/64"]' <<<"$CONFIG" >/dev/null
NODE_IP=$(docker inspect cozyplane-wg-client-worker -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
docker exec "$CLIENT" ip route add "$ENDPOINT_IP/32" via "$NODE_IP"
docker exec "$CLIENT" ip link add wg0 type wireguard
docker exec "$CLIENT" wg set wg0 private-key /run/client.key peer "$SERVER_KEY" endpoint "$ENDPOINT" allowed-ips "$ALLOWED" persistent-keepalive 5
docker exec "$CLIENT" ip link set wg0 mtu "$MTU" up
while read -r address; do
  if [[ "$address" == *:* ]]; then
    [[ "$address" == fd42:250:100:* ]] || exit 2
    docker exec "$CLIENT" ip -6 address add "$address/128" dev wg0
  else
    [[ "$address" =~ ^10\.250\.100\.[0-9]+$ ]] || exit 2
    docker exec "$CLIENT" ip address add "$address/32" dev wg0
  fi
done < <(jq -r '.status.assignedAddresses[]' <<<"$CONFIG")
docker exec "$CLIENT" ip route add 10.250.1.0/24 dev wg0
docker exec "$CLIENT" ip -6 route add fd42:250:1::/64 dev wg0
TARGET=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-a" -o json | jq -r '[.items[].spec.ip | select(contains(":")|not)][0]')
[[ "$TARGET" =~ ^10\.250\.1\.[0-9]+$ ]] || exit 2
docker exec "$CLIENT" curl -fsS --noproxy '*' -m 5 "http://$TARGET:8080/" | grep -qx site-a
if [[ "${HA_RETEST:-0}" == 1 ]]; then
  standby_ready() {
    "${K[@]}" get deployment gateway-vpn -o json | jq -e '.spec.replicas==2 and .status.readyReplicas==2 and .status.updatedReplicas==2 and .status.observedGeneration>=.metadata.generation' >/dev/null || return 1
    "${K[@]}" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json | jq -e '.items|length==2 and all(.[]; .metadata.deletionTimestamp==null and any(.status.conditions[]?; .type=="Ready" and .status=="True"))' >/dev/null || return 1
    "${K[@]}" get vpnconnection "$NAME" -o json | jq -e '. as $c | any(.status.conditions[]?; .type=="ClientConfigured" and .status=="True" and .observedGeneration==$c.metadata.generation)' >/dev/null
  }
  for _ in $(seq 1 150); do standby_ready && break; sleep 2; done
  standby_ready
  "${K[@]}" get vpngateway gateway -o json > "$REPORT/ha-ready-gateway-before.json"
  "${K[@]}" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json > "$REPORT/ha-ready-pods-before.json"
  selected_port=$(jq -r '.status.appliancePort' "$REPORT/ha-ready-gateway-before.json")
  selected=$("${K[@]}" get port "$selected_port" -o jsonpath='{.spec.podName}')
  [[ "$selected" =~ ^gateway-vpn-[a-z0-9-]+$ ]] || exit 2
  probes() {
    while true; do
      timestamp=$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')
      if docker exec "$CLIENT" curl -fsS --noproxy '*' -m 1 "http://$TARGET:8080/" >/dev/null 2>&1; then result=success; else result=failure; fi
      printf '%s\t%s\n' "$timestamp" "$result" >> "$REPORT/ha-ready-retest-probes.tsv"
      sleep .5
    done
  }
  probes & PROBE_PID=$!
  sleep 1
  jq -nc --arg time "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg pod "$selected" '{timestamp:$time,action:"delete-selected-with-standby-ready",pod:$pod}' >> "$REPORT/ha-ready-retest-events.jsonl"
  "${K[@]}" delete pod "$selected" --wait=false >/dev/null
  for _ in $(seq 1 150); do
    if docker exec "$CLIENT" curl -fsS --noproxy '*' -m 2 "http://$TARGET:8080/" >/dev/null 2>&1; then
      # Ensure failover selected another owned appliance, not a last request
      # served by the terminating selected pod.
      replacement_port=$("${K[@]}" get vpngateway gateway -o jsonpath='{.status.appliancePort}')
      replacement=$("${K[@]}" get port "$replacement_port" -o jsonpath='{.spec.podName}')
      [[ "$replacement" == "$selected" ]] || break
    fi
    sleep 2
  done
  [[ "${replacement:-$selected}" != "$selected" ]]
  docker exec "$CLIENT" curl -fsS --noproxy '*' -m 5 "http://$TARGET:8080/" | grep -qx site-a
  jq -nc --arg time "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg pod "$replacement" '{timestamp:$time,action:"replacement-application-traffic-confirmed",pod:$pod}' >> "$REPORT/ha-ready-retest-events.jsonl"
  "${K[@]}" get vpngateway gateway -o json > "$REPORT/ha-ready-gateway-after.json"
  "${K[@]}" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json > "$REPORT/ha-ready-pods-after.json"
  sleep 1
  kill "$PROBE_PID"; wait "$PROBE_PID" 2>/dev/null || true; PROBE_PID=''
  echo 'PASS: selected appliance loss with two Ready replicas and current client config; automatic provider.' | tee -a "$REPORT/checks.log"
fi
V6=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-v6" -o json | jq -r '[.items[].spec.ip | select(contains(":"))][0]')
[[ "$V6" == fd42:250:1:* ]] || exit 2
docker exec "$CLIENT" curl -fsS --noproxy '*' -m 5 "http://[$V6]:8080/" | grep -qx site-v6
docker exec "$CLIENT" ip -6 address add fd42:250:100::ffff/128 dev wg0
if docker exec "$CLIENT" curl --interface fd42:250:100::ffff --noproxy '*' -fsS -m 5 "http://[$V6]:8080/" >/dev/null 2>&1; then
  echo 'FAIL: spoofed IPv6 source was accepted' >&2; exit 1
fi
docker exec "$CLIENT" ip -6 address del fd42:250:100::ffff/128 dev wg0
echo 'PASS: authorized IPv6 control and explicit IPv6 source-spoof rejection.' | tee -a "$REPORT/checks.log"
UNDERLAY=$(docker inspect cozyplane-wg-client-control-plane -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
[[ "$UNDERLAY" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
# Prove the underlay API listener responds before attempting it via the tunnel.
CODE=$(curl --noproxy '*' -ksS --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' "https://$UNDERLAY:6443/version")
[[ "$CODE" =~ ^(200|401|403)$ ]] || exit 1
echo "Underlay positive control HTTPS status: $CODE" > "$REPORT/underlay-control.txt"
docker exec "$CLIENT" wg set wg0 peer "$SERVER_KEY" allowed-ips "$ALLOWED,$UNDERLAY/32"
docker exec "$CLIENT" ip route add "$UNDERLAY/32" dev wg0
if docker exec "$CLIENT" curl --noproxy '*' -ksS --connect-timeout 3 --max-time 5 -o /dev/null "https://$UNDERLAY:6443/version"; then
  echo 'FAIL: cluster underlay API became reachable through WireGuard' >&2; exit 1
fi
docker exec "$CLIENT" ip route del "$UNDERLAY/32" dev wg0
docker exec "$CLIENT" wg set wg0 peer "$SERVER_KEY" allowed-ips "$ALLOWED"
echo 'PASS: live underlay API rejected after tunnel route widening.' | tee -a "$REPORT/checks.log"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$REPORT/moderate-udp-counters-before.txt"
"${K[@]}" exec server-a -- cat /proc/net/snmp /proc/net/dev >> "$REPORT/moderate-udp-counters-before.txt"
ACTIVE_PORT=$("${K[@]}" get vpngateway gateway -o jsonpath='{.status.appliancePort}')
ACTIVE_POD=$("${K[@]}" get port "$ACTIVE_PORT" -o jsonpath='{.spec.podName}')
[[ "$ACTIVE_POD" =~ ^gateway-vpn-[a-z0-9-]+$ ]] || exit 2
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$REPORT/moderate-udp-gateway-counters-before.txt"
"${K[@]}" exec "$ACTIVE_POD" -- cat /proc/net/snmp /proc/net/dev >> "$REPORT/moderate-udp-gateway-counters-before.txt"
docker exec "$CLIENT" iperf3 -c "$TARGET" -p 5201 -u -b 20M -t 15 -J > "$REPORT/moderate-udp-client1.json"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$REPORT/moderate-udp-counters-after.txt"
"${K[@]}" exec server-a -- cat /proc/net/snmp /proc/net/dev >> "$REPORT/moderate-udp-counters-after.txt"
date -u +'%Y-%m-%dT%H:%M:%SZ' > "$REPORT/moderate-udp-gateway-counters-after.txt"
"${K[@]}" exec "$ACTIVE_POD" -- cat /proc/net/snmp /proc/net/dev >> "$REPORT/moderate-udp-gateway-counters-after.txt"
jq -e 'has("error")|not' "$REPORT/moderate-udp-client1.json" >/dev/null
echo 'PASS: moderate-rate product UDP baseline completed with receiver counters.' | tee -a "$REPORT/checks.log"
