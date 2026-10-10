#!/usr/bin/env bash
# Sourced by the isolated fixture; exact same data-plane probes before/after.
# shellcheck disable=SC2015
# Reload the reviewed evidence helper before this post-measurement phase.
# shellcheck source=test/ipsec-protocol.sh
source "$ROOT/test/ipsec-protocol.sh"
python3 "$ROOT/test/ipsec-snapshot.py" "$ROOT" "$REPORT" lifecycle ipsec-e2e.sh ipsec-lifecycle.sh ipsec-protocol.sh ipsec-auth-negative.sh ipsec-packet-counters.sh ipsec-sa-public.py ipsec-measure.sh ipsec-static-role.py
# Targeted idle controls are separate from the already-completed long suite.
# These complete pre/post XFRM, qdisc and guest softnet evidence missing at its baseline.
# shellcheck source=test/ipsec-packet-counters.sh
source "$ROOT/test/ipsec-packet-counters.sh"
for rate in 100M 20M; do
  packet_counters "targeted-$rate-before"
  counters "targeted-$rate-before"
  sample "targeted-$rate-udp" 1 20 udp "$rate"
  counters "targeted-$rate-after"
  packet_counters "targeted-$rate-after"
done
if [[ "${RUN_REORDER_CONTROL:-0}" == 1 ]]; then
  # shellcheck source=test/ipsec-reorder-control.sh
  source "$ROOT/test/ipsec-reorder-control.sh"
fi
rekey_actual 1 site-child-rekey
wait_for 'data-plane access after CHILD rekey' http 1 "$A"
client_exec 1 swanctl --list-sas > "$REPORT/rekey-sas.txt"
"${K[@]}" -n "$NS" rollout restart deployment/gateway-vpn >/dev/null
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
wait_for 'automatic native peer recovery after appliance restart' http 1 "$A"
wait_for 'restarted appliance acknowledges exact current configuration' current_configured
umask 077; openssl rand -hex 32 | tr -d '\n' > "$PRIVATE/rotated-psk"
old_checksum=$(config_checksum)
date -u +'%Y-%m-%dT%H:%M:%SZ credential-rollout-start' >> "$REPORT/recovery-events.txt"
"${K[@]}" -n "$NS" create secret generic peer-1-psk --from-file="psk=$PRIVATE/rotated-psk" --dry-run=client -o yaml | "${K[@]}" -n "$NS" apply -f - >/dev/null
wait_for 'changed credential configuration acknowledged by every Ready replica' config_changed "$old_checksum"
wait_for 'unchanged surviving peer healthy before retired-PSK rejection' http 2 "$A"
date -u +'%Y-%m-%dT%H:%M:%SZ credential-rollout-survivor-recovered' >> "$REPORT/recovery-events.txt"
negative_auth 1 2 retired-psk "$A"
docker exec -i "${CLIENT_NAMES[0]}" python3 -c 'import pathlib,re,sys; p=pathlib.Path("/run/ipsec-test/swanctl.conf"); p.write_text(re.sub(r"secret = [0-9a-f]+", "secret = "+sys.stdin.read().strip(),p.read_text()))' < "$PRIVATE/rotated-psk"
client_exec 1 swanctl --load-creds --file /run/ipsec-test/swanctl.conf >/dev/null
wait_for 'rotated PSK initiates successfully' initiate 1
wait_for 'rotated PSK reaches served VPC' http 1 "$A"
"${K[@]}" -n "$NS" patch vpngateway gateway --type=merge -p '{"spec":{"ha":{"mode":"WarmStandby"}}}' >/dev/null
standby_ready() {
  "${K[@]}" -n "$NS" get deployment gateway-vpn -o json | jq -e '.spec.replicas==2 and .status.readyReplicas==2 and .status.updatedReplicas==2 and .status.observedGeneration>=.metadata.generation' >/dev/null || return 1
  "${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json | jq -e '.items|length==2 and all(.[];.metadata.deletionTimestamp==null and any(.status.conditions[]?;.type=="Ready" and .status=="True"))' >/dev/null || return 1
  current_configured
}
wait_for 'both WarmStandby appliances Ready with current desired generation' standby_ready
wait_for 'WarmStandby peer traffic healthy before selected loss' http 1 "$A"
"${K[@]}" -n "$NS" get vpngateway gateway -o json > "$REPORT/ha-before-gateway.json"
selected=$(selected_pod)
selected_uid=$("${K[@]}" -n "$NS" get pod "$selected" -o jsonpath='{.metadata.uid}')
printf '%s\t%s\n' "$selected" "$selected_uid" > "$REPORT/ha-selected-before.tsv"
"${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json > "$REPORT/ha-before-pods.json"
observe_recovery() {
  local deadline=$((SECONDS+330)) code
  while ((SECONDS<deadline)) && [[ ! -f "$REPORT/ha-monitor.stop" ]]; do
    code=$(client_exec 1 curl --noproxy '*' -sS --connect-timeout 1 --max-time 1 -o /dev/null -w '%{http_code}' "http://$A:8080/" 2>/dev/null || true)
    jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" --arg code "$code" '{timestamp:$timestamp,http:$code}' >> "$REPORT/ha-probes.jsonl"
    sleep .5
  done
}
observe_recovery & observer=$!
sleep 2
date -u +'%Y-%m-%dT%H:%M:%SZ selected-appliance-delete' >> "$REPORT/recovery-events.txt"
"${K[@]}" -n "$NS" delete pod "$selected" --wait=true --timeout=90s >/dev/null
selected_recovered() {
  local pod uid
  pod=$(selected_pod); [[ -n "$pod" && "$pod" != "$selected" ]] || return 1
  uid=$("${K[@]}" -n "$NS" get pod "$pod" -o jsonpath='{.metadata.uid}')
  [[ -n "$uid" && "$uid" != "$selected_uid" ]] || return 1
  http 1 "$A" >/dev/null
}
wait_for 'automatic WarmStandby recovery on a different selected appliance UID' selected_recovered || true
[[ "$(http 1 "$B")" == site-b ]] && pass 'WarmStandby second VPC leg recovered' || fail 'WarmStandby second VPC leg'
[[ "$(http 1 "[$V6]")" == site-v6 ]] && pass 'WarmStandby IPv6 VPC leg recovered' || fail 'WarmStandby IPv6 VPC leg'
sleep 3; touch "$REPORT/ha-monitor.stop"; wait "$observer" || true
"${K[@]}" -n "$NS" get vpngateway gateway -o json > "$REPORT/ha-after-gateway.json"
selected_after=$(selected_pod)
printf '%s\t%s\n' "$selected_after" "$("${K[@]}" -n "$NS" get pod "$selected_after" -o jsonpath='{.metadata.uid}')" > "$REPORT/ha-selected-after.tsv"
"${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json > "$REPORT/ha-after-pods.json"
"${K[@]}" -n "$NS" get events -o json > "$REPORT/ha-events.json"
old_checksum=$(config_checksum)
date -u +'%Y-%m-%dT%H:%M:%SZ peer-withdrawal-rollout-start' >> "$REPORT/recovery-events.txt"
"${K[@]}" -n "$NS" delete vpnconnection peer-2 --wait=true --timeout=300s >/dev/null
wait_for 'peer withdrawal config acknowledged before revocation probe' config_changed "$old_checksum"
wait_for 'remaining authorized peer healthy before deletion rejection control' http 1 "$A"
date -u +'%Y-%m-%dT%H:%M:%SZ peer-withdrawal-survivor-recovered' >> "$REPORT/recovery-events.txt"
http 2 "$A" >/dev/null 2>&1 && fail 'deleted peer keeps authorized traffic' || pass 'deleted peer data-plane revoked'
client_exec 2 swanctl --terminate --ike peer-2 >/dev/null 2>&1 || true
negative_auth 2 1 deleted-site-peer "$A"
wait_for 'remaining peer recovers after peer deletion rollout' http 1 "$A"
static_peer_ip=$(docker inspect "${CLIENT_NAMES[0]}" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
client_exec 1 swanctl --terminate --ike peer-1 >/dev/null 2>&1 || true
client_exec 1 python3 -c 'import pathlib,re; p=pathlib.Path("/run/ipsec-test/swanctl.conf"); text=p.read_text(); text=re.sub(r"remote_addrs = [^\n]+","remote_addrs = %any",text); text=text.replace("dpd_action = restart","dpd_action = clear").replace("close_action = restart","close_action = none"); p.write_text(text)'
load_client 1
old_checksum=$(config_checksum)
"${K[@]}" -n "$NS" patch vpnconnection peer-1 --type=merge -p "{\"spec\":{\"ipsec\":{\"peerAddress\":\"$static_peer_ip\",\"startAction\":\"Start\"}}}" >/dev/null
wait_for 'static appliance initiator configuration acknowledged' config_changed "$old_checksum"
wait_for 'appliance-initiated static peer automatically restores actual traffic' http 1 "$A"
client_exec 1 swanctl --list-sas > "$REPORT/static-initiator-sas.txt"
client_exec 1 swanctl --list-sas --raw > "$REPORT/static-initiator-sas-raw.txt"
grep -Eq '^peer-1: #[0-9]+, ESTABLISHED, IKEv2, [0-9a-f]+_i [0-9a-f]+_r\*$' "$REPORT/static-initiator-sas.txt" && ! grep -Eq '^peer-1: .*_i\*' "$REPORT/static-initiator-sas.txt" && pass 'static client actual IKE role is responder' || fail 'static client responder role not demonstrated'
for appliance in $("${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o jsonpath='{.items[*].metadata.name}'); do
  "${K[@]}" -n "$NS" exec "$appliance" -- swanctl --list-sas --raw > "$REPORT/static-appliance-$appliance-sas-raw.txt"
done
python3 "$ROOT/test/ipsec-static-role.py" "$REPORT" 0 && pass 'static appliance initiator shares the exact client responder IKE SPI pair' || fail 'matching static IKE role evidence'
# Run after every IPSec probe; this deliberately leaves the gateway unconfigured.
# shellcheck source=test/ipsec-transition.sh
source "$ROOT/test/ipsec-transition.sh"
