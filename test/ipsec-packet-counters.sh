#!/usr/bin/env bash
# Read-only counters; raw SA/key material is filtered in memory, never exported.
# shellcheck disable=SC2154
packet_counters() {
  local phase="$1" name output states
  for name in server-a "$(selected_pod)"; do
    output=$("${K[@]}" -n "$NS" exec "$name" -- sh -c 'cat /proc/net/xfrm_stat /proc/net/dev; tc -s qdisc show')
    jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --arg name "$name" --arg counters "$output" '{timestamp:$timestamp,phase:$phase,name:$name,counters:$counters}' >> "$REPORT/packet-counters.jsonl"
    if [[ "$name" != server-a ]]; then
      states=$("${K[@]}" -n "$NS" exec "$name" -- ip -s xfrm state | python3 "$ROOT/test/ipsec-sa-public.py")
      jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --arg name "$name" --argjson states "$states" '{timestamp:$timestamp,phase:$phase,name:$name,states:$states}' >> "$REPORT/sa-public-counters.jsonl"
    fi
  done
  output=$(client_exec 1 sh -c 'cat /proc/net/xfrm_stat /proc/net/dev; tc -s qdisc show')
  jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --arg counters "$output" '{timestamp:$timestamp,phase:$phase,name:"peer-1",counters:$counters}' >> "$REPORT/packet-counters.jsonl"
  states=$(client_exec 1 ip -s xfrm state | python3 "$ROOT/test/ipsec-sa-public.py")
  jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --argjson states "$states" '{timestamp:$timestamp,phase:$phase,name:"peer-1",states:$states}' >> "$REPORT/sa-public-counters.jsonl"
  jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --arg counters "$(cat /proc/net/softnet_stat)" '{timestamp:$timestamp,phase:$phase,scope:"guest-global",softnet:$counters}' >> "$REPORT/packet-counters.jsonl"
}
