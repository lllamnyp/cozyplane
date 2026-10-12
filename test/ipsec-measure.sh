#!/usr/bin/env bash
# Sourced by the isolated IPsec harness after functional access checks succeed.
# COUNT is supplied by its parent; reporting fail records a flag and returns zero.
# shellcheck disable=SC2153,SC2015
sample() {
  local title="$1" count="$2" duration="$3" protocol="${4:-tcp}" rate="${5:-100M}" n pid
  local pids=() args=()
  echo "MEASURE: $title peers=$count seconds=$duration protocol=$protocol" | tee -a "$REPORT/checks.log"
  for n in $(seq 1 "$count"); do
    args=(-c "$A" -p "$((5200+n))" -t "$duration" -J)
    [[ "$protocol" != udp ]] || args+=(-u -b "$rate" -l 1200)
    client_exec "$n" timeout -k 5 "$((duration+60))" iperf3 "${args[@]}" > "$REPORT/$title-client$n.json" & pids+=("$!")
  done
  client_exec 1 ping -i .2 -w "$duration" "$A" > "$REPORT/$title-ping.txt" & pids+=("$!")
  for pid in "${pids[@]}"; do wait "$pid" || fail "$title traffic command failed"; done
  "${K[@]}" -n "$NS" get pods -o json | jq '[.items[]|{name:.metadata.name,phase:.status.phase,restarts:[.status.containerStatuses[]?.restartCount],images:[.status.containerStatuses[]?.imageID]}]' >> "$REPORT/pods.jsonl"
}
counters() {
  local phase="$1" name output
  for name in server-a "$(selected_pod)"; do
    output=$("${K[@]}" -n "$NS" exec "$name" -- cat /proc/net/snmp /proc/net/snmp6 /proc/net/dev)
    jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --arg phase "$phase" --arg name "$name" --arg counters "$output" '{timestamp:$timestamp,phase:$phase,name:$name,counters:$counters}' >> "$REPORT/udp-counters.jsonl"
  done
}
if [[ "${RUN_LOAD:-0}" == 1 ]]; then
  ((FAILED==0)) || { echo 'Functional security failure prevents load measurement.' >&2; exit 1; }
  for n in 1 8 16; do
    ((n<=COUNT)) || continue
    for repetition in 1 2 3; do sample "tcp-$n-$repetition" "$n" "${SECONDS_PER_SAMPLE:-60}"; done
  done
  for rate in 100M 20M; do
    counters "baseline-$rate-before"
    sample "baseline-$rate-udp" 1 "${SECONDS_PER_SAMPLE:-60}" udp "$rate"
    counters "baseline-$rate-after"
  done
  for loss in 1 5 10; do
    client_exec 1 tc qdisc replace dev eth0 root netem loss "$loss%"
    counters "loss-$loss-before"
    sample "loss-$loss" 1 "${SECONDS_PER_SAMPLE:-60}" udp 100M
    counters "loss-$loss-after"
    client_exec 1 tc qdisc del dev eth0 root
    wait_for "automatic recovery after $loss% loss" http 1 "$A"
  done
  client_exec 1 tc qdisc replace dev eth0 root netem delay 100ms 20ms reorder 1% 25%
  sample delay-jitter-reorder 1 "${SECONDS_PER_SAMPLE:-60}" udp 100M
  client_exec 1 tc qdisc del dev eth0 root
  client_exec 1 tc qdisc replace dev eth0 root netem loss 100%
  http 1 "$A" >/dev/null 2>&1 && fail '100% cut did not cut transport' || pass 'transport cut enforced'
  date -u +'%Y-%m-%dT%H:%M:%SZ cut-start' >> "$REPORT/recovery-events.txt"
  sleep 30
  client_exec 1 tc qdisc del dev eth0 root
  date -u +'%Y-%m-%dT%H:%M:%SZ cut-end' >> "$REPORT/recovery-events.txt"
  wait_for 'automatic recovery after 30-second cut' http 1 "$A"
  sample soak "$COUNT" "${SOAK_SECONDS:-600}"
fi
