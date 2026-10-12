#!/usr/bin/env bash
# Separate post-authentication diagnostic; production replay defaults stay intact.
# shellcheck disable=SC2154
python3 "$ROOT/test/ipsec-snapshot.py" "$ROOT" "$REPORT" reorder-control ipsec-reorder-control.sh ipsec-measure.sh ipsec-packet-counters.sh ipsec-sa-public.py
# shellcheck source=test/ipsec-measure.sh
source "$ROOT/test/ipsec-measure.sh"
# shellcheck source=test/ipsec-packet-counters.sh
source "$ROOT/test/ipsec-packet-counters.sh"
wait_for 'healthy authorized pool traffic before reorder control' http 1 "$A"
packet_counters targeted-reorder-before
counters targeted-reorder-before
client_exec 1 tc qdisc replace dev eth0 root netem delay 100ms 20ms reorder 1% 25%
sample targeted-reorder-udp 1 20 udp 100M
client_exec 1 tc -s -j qdisc show dev eth0 > "$REPORT/reorder-active-qdisc.json"
client_exec 1 sh -c 'cat /proc/net/dev; tc -s qdisc show dev eth0' > "$REPORT/reorder-active-netdev-qdisc.txt"
client_exec 1 tc qdisc del dev eth0 root
counters targeted-reorder-after
packet_counters targeted-reorder-after
wait_for 'healthy pool HTTP traffic after clearing reorder qdisc' http 1 "$A"
