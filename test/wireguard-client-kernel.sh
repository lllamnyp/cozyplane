#!/usr/bin/env bash
# Infrastructure probe only; results do not validate Cozyplane authorization.
set -euo pipefail
IMAGE="${BENCH_IMAGE:-cozyplane-wg-client-bench:local}"
ID="$(date +%s)-$$"
A="cozyplane-wgprobe-$ID-a"; B="cozyplane-wgprobe-$ID-b"
REPORT="${REPORT:-/tmp/cozyplane-wg-client/kernel-probe-$ID}"
mkdir -p "$REPORT"
cleanup() { docker rm -f "$A" "$B" >/dev/null 2>&1 || true; }
trap cleanup EXIT
for name in "$A" "$B"; do
  docker run -d --name "$name" --label cozyplane.test=wireguard-client --cap-add NET_ADMIN --network kind "$IMAGE" >/dev/null
  docker exec "$name" sh -c 'umask 077; wg genkey >/run/probe.key; ip link add wg0 type wireguard; wg set wg0 private-key /run/probe.key listen-port 51820; ip link set wg0 up'
done
KEY_A=$(docker exec "$A" sh -c 'wg pubkey </run/probe.key')
KEY_B=$(docker exec "$B" sh -c 'wg pubkey </run/probe.key')
IP_A=$(docker inspect "$A" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
IP_B=$(docker inspect "$B" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
docker exec "$A" ip addr add 10.253.100.1/24 dev wg0
docker exec "$B" ip addr add 10.253.100.2/24 dev wg0
docker exec "$A" wg set wg0 peer "$KEY_B" allowed-ips 10.253.100.2/32 endpoint "$IP_B:51820" persistent-keepalive 5
docker exec "$B" wg set wg0 peer "$KEY_A" allowed-ips 10.253.100.1/32 endpoint "$IP_A:51820" persistent-keepalive 5
docker exec -d "$B" iperf3 -s
docker exec "$A" ping -c 10 10.253.100.2 > "$REPORT/baseline-ping.txt"
docker exec "$A" iperf3 -c 10.253.100.2 -t 15 -J > "$REPORT/tcp-baseline.json"
for loss in 0 1 5 10; do
  docker exec "$A" tc qdisc replace dev eth0 root netem loss "$loss%"
  docker exec "$A" iperf3 -c 10.253.100.2 -t 15 -u -b 20M -J > "$REPORT/udp-loss-$loss.json"
done
docker exec "$A" tc qdisc replace dev eth0 root netem delay 100ms 20ms reorder 1% 25%
docker exec "$A" ping -c 20 -i .2 10.253.100.2 > "$REPORT/degraded-ping.txt"
docker exec "$A" tc qdisc del dev eth0 root
docker exec "$A" ping -c 3 10.253.100.2 > "$REPORT/recovery-ping.txt"
python3 test/wireguard-client-report.py "$REPORT"
echo "Infrastructure probe passed; Cozyplane integration remains separate. $REPORT"
