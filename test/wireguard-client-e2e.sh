#!/usr/bin/env bash
# Live tests against the dedicated local cluster. Keys exist only in /run inside clients.
# pass/fail are reporting functions; fail records the aggregate flag and returns success.
# shellcheck disable=SC2015
set -euo pipefail
[[ "${KCTX:-}" == kind-cozyplane-wg-client ]] || { echo 'KCTX must be kind-cozyplane-wg-client' >&2; exit 2; }
K=(kubectl --context "$KCTX")
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_IMAGE="${BENCH_IMAGE:-cozyplane-wg-client-bench:local}"
RUN_ID="$(date +%s)-$$"
NS="wg-client-$RUN_ID"
REPORT="${REPORT:-/tmp/cozyplane-wg-client/results-$RUN_ID}"
mkdir -p "$REPORT"
chmod 700 "$REPORT"
{
  date -u +'%Y-%m-%dT%H:%M:%SZ'
  git -C "$ROOT" rev-parse HEAD
  docker image inspect cozyplane-wireguard-client:local --format '{{.Id}}'
  uname -r
  go version
  "${K[@]}" version --client
} > "$REPORT/environment.txt"
COUNT="${CLIENTS:-16}"
[[ "$COUNT" =~ ^[0-9]+$ ]] && ((COUNT >= 2 && COUNT <= 16)) || { echo 'CLIENTS must be 2..16' >&2; exit 2; }
SECONDS_PER_SAMPLE="${SECONDS_PER_SAMPLE:-60}"
SOAK_SECONDS="${SOAK_SECONDS:-600}"
FAILED=0
CLIENT_NAMES=()
PROVIDER_PID=''
pass() { echo "PASS: $*" | tee -a "$REPORT/checks.log"; }
fail() { echo "FAIL: $*" | tee -a "$REPORT/checks.log" >&2; FAILED=1; }
cleanup() {
  if [[ -n "$PROVIDER_PID" ]]; then kill "$PROVIDER_PID" >/dev/null 2>&1 || true; wait "$PROVIDER_PID" 2>/dev/null || true; fi
  for client in "${CLIENT_NAMES[@]}"; do docker rm -f "$client" >/dev/null 2>&1 || true; done
  python3 "$ROOT/test/wireguard-client-report.py" "$REPORT" || true
  if [[ "${KEEP:-0}" != 1 ]]; then "${K[@]}" delete namespace "$NS" --wait=false >/dev/null 2>&1 || true; fi
  echo "Test report: $REPORT; namespace: $NS"
}
trap cleanup EXIT
wait_for() {
  local description="$1"; shift
  local deadline=$((SECONDS + 300))
  while ((SECONDS < deadline)); do if "$@"; then pass "$description"; return; fi; sleep 2; done
  fail "$description timed out"; return 1
}
configured() {
  "${K[@]}" -n "$NS" get vpnconnection "client-$1" -o json 2>/dev/null |
    jq -e '. as $c | any(.status.conditions[]?; .type=="ClientConfigured" and .status=="True" and .observedGeneration==$c.metadata.generation)' >/dev/null
}
client_exec() { local index="$1"; shift; docker exec "${CLIENT_NAMES[$((index-1))]}" "$@"; }
http() { client_exec "$1" curl -fsS --noproxy '*' --connect-timeout 3 --max-time 5 "http://$2:8080/"; }
ip_for() { "${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=$1" -o json | jq -r '[.items[].spec.ip | select(contains(":") | not)][0]'; }
kind load docker-image "$BENCH_IMAGE" --name cozyplane-wg-client >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
"${K[@]}" label namespace "$NS" pod-security.kubernetes.io/enforce=privileged >/dev/null
for site in a b c v6; do
  case "$site" in a) CIDR=10.250.1.0/24; NODE=cozyplane-wg-client-worker;;
    b) CIDR=10.250.2.0/24; NODE=cozyplane-wg-client-worker2;;
    c) CIDR=10.250.3.0/24; NODE=cozyplane-wg-client-worker2;;
    v6) CIDR=fd42:250:1::/64; NODE=cozyplane-wg-client-worker2;; esac
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: site-$site}
spec: {cidrs: ["$CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: site-$site}
spec: {vpcRef: {namespace: "$NS", name: site-$site}}
---
apiVersion: v1
kind: Pod
metadata:
  name: server-$site
  labels: {cozyplane.test/server: site-$site}
  annotations: {sdn.cozystack.io/vpc: site-$site}
spec:
  nodeName: $NODE
  containers:
  - name: server
    image: $BENCH_IMAGE
    imagePullPolicy: Never
    command: [bash, -c]
    args:
    - |
      for n in \$(seq 1 16); do iperf3 -s -p \$((5200+n)) >/dev/null 2>&1 & done
      mkdir -p /tmp/web; echo site-$site > /tmp/web/index.html
      cd /tmp/web; exec python3 -m http.server 8080 --bind ::
    resources:
      requests: {cpu: 100m, memory: 64Mi}
      limits: {cpu: "2", memory: 256Mi}
EOF
done
"${K[@]}" -n "$NS" wait --for=condition=Ready pod/server-a pod/server-b pod/server-c pod/server-v6 --timeout=180s
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {name: gateway}
spec:
  vpcRef: {name: site-a}
  additionalVPCRefs: [{name: site-b}, {name: site-c}, {name: site-v6}]
  wireguard:
    listenPort: 51820
    addressPools:
    - {name: clients-v4, cidr: 10.250.100.0/24}
    - {name: clients-v6, cidr: "fd42:250:100::/64"}
EOF
"${K[@]}" -n "$NS" wait --for=create deployment/gateway-vpn --timeout=180s
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
# Supply exactly one test-owned FloatingIP delegated Service's provider status.
service_ready() { SERVICE=$("${K[@]}" -n "$NS" get services -o json | jq -r '[.items[] | select(.spec.type=="LoadBalancer")][0].metadata.name // empty'); [[ -n "$SERVICE" ]]; }
wait_for 'FloatingIP delegated Service created' service_ready
NODE_IP=$(docker inspect cozyplane-wg-client-worker -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
FIP=$(docker network inspect kind | jq -r '.[0].IPAM.Config[] | select(.Subnet|contains(":")|not) | .Subnet' | python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.stdin.read().strip()); print(n[-250])')
# Emulate the provider continuously: appliance/endpoint changes can recreate the
# delegated Service. Only the owned fixture FloatingIP's Service is updated.
bash "$ROOT/test/wireguard-client-provider.sh" "$NS" "$REPORT" --watch & PROVIDER_PID=$!
for index in $(seq 1 "$COUNT"); do
  client="cozyplane-wgc-$RUN_ID-$index"; CLIENT_NAMES+=("$client")
  docker run -d --name "$client" --label cozyplane.test=wireguard-client --cap-add NET_ADMIN --network kind "$BENCH_IMAGE" >/dev/null
  client_exec "$index" sh -c 'umask 077; wg genkey > /run/client.key'
  public=$(client_exec "$index" sh -c 'wg pubkey < /run/client.key')
  refs='[{name: site-a}, {name: site-b}, {name: site-v6}]'; [[ "$index" != 2 ]] || refs='[{name: site-a}]'
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: client-$index}
spec:
  gatewayRef: {name: gateway}
  wireguard:
    peerPublicKey: "$public"
    client: {addressPools: [clients-v4, clients-v6], vpcRefs: $refs}
EOF
done
for index in $(seq 1 "$COUNT"); do wait_for "client-$index current configuration applied" configured "$index"; done
"${K[@]}" -n "$NS" get vpnconnections -o json | jq '[.items[].status.assignedAddresses[]] | length == (unique|length)' -e >/dev/null && pass 'all IPv4/IPv6 allocations unique' || fail 'duplicate allocation'
A=$(ip_for server-a); B=$(ip_for server-b); C=$(ip_for server-c)
V6=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-v6" -o json | jq -r '[.items[].spec.ip | select(contains(":"))][0]')
[[ "$A" != null && "$B" != null && "$C" != null ]] || { fail 'missing VPC addresses'; exit 1; }
for index in $(seq 1 "$COUNT"); do
  config=$("${K[@]}" -n "$NS" get vpnconnection "client-$index" -o json)
  endpoint=$(jq -r '.status.clientConfig.endpoint' <<<"$config")
  key=$(jq -r '.status.clientConfig.serverPublicKey' <<<"$config")
  mtu=$(jq -r '.status.clientConfig.mtu' <<<"$config")
  if [[ ! "$mtu" =~ ^[0-9]+$ ]] || ((mtu < 1280 || mtu > 9000)); then
    fail "client-$index public MTU is unusable for its dual-stack profile ($mtu)"; exit 1
  fi
  allowed=$(jq -r '.status.clientConfig.allowedIPs | join(",")' <<<"$config")
  client_exec "$index" ip route add "$FIP/32" via "$NODE_IP"
  client_exec "$index" ip link add wg0 type wireguard
  client_exec "$index" wg set wg0 private-key /run/client.key peer "$key" endpoint "$endpoint" allowed-ips "$allowed" persistent-keepalive 5
  while read -r address; do
    if [[ "$address" == *:* ]]; then prefix=128; else prefix=32; fi
    client_exec "$index" ip addr add "$address/$prefix" dev wg0
  done < <(jq -r '.status.assignedAddresses[]' <<<"$config")
  client_exec "$index" ip link set wg0 mtu "$mtu" up
  while read -r prefix; do client_exec "$index" ip route add "$prefix" dev wg0; done < <(jq -r '.status.clientConfig.allowedIPs[]' <<<"$config")
done
wait_for 'real client tunnel reaches site-a over FloatingIP' http 1 "$A"
[[ "$(http 1 "$B")" == site-b ]] && pass 'client-1 reaches second authorized VPC' || fail 'second VPC unreachable'
[[ "$(http 2 "$A")" == site-a ]] && pass 'restricted client reaches its VPC' || fail 'restricted client unreachable'
[[ "$V6" != null && "$(http 1 "[$V6]")" == site-v6 ]] && pass 'IPv6 VPC application traffic succeeds' || fail 'IPv6 VPC unreachable'
client_exec 1 iperf3 -6 -c "$V6" -p 5201 -t 10 -J > "$REPORT/ipv6-tcp.json" || fail 'IPv6 TCP transfer failed'
mtu=$(client_exec 1 cat /sys/class/net/wg0/mtu)
client_exec 1 ping -M 'do' -s "$((mtu-28))" -c 3 -W 3 "$A" > "$REPORT/mtu-v4-ping.txt" && pass 'IPv4 packets fit advertised MTU' || fail 'IPv4 advertised MTU fails'
client_exec 1 ping -6 -M 'do' -s "$((mtu-48))" -c 3 -W 3 "$V6" > "$REPORT/mtu-v6-ping.txt" && pass 'IPv6 packets fit advertised MTU' || fail 'IPv6 advertised MTU fails'
client_exec 1 timeout -k 2 8 tcpdump -n -i eth0 -c 1 'net 10.250.0.0/16 or net fd42:250::/32' > "$REPORT/cleartext-probe.txt" 2>&1 & sniff_pid=$!
sleep 1
for _ in 1 2 3; do http 1 "$A" >/dev/null; http 1 "[$V6]" >/dev/null; done
wait "$sniff_pid" || true
# tcpdump handles TERM and may exit successfully with zero captured packets;
# inspect its own capture counters rather than assuming GNU timeout's exit code.
if grep -q '0 packets captured' "$REPORT/cleartext-probe.txt" && ! grep -q ' > ' "$REPORT/cleartext-probe.txt"; then
  pass 'transport capture contains no cleartext tenant packet'
else fail 'cleartext packet detected or transport capture instrumentation failed'; fi
# Deliberately widen client AllowedIPs and routes: server enforcement must prevail.
server_key=$(client_exec 2 wg show wg0 peers)
client_exec 2 wg set wg0 peer "$server_key" allowed-ips 10.250.0.0/16,fd42:250::/32
client_exec 2 ip route add 10.250.2.0/24 dev wg0
client_exec 2 ip route add 10.250.3.0/24 dev wg0
client_exec 2 ip -6 route add fd42:250:1::/64 dev wg0
http 2 "$B" >/dev/null 2>&1 && fail 'unauthorized served VPC reachable' || pass 'unauthorized served VPC rejected after route widening'
http 2 "$C" >/dev/null 2>&1 && fail 'forbidden VPC reachable' || pass 'forbidden VPC rejected'
http 2 "[$V6]" >/dev/null 2>&1 && fail 'unauthorized IPv6 VPC reachable' || pass 'unauthorized IPv6 VPC rejected'
appliance_port=$("${K[@]}" -n "$NS" get vpngateway gateway -o json | jq -r '.status.appliancePort')
appliance=$("${K[@]}" get port "$appliance_port" -o json)
appliance_ip=$(jq -r '.spec.ip' <<<"$appliance")
appliance_pod=$(jq -r '.spec.podName' <<<"$appliance")
# The metrics proxy proves a real listening destination before testing its denial.
metrics_ready() { "${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$appliance_pod:9410/proxy/metrics" > "$REPORT/appliance-metrics.txt"; }
wait_for 'appliance metrics listener is available to operator' metrics_ready
client_exec 1 curl --noproxy '*' -fsS -m 5 "http://$appliance_ip:9410/metrics" >/dev/null 2>&1 && fail 'appliance-local metrics reachable from workstation' || pass 'appliance-local destination rejected'
client1_ip=$("${K[@]}" -n "$NS" get vpnconnection client-1 -o json | jq -r '.status.assignedAddresses[] | select(contains(":")|not)')
"${K[@]}" -n "$NS" logs server-a | grep -qF "$client1_ip - -" && pass 'workload observes original workstation source' || fail 'workstation source was rewritten'
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: workstation-source}
spec:
  vpcRef: {name: site-a}
  podSelector: {matchLabels: {cozyplane.test/server: site-a}}
EOF
sleep 5
http 1 "$A" >/dev/null 2>&1 && fail 'SecurityGroup default deny bypassed' || pass 'SecurityGroup default deny applied to workstation'
"${K[@]}" -n "$NS" patch securitygroup workstation-source --type=merge -p "{\"spec\":{\"ingress\":[{\"from\":{\"cidr\":\"$client1_ip/32\"},\"ports\":[{\"protocol\":\"TCP\",\"port\":8080}]}]}}" >/dev/null
wait_for 'SecurityGroup permits exact workstation source' http 1 "$A"
http 2 "$A" >/dev/null 2>&1 && fail 'SecurityGroup accepted different workstation source' || pass 'SecurityGroup denies nonmatching workstation source'
"${K[@]}" -n "$NS" delete securitygroup workstation-source >/dev/null
wait_for 'workstation access restored after SecurityGroup removal' http 2 "$A"
client_exec 1 wg set wg0 listen-port 55001
wait_for 'server learns changed workstation UDP endpoint' http 1 "$A"
client2_ip=$("${K[@]}" -n "$NS" get vpnconnection client-2 -o json | jq -r '.status.assignedAddresses[] | select(contains(":")|not)')
client1_server_key=$(client_exec 1 wg show wg0 peers)
# Both ends deliberately accept the pool so client-side AllowedIPs cannot mask
# a server-side inter-client policy bypass.
client_exec 1 wg set wg0 peer "$client1_server_key" allowed-ips '10.250.1.0/24,10.250.2.0/24,10.250.100.0/24,fd42:250:1::/64'
client_exec 1 ip route add "$client2_ip/32" dev wg0
client_exec 2 ip route add "$client1_ip/32" dev wg0
client_exec 2 ping -c 2 -W 2 "$client1_ip" >/dev/null 2>&1 && fail 'inter-client traffic accepted' || pass 'inter-client traffic rejected'
client_exec 2 ip addr add 10.250.100.240/32 dev wg0
client_exec 2 curl --interface 10.250.100.240 --noproxy '*' -fsS -m 5 "http://$A:8080" >/dev/null 2>&1 && fail 'spoofed source accepted' || pass 'spoofed source rejected by WireGuard'
client_exec 2 ip addr del 10.250.100.240/32 dev wg0
client_exec 1 ip -6 addr add fd42:250:100::ffff/128 dev wg0
client_exec 1 curl --interface fd42:250:100::ffff --noproxy '*' -fsS -m 5 "http://[$V6]:8080" >/dev/null 2>&1 && fail 'spoofed IPv6 source accepted' || pass 'spoofed IPv6 source rejected by WireGuard'
client_exec 1 ip -6 addr del fd42:250:100::ffff/128 dev wg0
egress_server="cozyplane-wgc-$RUN_ID-egress"
docker run -d --name "$egress_server" --label cozyplane.test=wireguard-client --network kind "$BENCH_IMAGE" sh -c 'mkdir -p /tmp/web; echo external-test > /tmp/web/index.html; cd /tmp/web; exec python3 -m http.server 8080' >/dev/null
CLIENT_NAMES+=("$egress_server")
egress_ip=$(docker inspect "$egress_server" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
external_up() { curl --noproxy '*' -fsS -m 3 "http://$egress_ip:8080/" | grep -qx external-test; }
wait_for 'controlled non-VPC destination is actually listening' external_up
client_exec 2 wg set wg0 peer "$server_key" allowed-ips "10.250.0.0/16,fd42:250::/32,$egress_ip/32"
client_exec 2 ip route add "$egress_ip/32" dev wg0
http 2 "$egress_ip" >/dev/null 2>&1 && fail 'non-VPC destination reachable through tunnel' || pass 'non-VPC destination rejected after route widening'
underlay=$(docker inspect cozyplane-wg-client-control-plane -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
underlay_code=$(curl --noproxy '*' -ksS --connect-timeout 3 --max-time 5 -o /dev/null -w '%{http_code}' "https://$underlay:6443/version")
[[ "$underlay_code" =~ ^(200|401|403)$ ]] && pass 'underlay API positive control responds' || { fail 'underlay API instrumentation failed'; exit 1; }
client_exec 2 wg set wg0 peer "$server_key" allowed-ips "10.250.0.0/16,fd42:250::/32,$egress_ip/32,$underlay/32"
client_exec 2 ip route add "$underlay/32" dev wg0
client_exec 2 curl --noproxy '*' -ksS --connect-timeout 3 --max-time 5 -o /dev/null "https://$underlay:6443/version" && fail 'underlay API reachable through tunnel' || pass 'underlay API rejected after route widening'
client_exec 2 ip route del "$underlay/32" dev wg0
sample() {
  local title="$1" count="$2" duration="$3" protocol="${4:-tcp}" rate="${5:-20M}"
  local pids=() n
  echo "MEASURE: $title clients=$count seconds=$duration protocol=$protocol"
  for n in $(seq 1 "$count"); do
    args=(-c "$A" -p "$((5200+n))" -t "$duration" -J)
    [[ "$protocol" != udp ]] || args+=(-u -b "$rate")
    client_exec "$n" timeout -k 5 "$((duration+60))" iperf3 "${args[@]}" > "$REPORT/$title-client$n.json" & pids+=("$!")
  done
  client_exec 1 ping -i .2 -w "$duration" "$A" > "$REPORT/$title-ping.txt" & pids+=("$!")
  for pid in "${pids[@]}"; do wait "$pid" || fail "$title traffic command failed"; done
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' "${CLIENT_NAMES[@]}" cozyplane-wg-client-worker cozyplane-wg-client-worker2 >> "$REPORT/resources.txt"
  "${K[@]}" -n "$NS" get pods -o json | jq '[.items[] | {name:.metadata.name,phase:.status.phase,restarts:[.status.containerStatuses[]?.restartCount]}]' >> "$REPORT/pods.jsonl"
  "${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json | jq '[.items[] | {name:.metadata.name,images:[.status.containerStatuses[]?.imageID]}]' >> "$REPORT/image-digests.jsonl"
}
if [[ "${RUN_LOAD:-1}" == 1 ]]; then
  for n in 1 8 16; do
    ((n <= COUNT)) || continue
    for repetition in 1 2 3; do sample "tcp-$n-$repetition" "$n" "$SECONDS_PER_SAMPLE"; done
  done
  # Calibrate total UDP to a quarter of observed single TCP throughput, capped at 100 Mbit/s.
  RATE=$(python3 -c 'import json,sys; o=json.load(open(sys.argv[1])); b=o["end"]["sum_received"]["bits_per_second"]; print(max(100000,min(100000000,int(b/4))))' "$REPORT/tcp-1-1-client1.json")
  sample baseline-udp 1 "$SECONDS_PER_SAMPLE" udp "$RATE"
  for loss in 1 5 10; do
    client_exec 1 tc qdisc replace dev eth0 root netem loss "$loss%"
    sample "loss-$loss" 1 "$SECONDS_PER_SAMPLE" udp "$RATE"
    client_exec 1 tc qdisc del dev eth0 root
    [[ "$(http 1 "$A")" == site-a ]] && pass "recovery after $loss% loss" || fail "recovery after $loss% loss"
  done
  client_exec 1 tc qdisc replace dev eth0 root netem delay 100ms 20ms reorder 1% 25%
  sample delay-jitter-reorder 1 "$SECONDS_PER_SAMPLE" udp "$RATE"
  client_exec 1 tc qdisc del dev eth0 root
  client_exec 1 tc qdisc replace dev eth0 root netem loss 100%
  http 1 "$A" >/dev/null 2>&1 && fail '100% cut did not cut transport' || pass 'transport cut enforced'
  sleep 30
  client_exec 1 tc qdisc del dev eth0 root
  wait_for 'automatic recovery after 30-second cut' http 1 "$A"
  sample soak "$COUNT" "$SOAK_SECONDS"
fi
"${K[@]}" -n "$NS" rollout restart deployment/gateway-vpn >/dev/null
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
wait_for 'automatic recovery after appliance restart' http 1 "$A"
# Rotate the workstation key in its own netns; the old private key never leaves it.
client_exec 1 sh -c 'umask 077; wg genkey > /run/rotated.key'
rotated_public=$(client_exec 1 sh -c 'wg pubkey < /run/rotated.key')
"${K[@]}" -n "$NS" patch vpnconnection client-1 --type=merge -p "{\"spec\":{\"wireguard\":{\"peerPublicKey\":\"$rotated_public\"}}}" >/dev/null
wait_for 'rotated workstation key applied' configured 1
http 1 "$A" >/dev/null 2>&1 && fail 'retired workstation key remains usable' || pass 'retired workstation key revoked'
client_exec 1 wg set wg0 private-key /run/rotated.key
wait_for 'rotated workstation key reaches VPC' http 1 "$A"
"${K[@]}" -n "$NS" patch vpngateway gateway --type=merge -p '{"spec":{"ha":{"mode":"WarmStandby"}}}' >/dev/null
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
standby_ready() {
  "${K[@]}" -n "$NS" get deployment gateway-vpn -o json | jq -e '.spec.replicas==2 and .status.readyReplicas==2 and .status.updatedReplicas==2 and .status.observedGeneration>=.metadata.generation' >/dev/null || return 1
  "${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json | jq -e '.items|length==2 and all(.[]; .metadata.deletionTimestamp==null and any(.status.conditions[]?; .type=="Ready" and .status=="True"))' >/dev/null || return 1
  configured 1
}
wait_for 'both WarmStandby appliances Ready with current client configuration' standby_ready
wait_for 'WarmStandby tunnel works' http 1 "$A"
selected_port=$("${K[@]}" -n "$NS" get vpngateway gateway -o json | jq -r '.status.appliancePort // empty')
selected=$("${K[@]}" get port "$selected_port" -o json | jq -r '.spec.podName // empty')
if [[ -n "$selected" ]]; then
  "${K[@]}" -n "$NS" delete pod "$selected" --wait=true --timeout=90s >/dev/null
  wait_for 'WarmStandby recovery after selected appliance loss' http 1 "$A"
else
  # Restart both deployment-managed pods; this still proves standby config loads.
  "${K[@]}" -n "$NS" rollout restart deployment/gateway-vpn >/dev/null
  "${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
  wait_for 'WarmStandby restart recovery' http 1 "$A"
fi
"${K[@]}" -n "$NS" patch vpnconnection client-1 --type=merge -p '{"spec":{"wireguard":{"client":{"vpcRefs":[{"name":"site-a"}]}}}}' >/dev/null
wait_for 'reduced rights applied' configured 1
http 1 "$B" >/dev/null 2>&1 && fail 'removed VPC right remains usable' || pass 'removed VPC right revoked'
wait_for 'remaining VPC access preserved' http 1 "$A"
"${K[@]}" -n "$NS" delete vpnconnection client-2 --wait=true --timeout=300s >/dev/null
http 2 "$A" >/dev/null 2>&1 && fail 'deleted client remains usable' || pass 'deleted client revoked'
((FAILED == 0)) || exit 1
pass 'WireGuard workstation suite completed'
