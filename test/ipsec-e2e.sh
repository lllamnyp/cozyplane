#!/usr/bin/env bash
# Native strongSwan site-to-site peers against the dedicated product fixture.
# Credentials are generated only at runtime, never printed or copied to reports.
# shellcheck disable=SC2015
set -euo pipefail
[[ "${KCTX:-}" == kind-cozyplane-ipsec-test ]] || exit 2
K=(kubectl --context "$KCTX")
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-cozyplane-ipsec:local}"
BENCH_IMAGE=cozyplane-ipsec-test-bench:local
RUN_ID="$(date +%s)-$$"; NS="ipsec-test-$RUN_ID"
REPORT="/tmp/cozyplane-ipsec-test/results-$RUN_ID"
PRIVATE="/tmp/cozyplane-ipsec-test/private-$RUN_ID"
mkdir -p "$REPORT" "$PRIVATE"; chmod 700 "$REPORT" "$PRIVATE"
printf '%s\n' ipsec > "$REPORT/backend.txt"
COUNT="${CLIENTS:-16}"
[[ "$COUNT" =~ ^[0-9]+$ ]] && ((COUNT>=2 && COUNT<=16)) || exit 2
FAILED=0; CLIENT_NAMES=(); PROVIDER_PID=''; MONITOR_PID=''
pass() { echo "PASS: $*" | tee -a "$REPORT/checks.log"; }
fail() { echo "FAIL: $*" | tee -a "$REPORT/checks.log" >&2; FAILED=1; }
cleanup() {
  local exit_status=$?
  jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" --argjson exitCode "$exit_status" '{timestamp:$timestamp,exitCode:$exitCode}' > "$REPORT/harness-exit.json"
  for pid in "$PROVIDER_PID" "$MONITOR_PID"; do [[ -z "$pid" ]] || kill "$pid" 2>/dev/null || true; done
  for name in "${CLIENT_NAMES[@]}"; do docker rm -f "$name" >/dev/null 2>&1 || true; done
  rm -rf -- "$PRIVATE"
  python3 "$ROOT/test/wireguard-client-report.py" "$REPORT" || true
  [[ "${KEEP:-0}" == 1 ]] || "${K[@]}" delete namespace "$NS" --wait=false >/dev/null 2>&1 || true
  echo "Test report: $REPORT; namespace: $NS"
}
trap cleanup EXIT
# shellcheck source=test/ipsec-probes.sh
source "$ROOT/test/ipsec-probes.sh"
# shellcheck source=test/ipsec-auth-negative.sh
source "$ROOT/test/ipsec-auth-negative.sh"
# shellcheck source=test/ipsec-protocol.sh
source "$ROOT/test/ipsec-protocol.sh"
wait_for() {
  local description="$1"; shift; local deadline=$((SECONDS+300))
  while ((SECONDS<deadline)); do if "$@"; then pass "$description"; return; fi; sleep 2; done
  fail "$description timed out"; return 1
}
client_exec() { local index="$1"; shift; docker exec "${CLIENT_NAMES[$((index-1))]}" "$@"; }
http() { client_exec "$1" curl -fsS --noproxy '*' --connect-timeout 2 --max-time 4 "http://$2:8080/"; }
ip_for() { "${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=$1" -o json | jq -r '[.items[].spec.ip | select(contains(":")|not)][0]'; }
selected_pod() { local port; port=$("${K[@]}" -n "$NS" get vpngateway gateway -o jsonpath='{.status.appliancePort}'); "${K[@]}" get port "$port" -o jsonpath='{.spec.podName}'; }
initiate() { client_exec "$1" swanctl --initiate --child "peer-$1" --timeout 30 >/dev/null 2>&1; }
config_checksum() { "${K[@]}" -n "$NS" get deployment gateway-vpn -o json | jq -r '.spec.template.metadata.annotations["sdn.cozystack.io/vpn-config-checksum"] // empty'; }
current_configured() {
  local desired checksum pod status pods deployment
  deployment=$("${K[@]}" -n "$NS" get deployment gateway-vpn -o json)
  jq -e '.status.observedGeneration>=.metadata.generation and .status.updatedReplicas==.spec.replicas and .status.readyReplicas==.spec.replicas' <<<"$deployment" >/dev/null || return 1
  desired=$(jq -r '.spec.replicas' <<<"$deployment")
  checksum=$(jq -r '.spec.template.metadata.annotations["sdn.cozystack.io/vpn-config-checksum"] // empty' <<<"$deployment")
  [[ "$checksum" =~ ^[0-9a-f]{64}$ ]] || return 1
  pods=$("${K[@]}" -n "$NS" get pods -l sdn.cozystack.io/vpn-gateway=gateway -o json)
  jq -e --arg checksum "$checksum" --argjson desired "$desired" '.items|length==$desired and all(.[];.metadata.deletionTimestamp==null and .metadata.annotations["sdn.cozystack.io/vpn-config-checksum"]==$checksum and any(.status.conditions[]?;.type=="Ready" and .status=="True"))' <<<"$pods" >/dev/null || return 1
  for pod in $(jq -r '.items[].metadata.name' <<<"$pods"); do
    status=$("${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$pod:9410/proxy/status") || return 1
    jq -e --arg checksum "$checksum" '.backend=="ipsec" and .configChecksum==$checksum' <<<"$status" >/dev/null || return 1
  done
}
config_changed() { [[ "$(config_checksum)" != "$1" ]] && current_configured; }
{
 date -u +'%Y-%m-%dT%H:%M:%SZ'; git -C "$ROOT" rev-parse HEAD 2>/dev/null || cat /tmp/cozyplane-ipsec-test/source-revision.txt
 docker image inspect "$IMAGE" --format '{{.Id}}'; uname -r; go version
} > "$REPORT/environment.txt"
kind load docker-image "$BENCH_IMAGE" --name cozyplane-ipsec-test >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
"${K[@]}" label namespace "$NS" pod-security.kubernetes.io/enforce=privileged >/dev/null
for site in a b c v6; do
  case "$site" in a) CIDR=10.250.1.0/24; NODE=cozyplane-ipsec-test-worker;;
    b) CIDR=10.250.2.0/24; NODE=cozyplane-ipsec-test-worker2;;
    c) CIDR=10.250.3.0/24; NODE=cozyplane-ipsec-test-worker2;;
    v6) CIDR=fd42:250:1::/64; NODE=cozyplane-ipsec-test-worker2;; esac
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
if [[ "${ROADWARRIOR:-0}" == 1 ]]; then
  # shellcheck source=test/ipsec-roadwarrior.sh
  source "$ROOT/test/ipsec-roadwarrior.sh"
  ((FAILED==0)) || exit 1
  exit 0
fi
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {name: gateway}
spec:
  vpcRef: {name: site-a}
  additionalVPCRefs: [{name: site-b}, {name: site-v6}]
  ipsec: {proposals: [aes256-sha256-modp2048]}
EOF
"${K[@]}" -n "$NS" wait --for=create deployment/gateway-vpn --timeout=180s
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
bash "$ROOT/test/wireguard-client-provider.sh" "$NS" "$REPORT" --watch & PROVIDER_PID=$!
endpoint_ready() { FIP=$("${K[@]}" -n "$NS" get vpngateway gateway -o jsonpath='{.status.address}'); [[ -n "$FIP" ]]; }
wait_for 'IPSec FloatingIP assigned by isolated fixture provider' endpoint_ready
NODE_IP=$(docker inspect cozyplane-ipsec-test-worker -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
for index in $(seq 1 "$COUNT"); do
  client="cozyplane-ipsec-peer-$RUN_ID-$index"; CLIENT_NAMES+=("$client")
  docker run -d --name "$client" --label cozyplane.test=ipsec --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 --network kind "$BENCH_IMAGE" >/dev/null
  cp "$ROOT/test/ipsec-peer.py" "$PRIVATE/peer.py"
  docker cp "$PRIVATE/peer.py" "$client:/run/peer.py" >/dev/null
  umask 077; openssl rand -hex 32 | tr -d '\n' > "$PRIVATE/psk-$index"
  "${K[@]}" -n "$NS" create secret generic "peer-$index-psk" --from-file="psk=$PRIVATE/psk-$index" >/dev/null
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: peer-$index}
spec:
  gatewayRef: {name: gateway}
  remoteCIDRs: ["10.250.100.$index/32", "fd42:250:100::$index/128"]
  ipsec:
    remoteIdentity: peer-$index.example.invalid
    auth: {pskSecretRef: peer-$index-psk}
    proposals: [aes256-sha256-modp2048]
    dpdDelay: 5
    startAction: None
EOF
  jq -nc --arg name "peer-$index" --arg endpoint "$FIP" --arg node "$NODE_IP" --arg identity "peer-$index.example.invalid" --arg ipv4 "10.250.100.$index" --arg ipv6 "fd42:250:100::$index" --rawfile psk "$PRIVATE/psk-$index" '{name:$name,endpoint:$endpoint,node:$node,identity:$identity,ipv4:$ipv4,ipv6:$ipv6,psk:$psk}' |
    docker exec -i "$client" python3 /run/peer.py
done
routes_ready() {
  "${K[@]}" -n "$NS" get vpngateway gateway -o json | jq -e --argjson count "$COUNT" '[.status.routes[]? | select(.port!=null and .port!="")]|length>=($count*3)' >/dev/null
}
wait_for 'all managed source routes materialized in three served VPCs' routes_ready
"${K[@]}" -n "$NS" rollout status deployment/gateway-vpn --timeout=300s
[[ "${REQUIRE_CONFIG_ACK:-1}" != 1 ]] || wait_for 'all Ready appliances acknowledge exact desired config checksum' current_configured
for index in $(seq 1 "$COUNT"); do
  wait_for "native IKEv2/CHILD peer-$index established" initiate "$index"
  ((index!=1)) || preflight_actual_sa "$index"
done
A=$(ip_for server-a); B=$(ip_for server-b); C=$(ip_for server-c)
V6=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-v6" -o json | jq -r '[.items[].spec.ip | select(contains(":"))][0]')
wait_for 'real IPSec peer reaches first VPC via FloatingIP' http 1 "$A"
[[ "$(http 1 "$B")" == site-b ]] && pass 'IPSec reaches second served VPC' || fail 'second VPC unreachable'
[[ "$(http 1 "[$V6]")" == site-v6 ]] && pass 'IPSec IPv6 application traffic succeeds' || fail 'IPv6 unreachable'
openssl rand -hex 32 | tr -d '\n' > "$PRIVATE/bad-psk"
set_client_secret 1 "$PRIVATE/bad-psk"
negative_auth 1 2 bad-psk "$A"
set_client_secret 1 "$PRIVATE/psk-1"
load_client 1
wait_for 'correct PSK restores authentication after negative control' initiate 1
wait_for 'correct PSK restores actual traffic' http 1 "$A"
client_exec 1 iperf3 -6 -c "$V6" -p 5201 -t 10 -J > "$REPORT/ipv6-tcp.json" || fail 'IPv6 TCP transfer'
client_exec 1 ping -M 'do' -s 1252 -c 3 -W 3 "$A" > "$REPORT/mtu-v4-ping.txt" && pass 'IPv4 MTU1280' || fail 'IPv4 MTU1280'
client_exec 1 ping -6 -M 'do' -s 1232 -c 3 -W 3 "$V6" > "$REPORT/mtu-v6-ping.txt" && pass 'IPv6 MTU1280' || fail 'IPv6 MTU1280'
client_exec 1 timeout -k 2 8 tcpdump -n -i eth0 -c 1 'net 10.250.0.0/16 or net fd42:250::/32' > "$REPORT/cleartext-probe.txt" 2>&1 & sniff_pid=$!
sleep 1; http 1 "$A" >/dev/null; http 1 "[$V6]" >/dev/null; wait "$sniff_pid" || true
grep -q '0 packets captured' "$REPORT/cleartext-probe.txt" && ! grep -q ' > ' "$REPORT/cleartext-probe.txt" && pass 'no cleartext tenant packet on transport' || fail 'cleartext or instrumentation error'
client_exec 1 timeout -k 2 8 tcpdump -n -i eth0 -c 1 'udp port 4500 or ip proto 50' > "$REPORT/encrypted-transport.txt" 2>&1 & sniff_pid=$!
sleep 1; http 1 "$A" >/dev/null; wait "$sniff_pid" || true
grep -q '1 packet captured' "$REPORT/encrypted-transport.txt" && pass 'outer transport capture observes actual encrypted tunnel traffic' || fail 'encrypted transport positive capture missing'
forbidden_control=$("${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/server-c:8080/proxy/")
[[ "$forbidden_control" == site-c ]] && pass 'forbidden VPC listener positive operator control' || { fail 'forbidden listener control'; exit 1; }
http 1 "$C" >/dev/null 2>&1 && fail 'forbidden VPC reachable' || pass 'forbidden unserved VPC rejected with broad selectors'
for family in 4 6; do
  if [[ "$family" == 4 ]]; then source=10.250.100.240; address=$A; else source=fd42:250:100::ffff; address="[$V6]"; fi
  client_exec 1 ip "-$family" addr add "$source/$([[ "$family" == 4 ]] && echo 32 || echo 128)" dev ipsec0
  client_exec 1 curl --interface "$source" --noproxy '*' -fsS -m 4 "http://$address:8080/" >/dev/null 2>&1 && fail "IPv$family spoofed source accepted" || pass "IPv$family spoofed source rejected"
  client_exec 1 ip "-$family" addr del "$source/$([[ "$family" == 4 ]] && echo 32 || echo 128)" dev ipsec0
done
probe_local_destinations 1 4
probe_local_destinations 1 6
"${K[@]}" -n "$NS" logs server-a | grep -qF '10.250.100.1 - -' && pass 'original site source preserved' || fail 'site source rewritten'
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: site-source}
spec:
  vpcRef: {name: site-a}
  podSelector: {matchLabels: {cozyplane.test/server: site-a}}
EOF
sg_denied() { ! http 1 "$A" >/dev/null 2>&1; }
wait_for 'SG default deny applies after known positive access' sg_denied
"${K[@]}" -n "$NS" patch securitygroup site-source --type=merge -p '{"spec":{"ingress":[{"from":{"cidr":"10.250.100.1/32"},"ports":[{"protocol":"TCP","port":8080}]}]}}' >/dev/null
wait_for 'SG exact site source allowed' http 1 "$A"
http 2 "$A" >/dev/null 2>&1 && fail 'SG nonmatching peer accepted' || pass 'SG nonmatching peer denied'
"${K[@]}" -n "$NS" delete securitygroup site-source >/dev/null
wait_for 'peer2 restored after SG removal' http 2 "$A"
for index in 1 2; do
  client_exec "$index" sh -c 'mkdir -p /run/web; echo peer-positive > /run/web/index.html; cd /run/web; python3 -m http.server 8080 --bind :: >/run/web.log 2>&1 &'
  wait_for "peer-$index listener positive control" client_exec "$index" curl --noproxy '*' -fsS -m 3 http://127.0.0.1:8080/
done
http 1 10.250.100.2 >/dev/null 2>&1 && fail 'inter-peer transit permitted outside served VPCs' || pass 'inter-peer transit rejected outside served VPCs'
FIXTURE_CLUSTER=cozyplane-ipsec-test python3 "$ROOT/test/wireguard-client-monitor.py" "$NS" "$$" "$REPORT" & MONITOR_PID=$!
# shellcheck source=test/ipsec-measure.sh
source "$ROOT/test/ipsec-measure.sh"
if [[ "${RUN_LIFECYCLE:-0}" == 1 ]]; then
  # shellcheck source=test/ipsec-lifecycle.sh
  source "$ROOT/test/ipsec-lifecycle.sh"
fi
((FAILED==0)) || exit 1
pass 'IPSec site-to-site smoke finished'
