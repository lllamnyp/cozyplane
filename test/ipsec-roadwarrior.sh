#!/usr/bin/env bash
# Sourced after shared VPC/server fixtures by ipsec-e2e.sh. Eight real peers:
# certificate and EAP-MSCHAPv2, each with two IPv4 and two IPv6 pool consumers.
# PROVIDER_PID is consumed by its parent's exit trap.
# shellcheck disable=SC2153,SC2154,SC2015,SC2034
((COUNT==8)) || { fail 'roadwarrior suite requires CLIENTS=8'; exit 2; }
# shellcheck source=test/ipsec-roadwarrior-vip.sh
source "$ROOT/test/ipsec-roadwarrior-vip.sh"
python3 "$ROOT/test/ipsec-snapshot.py" "$ROOT" "$REPORT" roadwarrior ipsec-e2e.sh ipsec-roadwarrior.sh ipsec-roadwarrior-vip.sh ipsec-vip-public.py ipsec-peer.py ipsec-probes.sh ipsec-auth-negative.sh ipsec-protocol.sh ipsec-spoof-policy.py ipsec-sa-public.py ipsec-eap-cross.py
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=Fixture-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$PRIVATE/ca.key" -out "$PRIVATE/ca.crt" 2>/dev/null
issue_certificate() {
  local identity="$1" name="$2" issuer="${3:-ca}"
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$identity" -keyout "$PRIVATE/$name.key" -out "$PRIVATE/$name.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature\n' "$identity" > "$PRIVATE/$name.ext"
  openssl x509 -req -in "$PRIVATE/$name.csr" -CA "$PRIVATE/$issuer.crt" -CAkey "$PRIVATE/$issuer.key" -CAcreateserial -days 2 -extfile "$PRIVATE/$name.ext" -out "$PRIVATE/$name.crt" 2>/dev/null
}
issue_certificate gateway.example.invalid gateway
"${K[@]}" -n "$NS" create secret generic ike-tls --type=kubernetes.io/tls --from-file="tls.crt=$PRIVATE/gateway.crt" --from-file="tls.key=$PRIVATE/gateway.key" --from-file="ca.crt=$PRIVATE/ca.crt" >/dev/null
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {name: gateway}
spec:
  vpcRef: {name: site-a}
  additionalVPCRefs: [{name: site-b}, {name: site-v6}]
  ipsec:
    proposals: [aes256-sha256-modp2048]
    credentialSecretRef: ike-tls
    localIdentity: gateway.example.invalid
    addressPools:
    - {name: clients-v4, cidr: 10.250.150.0/24}
    - {name: clients-v6, cidr: "fd42:250:150::/120"}
EOF
"${K[@]}" -n "$NS" wait --for=create deployment/gateway-vpn --timeout=180s
bash "$ROOT/test/wireguard-client-provider.sh" "$NS" "$REPORT" --watch & PROVIDER_PID=$!
endpoint_ready() { FIP=$("${K[@]}" -n "$NS" get vpngateway gateway -o jsonpath='{.status.address}'); [[ -n "$FIP" ]]; }
wait_for 'roadwarrior FloatingIP assigned by isolated provider' endpoint_ready
NODE_IP=$(docker inspect cozyplane-ipsec-test-worker -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
openssl rand -hex 32 | tr -d '\n' > "$PRIVATE/pool-psk-denied"
"${K[@]}" -n "$NS" create secret generic pool-psk-denied --from-file="psk=$PRIVATE/pool-psk-denied" >/dev/null
pool_psk_result=0
pool_psk_output=$("${K[@]}" -n "$NS" create -f - 2>&1 <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: pool-psk-denied}
spec:
  gatewayRef: {name: gateway}
  ipsec:
    remoteIdentity: pool-psk.example.invalid
    auth: {pskSecretRef: pool-psk-denied}
    addressPool: clients-v4
    startAction: None
EOF
) || pool_psk_result=$?
printf '%s\n' "$pool_psk_output" > "$REPORT/psk-pool-api-rejection.txt"
((pool_psk_result!=0)) && grep -q 'an address pool requires certificate or EAP authentication' <<<"$pool_psk_output" && pass 'PSK roadwarrior with pool explicitly rejected by actual API' || { fail 'unsupported PSK pool mode was not rejected explicitly'; "${K[@]}" -n "$NS" delete vpnconnection pool-psk-denied --ignore-not-found >/dev/null; }
for index in $(seq 1 "$COUNT"); do
  mode=certificate; ((index%4==3 || index%4==0)) && mode=eap
  family=4; pool=clients-v4; ((index<=4)) || { family=6; pool=clients-v6; }
  identity="peer-$index.example.invalid"
  client="cozyplane-ipsec-peer-$RUN_ID-$index"; CLIENT_NAMES+=("$client")
  docker run -d --name "$client" --label cozyplane.test=ipsec --cap-add NET_ADMIN --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 --network kind "$BENCH_IMAGE" >/dev/null
  docker cp "$ROOT/test/ipsec-peer.py" "$client:/run/peer.py" >/dev/null
  docker cp "$ROOT/test/ipsec-vip-public.py" "$client:/run/ipsec-vip-public.py" >/dev/null
  if [[ "$mode" == certificate ]]; then
    issue_certificate "$identity" "peer-$index"
    auth="certificate: {remoteIdentity: $identity}"
    jq -nc --arg name "peer-$index" --arg mode "$mode" --argjson family "$family" --arg endpoint "$FIP" --arg node "$NODE_IP" --arg identity "$identity" --rawfile ca "$PRIVATE/ca.crt" --rawfile certificate "$PRIVATE/peer-$index.crt" --rawfile privateKey "$PRIVATE/peer-$index.key" '{name:$name,mode:$mode,family:$family,endpoint:$endpoint,node:$node,identity:$identity,ca:$ca,certificate:$certificate,privateKey:$privateKey}' > "$PRIVATE/peer-$index.json"
  else
    openssl rand -hex 24 | tr -d '\n' > "$PRIVATE/password-$index"
    "${K[@]}" -n "$NS" create secret generic "peer-$index-eap" --from-file="password=$PRIVATE/password-$index" >/dev/null
    auth="eap: {identity: $identity, secretRef: peer-$index-eap}"
    jq -nc --arg name "peer-$index" --arg mode "$mode" --argjson family "$family" --arg endpoint "$FIP" --arg node "$NODE_IP" --arg identity "$identity" --rawfile ca "$PRIVATE/ca.crt" --rawfile password "$PRIVATE/password-$index" '{name:$name,mode:$mode,family:$family,endpoint:$endpoint,node:$node,identity:$identity,ca:$ca,password:$password}' > "$PRIVATE/peer-$index.json"
  fi
  "${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: peer-$index}
spec:
  gatewayRef: {name: gateway}
  ipsec:
    auth: {$auth}
    proposals: [aes256-sha256-modp2048]
    dpdDelay: 5
    startAction: None
    addressPool: $pool
EOF
  docker exec -i "$client" python3 /run/peer.py < "$PRIVATE/peer-$index.json"
done
wait_for 'all roadwarrior replicas acknowledge desired credentials/pools config' current_configured
assigned() { "${K[@]}" -n "$NS" get vpnconnection "peer-$1" -o json | jq -e '(.status.assignedAddresses // [])|length>0' >/dev/null; }
for index in $(seq 1 "$COUNT"); do
  wait_for "native roadwarrior peer-$index authenticates" initiate "$index"
  ((index!=1)) || preflight_actual_sa "$index"
  wait_for "roadwarrior peer-$index exposes actual assigned address" assigned "$index"
  refresh_vip "$index" initial
  client_exec "$index" swanctl --list-sas > "$REPORT/peer-$index-sas.txt"
done
A=$(ip_for server-a); B=$(ip_for server-b); C=$(ip_for server-c)
V6=$("${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=server-v6" -o json | jq -r '[.items[].spec.ip|select(contains(":"))][0]')
rw_concurrent_access() {
local context="$1" repetition index target marker
for repetition in 1 2 3; do
  pids=()
  for index in $(seq 1 "$COUNT"); do
    target=$A; marker=site-a; ((index<=4)) || { target="[$V6]"; marker=site-v6; }
    (for _ in 1 2 3 4 5; do [[ "$(http "$index" "$target")" == "$marker" ]] || exit 1; done) > "$REPORT/roadwarrior-$context-round$repetition-peer$index.txt" 2>&1 & pids+=("$!")
  done
  for index in $(seq 1 "$COUNT"); do
    wait "${pids[$((index-1))]}" && pass "roadwarrior peer-$index concurrent exact-marker access $context round$repetition" || fail "roadwarrior peer-$index concurrent shared-pool return traffic $context"
  done
done
}
rw_concurrent_access initial
for index in $(seq 1 "$COUNT"); do
  vip=$("${K[@]}" -n "$NS" get vpnconnection "peer-$index" -o json | jq -r '.status.assignedAddresses[0]')
  server='server-a'; ((index<=4)) || server='server-v6'
  "${K[@]}" -n "$NS" logs "$server" | grep -qF "$vip - -" && pass "roadwarrior peer-$index workload observes actual assigned source" || fail "roadwarrior peer-$index source address mismatch"
done
for index in 1 2 3 4; do [[ "$(http "$index" "$B")" == site-b ]] && pass "roadwarrior peer-$index second VPC" || fail 'roadwarrior second VPC'; done
[[ "$("${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/server-c:8080/proxy/")" == site-c ]] && pass 'roadwarrior forbidden VPC positive operator control' || { fail 'forbidden VPC control'; exit 1; }
http 1 "$C" >/dev/null 2>&1 && fail 'roadwarrior forbidden VPC reachable' || pass 'roadwarrior unserved VPC denied'
probe_local_destinations 1 4
probe_local_destinations 5 6
"${K[@]}" -n "$NS" get vpnconnections -o json | jq -e '[.items[].status.assignedAddresses[]]|length==8 and length==(unique|length)' >/dev/null && pass 'eight unique identity-bound actual pool allocations' || fail 'pool duplicate/missing allocations'
for pair in '1 2 4' '5 6 6'; do
  read -r attacker victim family <<<"$pair"
  spoof=$(actual_vip "$victim")
  target=$A; target_http=$A; marker=site-a
  [[ "$family" == 4 ]] || { target=$V6; target_http="[$V6]"; marker=site-v6; }
  [[ "$(http "$attacker" "$target_http")" == "$marker" && "$(http "$victim" "$target_http")" == "$marker" ]] || { fail 'pool spoof initial positive controls'; exit 1; }
  docker cp "$ROOT/test/ipsec-spoof-policy.py" "${CLIENT_NAMES[$((attacker-1))]}:/run/ipsec-spoof-policy.py" >/dev/null
  docker cp "$ROOT/test/ipsec-sa-public.py" "${CLIENT_NAMES[$((attacker-1))]}:/run/ipsec-sa-public.py" >/dev/null
  client_exec "$attacker" python3 /run/ipsec-spoof-policy.py "$spoof" "$target" > "$REPORT/pool-spoof-v$family.json" && pass "IPv$family another member source actually encrypted then rejected" || fail "IPv$family encrypted pool-source spoof evidence"
  wait_for "IPv$family attacker proper assigned source restores traffic after policy cleanup" http "$attacker" "$target_http"
  wait_for "IPv$family legitimate pool member survives source-spoof probe" http "$victim" "$target_http"
done
pool_vip=$(actual_vip 1)
"${K[@]}" -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: pool-source}
spec:
  vpcRef: {name: site-a}
  podSelector: {matchLabels: {cozyplane.test/server: site-a}}
EOF
pool_sg_denied() { ! http 1 "$A" >/dev/null 2>&1; }
wait_for 'pool SG default deny after exact-marker positive access' pool_sg_denied
"${K[@]}" -n "$NS" patch securitygroup pool-source --type=merge -p "{\"spec\":{\"ingress\":[{\"from\":{\"cidr\":\"$pool_vip/32\"},\"ports\":[{\"protocol\":\"TCP\",\"port\":8080}]}]}}" >/dev/null
wait_for 'pool SG permits exact actual assigned source VIP' http 1 "$A"
http 2 "$A" >/dev/null 2>&1 && fail 'pool SG accepted another member VIP' || pass 'pool SG denies another member VIP'
"${K[@]}" -n "$NS" delete securitygroup pool-source >/dev/null
wait_for 'other pool member restored after SG removal' http 2 "$A"
((FAILED==0)) || exit 1
aa_exit=0
aa_output=$("${K[@]}" -n "$NS" patch vpngateway gateway --type=merge -p '{"spec":{"ha":{"mode":"ActiveActive","activeActive":{"localASN":64512,"peerASN":64513,"peerAddresses":["10.250.150.240"]}}}}' 2>&1) || aa_exit=$?
printf '%s\n' "$aa_output" > "$REPORT/pool-activeactive-api-rejection.txt"
((aa_exit!=0)) && grep -q 'ActiveActive IPsec appliances do not coordinate client address leases' <<<"$aa_output" && pass 'actual API rejects ActiveActive with IPsec pools' || { fail 'ActiveActive pool guard not demonstrated'; exit 1; }
"${K[@]}" -n "$NS" patch vpngateway gateway --type=merge -p '{"spec":{"ha":{"mode":"WarmStandby"}}}' >/dev/null
rw_standby_ready() {
  "${K[@]}" -n "$NS" get deployment gateway-vpn -o json | jq -e '.spec.replicas==2 and .status.readyReplicas==2 and .status.updatedReplicas==2 and .status.observedGeneration>=.metadata.generation' >/dev/null || return 1
  current_configured
}
wait_for 'pool WarmStandby two Ready replicas with exact current configuration' rw_standby_ready
refresh_live_vips pool-warmstandby-before
rw_concurrent_access before-warm-fault
"${K[@]}" -n "$NS" get vpnconnections -o json | jq -e '[.items[].status.assignedAddresses[]]|length==8 and length==(unique|length)' >/dev/null || { fail 'pre-fault pool VIP uniqueness'; exit 1; }
selected_before=$(selected_pod)
selected_uid=$("${K[@]}" -n "$NS" get pod "$selected_before" -o jsonpath='{.metadata.uid}')
printf '%s\t%s\n' "$selected_before" "$selected_uid" > "$REPORT/pool-ha-selected-before.tsv"
date -u +'%Y-%m-%dT%H:%M:%SZ pool-selected-delete' >> "$REPORT/recovery-events.txt"
"${K[@]}" -n "$NS" delete pod "$selected_before" --wait=true --timeout=90s >/dev/null
rw_new_selected() {
  local pod uid
  pod=$(selected_pod); [[ -n "$pod" && "$pod" != "$selected_before" ]] || return 1
  uid=$("${K[@]}" -n "$NS" get pod "$pod" -o jsonpath='{.metadata.uid}')
  [[ -n "$uid" && "$uid" != "$selected_uid" ]] && current_configured
}
wait_for 'pool WarmStandby selects a different appliance UID with current acknowledgment' rw_new_selected
date -u +'%Y-%m-%dT%H:%M:%SZ pool-client-vip-refresh-start' >> "$REPORT/recovery-events.txt"
refresh_live_vips pool-warmstandby-after
date -u +'%Y-%m-%dT%H:%M:%SZ pool-client-vip-refresh-end' >> "$REPORT/recovery-events.txt"
selected_after=$(selected_pod)
printf '%s\t%s\n' "$selected_after" "$("${K[@]}" -n "$NS" get pod "$selected_after" -o jsonpath='{.metadata.uid}')" > "$REPORT/pool-ha-selected-after.tsv"
rw_concurrent_access after-warm-fault
for index in 1 2 3 4; do [[ "$(http "$index" "$B")" == site-b ]] && pass "pool WarmStandby peer-$index second VPC recovered" || fail 'pool WarmStandby second VPC leg'; done
"${K[@]}" -n "$NS" get vpnconnections -o json | jq -e '[.items[].status.assignedAddresses[]]|length==8 and length==(unique|length)' >/dev/null && pass 'pool WarmStandby eight current unique VIP allocations' || fail 'post-fault pool VIP uniqueness'
rekey_actual 2 certificate-child-rekey
refresh_vip 2 after-rekey
for index in 1 2 3 4; do wait_for "shared-pool peer-$index access survives peer2 rekey" http "$index" "$A"; done
docker cp "$ROOT/test/ipsec-eap-cross.py" "${CLIENT_NAMES[2]}:/run/ipsec-eap-cross.py" >/dev/null
jq -nc --arg ikeIdentity peer-3.example.invalid --arg eapIdentity peer-4.example.invalid --rawfile password "$PRIVATE/password-4" '{ikeIdentity:$ikeIdentity,eapIdentity:$eapIdentity,password:$password}' | docker exec -i "${CLIENT_NAMES[2]}" python3 /run/ipsec-eap-cross.py > "$REPORT/eap-cross-identity-config.json"
negative_auth 3 1 eap-cross-identity "$A"
client_exec 3 cp /run/ipsec-test/swanctl-before-cross.conf /run/ipsec-test/swanctl.conf
load_client 3
wait_for 'proper EAP identity/password restores authentication after cross-profile rejection' initiate 3
refresh_vip 3 eap-cross-restored
wait_for 'proper EAP identity restores actual pool access' http 3 "$A"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=Untrusted-Fixture-CA -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$PRIVATE/untrusted.key" -out "$PRIVATE/untrusted.crt" 2>/dev/null
issue_certificate peer-2.example.invalid peer-2-untrusted untrusted
docker cp "$PRIVATE/peer-2-untrusted.crt" "${CLIENT_NAMES[1]}:/run/ipsec-test/x509/fixture-client.pem" >/dev/null
docker cp "$PRIVATE/peer-2-untrusted.key" "${CLIENT_NAMES[1]}:/run/ipsec-test/private/fixture-client.key" >/dev/null
negative_auth 2 1 untrusted-client-ca "$A"
docker cp "$PRIVATE/peer-2.crt" "${CLIENT_NAMES[1]}:/run/ipsec-test/x509/fixture-client.pem" >/dev/null
docker cp "$PRIVATE/peer-2.key" "${CLIENT_NAMES[1]}:/run/ipsec-test/private/fixture-client.key" >/dev/null
load_client 2
wait_for 'trusted client certificate restores authentication' initiate 2
refresh_vip 2 certificate-restored
wait_for 'trusted client certificate restores actual shared-pool traffic' http 2 "$A"
old_checksum=$(config_checksum)
"${K[@]}" -n "$NS" delete vpnconnection peer-2 --wait=true --timeout=300s >/dev/null
wait_for 'deleted certificate peer configuration acknowledged' config_changed "$old_checksum"
refresh_live_vips certificate-withdrawn
wait_for 'trusted surviving peer healthy before removed certificate rejection' http 1 "$A"
http 2 "$A" >/dev/null 2>&1 && fail 'deleted certificate peer retains traffic' || pass 'deleted certificate peer denied'
client_exec 2 swanctl --terminate --ike peer-2 >/dev/null 2>&1 || true
negative_auth 2 1 deleted-certificate-peer "$A"
for index in 1 3 4; do wait_for "remaining shared-pool peer-$index recovers after withdrawal" http "$index" "$A"; done
for index in 5 6 7 8; do wait_for "IPv6 pool peer-$index survives certificate withdrawal" http "$index" "[$V6]"; done
rekey_actual 3 eap-child-rekey
refresh_vip 3 after-rekey
wait_for 'EAP actual traffic after rekey' http 3 "$A"
openssl rand -hex 24 | tr -d '\n' > "$PRIVATE/wrong-password"
set_client_secret 3 "$PRIVATE/wrong-password"
negative_auth 3 1 wrong-eap-password "$A"
set_client_secret 3 "$PRIVATE/password-3"
load_client 3
wait_for 'correct EAP password restores actual authentication' initiate 3
refresh_vip 3 eap-restored
wait_for 'correct EAP password restores actual traffic' http 3 "$A"
old_checksum=$(config_checksum)
"${K[@]}" -n "$NS" delete vpnconnection peer-3 --wait=true --timeout=300s >/dev/null
wait_for 'deleted EAP peer configuration acknowledged' config_changed "$old_checksum"
refresh_live_vips eap-withdrawn
wait_for 'trusted surviving peer healthy before removed EAP rejection' http 1 "$A"
http 3 "$A" >/dev/null 2>&1 && fail 'deleted EAP peer retains traffic' || pass 'deleted EAP peer denied'
client_exec 3 swanctl --terminate --ike peer-3 >/dev/null 2>&1 || true
negative_auth 3 1 deleted-eap-peer "$A"
for index in 1 4; do wait_for "shared-pool peer-$index survives EAP withdrawal" http "$index" "$A"; done
for index in 5 6 7 8; do wait_for "IPv6 pool peer-$index survives EAP withdrawal" http "$index" "[$V6]"; done
((FAILED==0)) || exit 1
pass 'Certificate/EAP IPv4/IPv6 shared-pool roadwarrior suite finished'
# shellcheck source=test/ipsec-reorder-control.sh
source "$ROOT/test/ipsec-reorder-control.sh"
