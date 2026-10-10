#!/usr/bin/env bash
# Shared real destination controls. Called only inside the isolated parent fixture.
# shellcheck disable=SC2154,SC2015
probe_local_destinations() {
  local peer="$1" family="$2" pod addresses address prefix url fabric underlay code node container pid
  pod=$(selected_pod)
  "${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$pod:9410/proxy/metrics" > "$REPORT/appliance-metrics.txt" && pass 'operator metrics positive control' || fail 'operator metrics not listening'
  addresses=$("${K[@]}" -n "$NS" exec "$pod" -- ip -j addr | jq -r --arg family "inet$([[ "$family" == 6 ]] && echo 6)" '.[]|.addr_info[]?|select(.scope=="global" and .family==$family)|.local')
  node=$("${K[@]}" -n "$NS" get pod "$pod" -o jsonpath='{.spec.nodeName}')
  container=$("${K[@]}" -n "$NS" get pod "$pod" -o json | jq -r '.status.containerStatuses[0].containerID' | sed 's#containerd://##')
  pid=$(docker exec "$node" crictl inspect "$container" | jq -r '.info.pid')
  [[ "$node" == cozyplane-ipsec-test-* && "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  for address in $addresses; do
    url="$address"; [[ "$family" == 4 ]] || url="[$address]"
    # Enter only the known appliance network namespace, keeping bench tools.
    code=$(docker run --rm --name "cozyplane-ipsec-peer-$RUN_ID-local-$peer" --label cozyplane.test=ipsec --pid="container:$node" --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt apparmor=unconfined --network none "$BENCH_IMAGE" nsenter -t "$pid" -n curl --noproxy '*' -sS -m 4 -o /dev/null -w '%{http_code}' "http://$url:9410/metrics")
    [[ "$code" != 000 && -n "$code" ]] && pass "IPv$family local address listener positive control ($address)" || { fail 'local address instrumentation failed'; return 1; }
  done
  fabric=$("${K[@]}" -n "$NS" get pod "$pod" -o json | jq -r --argjson family "$family" '.status.podIPs[]?.ip|select((contains(":") and $family==6) or ((contains(":")|not) and $family==4))')
  for address in $addresses $fabric; do
    prefix=32; url="$address"; [[ "$family" == 4 ]] || { prefix=128; url="[$address]"; }
    client_exec "$peer" ip "-$family" route replace "$address/$prefix" dev ipsec0
    code=$(client_exec "$peer" curl --noproxy '*' -sS -m 4 -o /dev/null -w '%{http_code}' "http://$url:9410/metrics" 2>/dev/null || true)
    [[ "$code" == 000 ]] && pass "IPv$family appliance local/fabric metrics denied ($address)" || fail "IPv$family appliance local/fabric metrics reachable ($address HTTP$code)"
  done
  [[ "$family" == 4 ]] || return 0
  underlay=$(docker inspect cozyplane-ipsec-test-control-plane -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
  code=$(curl --noproxy '*' -ksS -m 4 -o /dev/null -w '%{http_code}' "https://$underlay:6443/version")
  [[ "$code" =~ ^(200|401|403)$ ]] && pass 'underlay API positive control' || { fail 'underlay control failed'; return 1; }
  client_exec "$peer" ip route replace "$underlay/32" dev ipsec0
  code=$(client_exec "$peer" curl --noproxy '*' -ksS -m 4 -o /dev/null -w '%{http_code}' "https://$underlay:6443/version" 2>/dev/null || true)
  [[ "$code" == 000 ]] && pass 'underlay API denied through IPSec' || fail "underlay reachable through IPSec (HTTP$code)"
}
