#!/usr/bin/env bash
# Match controller observations against actual negotiated kernel selectors.
# shellcheck disable=SC2154,SC2317
actual_vip() {
  client_exec "$1" sh -c 'ip xfrm policy | python3 /run/ipsec-vip-public.py'
}
refresh_vip() {
  local index="$1" context="$2" vip family bits prefix
  vip_observed() {
    vip=$(actual_vip "$index" 2>/dev/null) || return 1
    "${K[@]}" -n "$NS" get vpnconnection "peer-$index" -o json | jq -e --arg vip "$vip" '(.status.assignedAddresses // [])|index($vip)!=null' >/dev/null
  }
  wait_for "peer-$index actual negotiated VIP matches current observation ($context)" vip_observed
  # Remove only this disposable client's previous addresses in fixture pools.
  client_exec "$index" python3 -c 'import ipaddress,json,subprocess; pools=[ipaddress.ip_network("10.250.150.0/24"),ipaddress.ip_network("fd42:250:150::/120")]; links=json.loads(subprocess.check_output(["ip","-j","addr","show","dev","ipsec0"])); [(subprocess.run(["ip","-6" if a["family"]=="inet6" else "-4","addr","del",a["local"]+"/"+str(a["prefixlen"]),"dev","ipsec0"],check=True)) for link in links for a in link.get("addr_info",[]) if any(ipaddress.ip_address(a["local"]) in pool for pool in pools)]'
  family=4; bits=32; prefix=10.250.0.0/16
  [[ "$vip" != *:* ]] || { family=6; bits=128; prefix=fd42:250::/32; }
  client_exec "$index" ip "-$family" addr add "$vip/$bits" dev ipsec0
  client_exec "$index" ip "-$family" route replace "$prefix" dev ipsec0 src "$vip"
  jq -nc --arg index "$index" --arg vip "$vip" --arg family "$family" --arg context "$context" '{peer:$index,address:$vip,family:$family,context:$context}' >> "$REPORT/roadwarrior-allocations.jsonl"
}
refresh_live_vips() {
  local index
  for index in $(seq 1 "$COUNT"); do
    "${K[@]}" -n "$NS" get vpnconnection "peer-$index" >/dev/null 2>&1 || continue
    refresh_vip "$index" "$1"
  done
}
