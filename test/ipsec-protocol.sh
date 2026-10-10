#!/usr/bin/env bash
# Public protocol evidence only: retain SPIs, never XFRM encryption keys.
# shellcheck disable=SC2317
peer_spis() {
  client_exec "$1" ip -s xfrm state | python3 "$ROOT/test/ipsec-sa-public.py" | jq '[.[]|select(.proto=="esp")|.spi]|sort'
}
preflight_actual_sa() {
  local index="$1" pod
  client_exec "$index" ip -s xfrm state | python3 "$ROOT/test/ipsec-sa-public.py" > "$REPORT/sa-preflight-peer-$index.json"
  pod=$(selected_pod)
  "${K[@]}" -n "$NS" exec "$pod" -- ip -s xfrm state | python3 "$ROOT/test/ipsec-sa-public.py" > "$REPORT/sa-preflight-appliance.json"
  jq -e 'length>0 and all(.[]; .spi!=null and .["lifetime-current"].packets!=null)' "$REPORT/sa-preflight-peer-$index.json" >/dev/null
  jq -e 'length>0 and all(.[]; .spi!=null and .["lifetime-current"].packets!=null)' "$REPORT/sa-preflight-appliance.json" >/dev/null
  pass 'actual initiator/appliance SA format and public counters preflight'
}
rekey_actual() {
  local index="$1" title="$2" before
  before=$(peer_spis "$index")
  printf '%s\n' "$before" > "$REPORT/$title-spis-before.json"
  client_exec "$index" swanctl --rekey --child "peer-$index" >/dev/null || { fail "$title command rejected"; return; }
  rekey_changed() {
    local after; after=$(peer_spis "$index")
    jq -en --argjson before "$before" --argjson after "$after" '($before|length)>0 and (($after-$before)|length)>0' >/dev/null
  }
  wait_for "$title installs new actual ESP SPIs" rekey_changed
  peer_spis "$index" > "$REPORT/$title-spis-after.json"
}
