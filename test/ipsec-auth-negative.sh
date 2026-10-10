#!/usr/bin/env bash
# Behavior + categorized outcomes, with another established peer as live control.
# Credentials and daemon debug logs are never copied to reports.
# shellcheck disable=SC2154,SC2015
load_client() { client_exec "$1" swanctl --load-all --clear --file /run/ipsec-test/swanctl.conf >/dev/null; }
set_client_secret() {
  local index="$1" file="$2"
  docker exec -i "${CLIENT_NAMES[$((index-1))]}" python3 -c 'import pathlib,re,sys; p=pathlib.Path("/run/ipsec-test/swanctl.conf"); p.write_text(re.sub(r"secret = [0-9a-f]+", "secret = "+sys.stdin.read().strip(),p.read_text()))' < "$file"
}
negative_auth() {
  local index="$1" survivor="$2" title="$3" target="$4" output result category control
  client_exec "$index" swanctl --terminate --ike "peer-$index" >/dev/null 2>&1 || true
  load_client "$index"
  # Keep a real positive control active throughout the failed authentication.
  (for _ in $(seq 1 40); do
    if http "$survivor" "$target" >/dev/null 2>&1; then code=200; else code=000; fi
    jq -nc --arg timestamp "$(date -u +'%Y-%m-%dT%H:%M:%S.%NZ')" --arg http "$code" '{timestamp:$timestamp,http:$http}' >> "$REPORT/$title-positive.jsonl"
    sleep .5
  done) & control=$!
  result=0
  output=$(client_exec "$index" swanctl --initiate --child "peer-$index" --timeout 30 2>&1) || result=$?
  wait "$control" || true
  category=unclassified
  if grep -qiE 'AUTHENTICATION_FAILED|authentication failed|EAP.*failed|no trusted RSA|no trusted.*key|no trusted.*certificate' <<<"$output"; then category=authentication-rejected; fi
  jq -nc --arg title "$title" --arg category "$category" --argjson result "$result" '{case:$title,outcome:$category,exitCode:$result}' >> "$REPORT/auth-negative.jsonl"
  ((result!=0)) && [[ "$category" == authentication-rejected ]] && pass "$title rejects authentication explicitly" || fail "$title lacks explicit authentication rejection"
  jq -se 'all(.[];.http=="200") and length>=2' "$REPORT/$title-positive.jsonl" >/dev/null && pass "$title concurrent surviving peer stays reachable" || fail "$title positive control failed"
  http "$index" "$target" >/dev/null 2>&1 && fail "$title bad credential passes traffic" || pass "$title bad credential has no data-plane access"
}
