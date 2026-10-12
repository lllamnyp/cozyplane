#!/usr/bin/env bash
# Sourced last: simultaneous backend edits while the dedicated controller is stopped.
# shellcheck disable=SC2154,SC2317
transition_check() (
  set -euo pipefail
  [[ "$KCTX" == kind-cozyplane-ipsec-test && "$NS" =~ ^ipsec-test-[0-9]+-[0-9]+$ && "${HOSTNAME:-}" == ipsec-guest ]] || exit 2
  local replicas controller restore_needed=0
  controller=$("${K[@]}" -n kube-system get deployment cozyplane-controller -o json)
  jq -e '.metadata.name=="cozyplane-controller" and .metadata.namespace=="kube-system" and .spec.template.spec.serviceAccountName=="cozyplane-controller"' <<<"$controller" >/dev/null
  replicas=$(jq -r '.spec.replicas' <<<"$controller")
  [[ "$replicas" =~ ^[1-9][0-9]*$ ]] || exit 2
  restore() {
    if ((restore_needed)); then
      "${K[@]}" -n kube-system scale deployment cozyplane-controller --replicas="$replicas" >/dev/null
    fi
  }
  trap restore EXIT
  # Avoid synthesizing the old state: capture only actual live status.
  for _ in $(seq 1 150); do
    "${K[@]}" -n "$NS" get vpnconnection peer-1 -o json > "$REPORT/transition-before-peer.json"
    jq -e '. as $peer | .status.phase=="Established" and .status.lastHandshake!=null and all(["Established","RoutesProgrammed"][]; . as $type | any($peer.status.conditions[]?; .type==$type and .status=="True" and .observedGeneration==$peer.metadata.generation))' "$REPORT/transition-before-peer.json" >/dev/null && break
    sleep 2
  done
  jq -e '. as $peer | .status.phase=="Established" and .status.lastHandshake!=null and all(["Established","RoutesProgrammed"][]; . as $type | any($peer.status.conditions[]?; .type==$type and .status=="True" and .observedGeneration==$peer.metadata.generation))' "$REPORT/transition-before-peer.json" >/dev/null
  [[ "$(http 1 "$A")" == site-a ]]
  "${K[@]}" -n "$NS" get vpngateway gateway -o json > "$REPORT/transition-before-gateway.json"
  restore_needed=1
  "${K[@]}" -n kube-system scale deployment cozyplane-controller --replicas=0 >/dev/null
  "${K[@]}" -n kube-system rollout status deployment/cozyplane-controller --timeout=90s >/dev/null
  # Public synthetic key bytes; no private key exists for this deliberately invalid setup.
  local key
  key=$(python3 -c 'import base64; print(base64.b64encode(bytes(range(1,33))).decode())')
  "${K[@]}" -n "$NS" patch vpngateway gateway --type=merge -p '{"spec":{"ipsec":null,"wireguard":{}}}' > "$REPORT/transition-gateway-patch.txt" 2>&1
  "${K[@]}" -n "$NS" patch vpnconnection peer-1 --type=merge -p "{\"spec\":{\"ipsec\":null,\"wireguard\":{\"peerPublicKey\":\"$key\",\"presharedKeySecretRef\":\"fixture-absent\"}}}" > "$REPORT/transition-peer-patch.txt" 2>&1
  "${K[@]}" -n "$NS" get vpnconnection peer-1 -o json > "$REPORT/transition-stopped-peer.json"
  jq -e '. as $peer | all(["Established","RoutesProgrammed"][]; . as $type | any($peer.status.conditions[]?; .type==$type and .status=="True"))' "$REPORT/transition-stopped-peer.json" >/dev/null
  restore
  restore_needed=0
  "${K[@]}" -n kube-system rollout status deployment/cozyplane-controller --timeout=180s >/dev/null
  drained() {
    "${K[@]}" -n "$NS" get vpnconnection peer-1 -o json > "$REPORT/transition-after-peer.json"
    "${K[@]}" -n "$NS" get vpngateway gateway -o json > "$REPORT/transition-after-gateway.json"
    jq -e '. as $peer | .status.phase=="Pending" and all(["Established","RoutesProgrammed"][]; . as $type | any($peer.status.conditions[]?; .type==$type and .status=="False" and .observedGeneration==$peer.metadata.generation))' "$REPORT/transition-after-peer.json" >/dev/null || return 1
    jq -e '. as $gateway | .status.phase=="Pending" and any(.status.conditions[]?; .type=="ApplianceReady" and .status=="False" and .observedGeneration==$gateway.metadata.generation)' "$REPORT/transition-after-gateway.json" >/dev/null
  }
  wait_for 'simultaneous backend edits withdraw historical Established and routes at current generation' drained
  jq -en --slurpfile before "$REPORT/transition-before-peer.json" --slurpfile after "$REPORT/transition-after-peer.json" '$before[0].status.lastHandshake==$after[0].status.lastHandshake and ($before[0].status.assignedAddresses // [])==($after[0].status.assignedAddresses // [])' >/dev/null
  if http 1 "$A" >/dev/null 2>&1; then
    echo 'Old IPSec data access survived the backend transition' >&2
    exit 1
  fi
  "${K[@]}" -n "$NS" get vpcbindings -o json > "$REPORT/transition-bindings.json"
  jq -e 'all(.items[]; .spec.allowForwarding!=true)' "$REPORT/transition-bindings.json" >/dev/null
  jq -e 'all(.status.routes[]?; (.port // "")=="")' "$REPORT/transition-after-gateway.json" >/dev/null
)
python3 "$ROOT/test/ipsec-snapshot.py" "$ROOT" "$REPORT" backend-transition ipsec-transition.sh
transition_check
pass 'simultaneous backend edits clear live status and traffic while retaining handshake history'
