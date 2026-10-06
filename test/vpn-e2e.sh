#!/usr/bin/env bash
#
# VPN end-to-end test on an already-installed cozyplane cluster.
#
# Also exercises the hub scenario: gateway-a additionally serves site-c via
# spec.additionalVPCRefs, reusing the a-to-b connection's remote routes.
#
# The harness deliberately does not create a cluster: test/e2e.sh owns the kind
# bootstrap, while a lab runner supplies an existing Talos cluster through KCTX.
# This keeps the VPN assertions identical in both environments. All credentials
# live only in the throw-away namespace created below.
#
# Usage:
#   BACKEND=wireguard MODE=materialize KCTX=kind-cozyplane-e2e bash test/vpn-e2e.sh
#   BACKEND=ipsec     MODE=live KCTX=<lab-context>              bash test/vpn-e2e.sh
#
# Optional:
#   VPN_E2E_RUN_ID=<dns-label>  namespace suffix (useful for concurrent labs)
#   KEEP=1                      retain fixtures for diagnosis
set -euo pipefail

BACKEND="${BACKEND:-wireguard}"
case "$BACKEND" in
  wireguard|ipsec) ;;
  *) echo "BACKEND must be wireguard or ipsec (got $BACKEND)" >&2; exit 2 ;;
esac

MODE="${MODE:-materialize}"
case "$MODE" in
  materialize|live) ;;
  *) echo "MODE must be materialize or live (got $MODE)" >&2; exit 2 ;;
esac

KCTX="${KCTX:-}"
[ -n "$KCTX" ] || { echo "KCTX must name the target Kubernetes context" >&2; exit 2; }
K=(kubectl --context "$KCTX")

RUN_ID="${VPN_E2E_RUN_ID:-${GITHUB_RUN_ID:-$(date +%s)-$$}}"
RUN_ID="$(printf '%s' "$RUN_ID" | tr '[:upper:]_' '[:lower:]-' | tr -cd 'a-z0-9-')"
RUN_ID="${RUN_ID:0:30}"
NS="vpn-e2e-${BACKEND}-${RUN_ID}"
VPC_A_CIDR="10.250.0.0/24"
VPC_B_CIDR="10.251.0.0/24"
VPC_C_CIDR="10.252.0.0/24"
FAILED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; FAILED=1; }

cleanup() {
  [ "${KEEP:-0}" = "1" ] && { echo "keeping namespace $NS"; return; }
  "${K[@]}" delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_jsonpath() { # description resource jsonpath expected [timeout seconds]
  local desc="$1" resource="$2" path="$3" expected="$4" timeout="${5:-180}" got=""
  local deadline=$((SECONDS + timeout))
  while [ "$SECONDS" -lt "$deadline" ]; do
    got=$("${K[@]}" -n "$NS" get "$resource" -o "jsonpath=$path" 2>/dev/null || true)
    [ "$got" = "$expected" ] && { pass "$desc"; return 0; }
    sleep 2
  done
  fail "$desc (want $expected, got ${got:-empty})"
  return 1
}

wait_value() { # description resource jsonpath [timeout seconds]
  local desc="$1" resource="$2" path="$3" timeout="${4:-180}" got=""
  local deadline=$((SECONDS + timeout))
  while [ "$SECONDS" -lt "$deadline" ]; do
    got=$("${K[@]}" -n "$NS" get "$resource" -o "jsonpath=$path" 2>/dev/null || true)
    [ -n "$got" ] && { WAIT_VALUE="$got"; pass "$desc"; return 0; }
    sleep 2
  done
  fail "$desc (value is empty)"
  return 1
}

vpc_ip() { "${K[@]}" get ports -l "sdn.cozystack.io/pod-namespace=$NS,sdn.cozystack.io/pod-name=$1" -o jsonpath='{.items[0].spec.ip}'; }
# The appliance metrics listener comes up a moment after the pod is Ready and the
# apiserver proxy times out on a closed port, so poll rather than fail on the first
# attempt.
fetch_metrics() { # pod-name
  local out=""
  for _ in $(seq 1 15); do
    out=$("${K[@]}" get --raw "/api/v1/namespaces/$NS/pods/$1:9410/proxy/metrics" 2>/dev/null) && break
    sleep 4
  done
  printf '%s' "$out"
}

echo "== VPN e2e: backend=$BACKEND mode=$MODE context=$KCTX namespace=$NS =="
# Discovery through api-resources rather than a raw GET of the group document:
# recent kubectl builds answer the raw path with 404 while the aggregated API
# serves resources fine.
"${K[@]}" api-resources --api-group=sdn.cozystack.io >/dev/null
"${K[@]}" create namespace "$NS" >/dev/null
# The tunnel appliance needs NET_ADMIN and forwarding sysctls in its own netns.
# On a cluster with a Pod Security default (Cozystack enforces one), the
# throw-away namespace must opt out the way tenant namespaces do.
"${K[@]}" label namespace "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null

"${K[@]}" -n "$NS" apply -f - <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: site-a}
spec: {cidrs: ["$VPC_A_CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: site-a}
spec: {vpcRef: {namespace: "$NS", name: site-a}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: site-b}
spec: {cidrs: ["$VPC_B_CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: site-b}
spec: {vpcRef: {namespace: "$NS", name: site-b}}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: site-c}
spec: {cidrs: ["$VPC_C_CIDR"]}
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPCBinding
metadata: {name: site-c}
spec: {vpcRef: {namespace: "$NS", name: site-c}}
---
apiVersion: v1
kind: Pod
metadata: {name: client-a, annotations: {sdn.cozystack.io/vpc: site-a}}
spec:
  containers: [{name: client, image: busybox:1.36, command: [sh, -c, "sleep 3600"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: server-b, annotations: {sdn.cozystack.io/vpc: site-b}}
spec:
  containers: [{name: server, image: busybox:1.36, command: [sh, -c, "mkdir -p /www; echo server-b > /www/index.html; httpd -f -p 8080 -h /www"]}]
---
apiVersion: v1
kind: Pod
metadata: {name: client-c, annotations: {sdn.cozystack.io/vpc: site-c}}
spec:
  containers: [{name: client, image: busybox:1.36, command: [sh, -c, "sleep 3600"]}]
EOF
"${K[@]}" -n "$NS" wait --for=condition=Ready pod/client-a pod/server-b pod/client-c --timeout=180s

if [ "$BACKEND" = "wireguard" ]; then
  gateway_spec='wireguard: {listenPort: 51820}'
else
  # modp2048: the appliance image ships strongSwan without the openssl plugin, so ECP groups are unavailable.
  gateway_spec='ipsec: {proposals: ["aes256-sha256-modp2048"]}'
fi
"${K[@]}" -n "$NS" apply -f - <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {name: gateway-a}
spec:
  vpcRef: {name: site-a}
  additionalVPCRefs: [{name: site-c}]
  $gateway_spec
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNGateway
metadata: {name: gateway-b}
spec:
  vpcRef: {name: site-b}
  $gateway_spec
EOF

# One resource per wait: with several arguments kubectl 1.34 returns NotFound
# at once instead of waiting for the objects to appear.
"${K[@]}" -n "$NS" wait --for=create deployment/gateway-a-vpn --timeout=180s
"${K[@]}" -n "$NS" wait --for=create deployment/gateway-b-vpn --timeout=180s
"${K[@]}" -n "$NS" rollout status deployment/gateway-a-vpn --timeout=180s
"${K[@]}" -n "$NS" rollout status deployment/gateway-b-vpn --timeout=180s

# The secrets are runtime-only. They are intentionally generated after the
# namespace exists and are deleted with it; no fixture contains key material.
case "$BACKEND" in
  wireguard)
    PSK="$(openssl rand -base64 32 | tr -d '\n')"
    "${K[@]}" -n "$NS" create secret generic tunnel-psk --from-literal=presharedKey="$PSK" >/dev/null
    wait_value "gateway-a published its WireGuard key" vpngateway/gateway-a '{.status.publicKey}'
    KEY_A="$WAIT_VALUE"
    wait_value "gateway-b published its WireGuard key" vpngateway/gateway-b '{.status.publicKey}'
    KEY_B="$WAIT_VALUE"
    [ -n "$KEY_A" ] && [ -n "$KEY_B" ] || { echo "VPN gateways did not publish WireGuard public keys" >&2; exit 1; }
    CONNECTION_A="wireguard: {peerPublicKey: \"$KEY_B\", presharedKeySecretRef: tunnel-psk, persistentKeepalive: 5}"
    CONNECTION_B="wireguard: {peerPublicKey: \"$KEY_A\", presharedKeySecretRef: tunnel-psk, persistentKeepalive: 5}"
    ;;
  ipsec)
    PSK="$(openssl rand -hex 32)"
    "${K[@]}" -n "$NS" create secret generic tunnel-psk --from-literal=psk="$PSK" >/dev/null
    CONNECTION_A="ipsec: {auth: {pskSecretRef: tunnel-psk}, proposals: [\"aes256-sha256-modp2048\"], dpdDelay: 5, startAction: None}"
    CONNECTION_B="ipsec: {auth: {pskSecretRef: tunnel-psk}, proposals: [\"aes256-sha256-modp2048\"], dpdDelay: 5, startAction: None}"
    ;;
esac

"${K[@]}" -n "$NS" apply -f - <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: a-to-b}
spec:
  gatewayRef: {name: gateway-a}
  remoteCIDRs: ["$VPC_B_CIDR"]
  $CONNECTION_A
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: b-to-a}
spec:
  gatewayRef: {name: gateway-b}
  remoteCIDRs: ["$VPC_A_CIDR", "$VPC_C_CIDR"]  # the hub peer must list every served VPC
  $CONNECTION_B
EOF

# The controller rolls the appliance after projecting each connection and its
# ephemeral credential. Waiting for the rollout also catches a rejected Secret
# reference before the datapath assertion gives an opaque timeout.
"${K[@]}" -n "$NS" rollout status deployment/gateway-a-vpn --timeout=180s
"${K[@]}" -n "$NS" rollout status deployment/gateway-b-vpn --timeout=180s

wait_jsonpath "a-to-b route materialized" vpngateway/gateway-a '{.status.routes[0].cidrs[0]}' "$VPC_B_CIDR"
wait_jsonpath "b-to-a route materialized" vpngateway/gateway-b '{.status.routes[0].cidrs[0]}' "$VPC_A_CIDR"
wait_value "a-to-b route has an appliance Port" vpngateway/gateway-a '{.status.routes[0].port}'
PORT_SITE_A="$WAIT_VALUE"
wait_value "b-to-a route has an appliance Port" vpngateway/gateway-b '{.status.routes[0].port}'

# Hub scenario: gateway-a additionally serves site-c via additionalVPCRefs.
wait_jsonpath "hub VPCBinding forwards a-to-b's remote CIDR to site-c" vpcbinding/gateway-a-vpn-site-c '{.spec.forwardingCIDRs[0]}' "$VPC_B_CIDR"
wait_jsonpath "hub route for site-c materialized" vpngateway/gateway-a '{.status.routes[1].cidrs[0]}' "$VPC_B_CIDR"
wait_value "hub route for site-c has an appliance Port" vpngateway/gateway-a '{.status.routes[1].port}'
PORT_SITE_C="$WAIT_VALUE"
if [ "$PORT_SITE_A" != "$PORT_SITE_C" ]; then
  pass "hub routes use distinct appliance Ports"
else
  fail "hub routes share the same appliance Port ($PORT_SITE_A)"
fi
PORT_SITE_C_VPC=$("${K[@]}" get port "$PORT_SITE_C" -o jsonpath='{.metadata.labels.sdn\.cozystack\.io/vpc}' 2>/dev/null || true)
if [ "$PORT_SITE_C_VPC" = "site-c" ]; then
  pass "hub route's Port is labelled for site-c"
else
  fail "hub route's Port is not labelled for site-c (got ${PORT_SITE_C_VPC:-empty})"
fi

POD_A=$("${K[@]}" -n "$NS" get pod -l sdn.cozystack.io/vpn-gateway=gateway-a -o jsonpath='{.items[0].metadata.name}')
[ -n "$POD_A" ] || { echo "gateway-a has no appliance pod" >&2; exit 1; }

APPLIANCE_NETWORKS=$("${K[@]}" -n "$NS" get pod "$POD_A" -o jsonpath='{.metadata.annotations.sdn\.cozystack\.io/networks}' 2>/dev/null || true)
if [ -n "$APPLIANCE_NETWORKS" ]; then
  pass "gateway-a appliance pod carries the sdn.cozystack.io/networks annotation"
else
  fail "gateway-a appliance pod is missing the sdn.cozystack.io/networks annotation"
fi
APPLIANCE_VPC=$("${K[@]}" -n "$NS" get pod "$POD_A" -o jsonpath='{.metadata.annotations.sdn\.cozystack\.io/vpc}' 2>/dev/null || true)
if [ -z "$APPLIANCE_VPC" ]; then
  pass "gateway-a appliance pod does not carry the single-VPC sdn.cozystack.io/vpc annotation"
else
  fail "gateway-a appliance pod unexpectedly carries sdn.cozystack.io/vpc=$APPLIANCE_VPC"
fi
METRICS_A=$(fetch_metrics "$POD_A")
if printf '%s\n' "$METRICS_A" | grep -q 'cozyplane_vpn_connection_up{connection="a-to-b"'; then
  pass "a-to-b is exported by the appliance metrics endpoint"
else
  fail "a-to-b is missing from the appliance metrics endpoint"
fi

if [ "$MODE" = "live" ]; then
  # A live tunnel needs externally reachable endpoint addresses. The laboratory
  # cluster supplies them through its normal LoadBalancer/FloatingIP allocator;
  # kind deliberately does not pretend to provide that platform service.
  wait_value "gateway-a received a FloatingIP" vpngateway/gateway-a '{.status.address}'
  ENDPOINT_A="$WAIT_VALUE"
  wait_value "gateway-b received a FloatingIP" vpngateway/gateway-b '{.status.address}'
  ENDPOINT_B="$WAIT_VALUE"

  if [ "$BACKEND" = "wireguard" ]; then
    CONNECTION_A="wireguard: {peerPublicKey: \"$KEY_B\", peerEndpoint: \"$ENDPOINT_B:51820\", presharedKeySecretRef: tunnel-psk, persistentKeepalive: 5}"
    CONNECTION_B="wireguard: {peerPublicKey: \"$KEY_A\", peerEndpoint: \"$ENDPOINT_A:51820\", presharedKeySecretRef: tunnel-psk, persistentKeepalive: 5}"
  else
    CONNECTION_A="ipsec: {peerAddress: \"$ENDPOINT_B\", auth: {pskSecretRef: tunnel-psk}, proposals: [\"aes256-sha256-modp2048\"], dpdDelay: 5, startAction: Start}"
    CONNECTION_B="ipsec: {peerAddress: \"$ENDPOINT_A\", auth: {pskSecretRef: tunnel-psk}, proposals: [\"aes256-sha256-modp2048\"], dpdDelay: 5, startAction: None}"
  fi
  "${K[@]}" -n "$NS" apply -f - <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: a-to-b}
spec:
  gatewayRef: {name: gateway-a}
  remoteCIDRs: ["$VPC_B_CIDR"]
  $CONNECTION_A
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPNConnection
metadata: {name: b-to-a}
spec:
  gatewayRef: {name: gateway-b}
  remoteCIDRs: ["$VPC_A_CIDR", "$VPC_C_CIDR"]  # the hub peer must list every served VPC
  $CONNECTION_B
EOF
  "${K[@]}" -n "$NS" rollout status deployment/gateway-a-vpn --timeout=180s
  "${K[@]}" -n "$NS" rollout status deployment/gateway-b-vpn --timeout=180s

  SERVER_B_IP="$(vpc_ip server-b)"
  [ -n "$SERVER_B_IP" ] || { echo "server-b has no VPC address" >&2; exit 1; }
  # This flow is both the data-plane proof and the trigger for IPsec CHILD_SA.
  for _ in $(seq 1 30); do
    if "${K[@]}" -n "$NS" exec client-a -- wget -qO- -T3 "http://$SERVER_B_IP:8080/" 2>/dev/null | grep -qx server-b; then
      pass "site-a reaches site-b over $BACKEND"
      break
    fi
    sleep 2
  done
  if ! "${K[@]}" -n "$NS" exec client-a -- wget -qO- -T3 "http://$SERVER_B_IP:8080/" 2>/dev/null | grep -qx server-b; then
    fail "site-a cannot reach site-b over $BACKEND"
  fi
  # Hub scenario: client-c (site-c, served by gateway-a as a hub) reaches
  # site-b over the same a-to-b tunnel.
  for _ in $(seq 1 30); do
    if "${K[@]}" -n "$NS" exec client-c -- wget -qO- -T3 "http://$SERVER_B_IP:8080/" 2>/dev/null | grep -qx server-b; then
      pass "hub VPC site-c reaches site-b over $BACKEND"
      break
    fi
    sleep 2
  done
  if ! "${K[@]}" -n "$NS" exec client-c -- wget -qO- -T3 "http://$SERVER_B_IP:8080/" 2>/dev/null | grep -qx server-b; then
    fail "hub VPC site-c cannot reach site-b over $BACKEND"
  fi
  wait_jsonpath "a-to-b reports Established" vpnconnection/a-to-b '{.status.phase}' Established 120 || true
  wait_jsonpath "b-to-a reports Established" vpnconnection/b-to-a '{.status.phase}' Established 120 || true
  POD_A=$("${K[@]}" -n "$NS" get pod -l sdn.cozystack.io/vpn-gateway=gateway-a -o jsonpath='{.items[0].metadata.name}')
  METRICS_A=$(fetch_metrics "$POD_A")
  if printf '%s\n' "$METRICS_A" | grep -q 'cozyplane_vpn_connection_up{connection="a-to-b",backend="'"$BACKEND"'"} 1'; then
    pass "a-to-b live metric is up"
  else
    fail "a-to-b live metric did not become up"
  fi
fi

if [ "$FAILED" -ne 0 ]; then
  echo "VPN e2e failed; inspect namespace $NS (set KEEP=1 to retain it)" >&2
  exit 1
fi
echo "VPN e2e passed: backend=$BACKEND"
