#!/usr/bin/env bash
# cozyplane-kpr increment-2 e2e: a kind cluster with NO kube-proxy
# (kubeProxyMode: none). ClusterIP then works ONLY if cozyplane-kpr's socket-LB
# serves it — there is no iptables service proxy to fall back on. Proves TCP +
# UDP ClusterIP and cluster DNS from a pod.
#
# Bootstrap note: with no kube-proxy the kubernetes.default ClusterIP is unserved
# until kpr runs, so kpr itself is pointed at the real apiserver endpoint
# (--k8s-api-server-urls) instead of the in-cluster ClusterIP.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER="${CLUSTER:-kpr-e2e}"
KIND="${KIND:-kind}"
K="kubectl"
pass=0; fail=0
ok()   { echo "  ok   - $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL - $*"; fail=$((fail+1)); }

cleanup() { [ "${KEEP:-0}" = "1" ] || $KIND delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "== kind cluster (kubeProxyMode: none) =="
cat >/tmp/kpr-kind.yaml <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $CLUSTER
networking:
  kubeProxyMode: none
nodes:
  - role: control-plane
EOF
$KIND delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
$KIND create cluster --config /tmp/kpr-kind.yaml >/dev/null
export KUBECONFIG="$($KIND get kubeconfig --name "$CLUSTER" >/tmp/kpr-e2e.kubeconfig; echo /tmp/kpr-e2e.kubeconfig)"

echo "== build + load cozyplane-kpr image =="
CGO_ENABLED=0 go -C "$ROOT/kpr" build -o "$ROOT/kpr/cozyplane-kpr" .
docker build -q -t cozyplane-kpr:dev -f "$ROOT/kpr/Dockerfile" "$ROOT/kpr" >/dev/null
$KIND load docker-image cozyplane-kpr:dev --name "$CLUSTER" >/dev/null

echo "== deploy cozyplane-kpr (pointed at the real apiserver) =="
CPIP="$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "${CLUSTER}-control-plane")"
$K apply -f "$ROOT/deploy/kpr-daemonset.yaml" >/dev/null
$K -n kube-system patch ds cozyplane-kpr --type=json -p \
  "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args\",\"value\":[\"--k8s-api-server-urls=https://${CPIP}:6443\"]}]" >/dev/null
$K -n kube-system rollout status ds/cozyplane-kpr --timeout=150s

# Socket-LB attached?
POD="$($K -n kube-system get pod -l app=cozyplane-kpr -o name | head -1)"
if $K -n kube-system logs "$POD" 2>/dev/null | grep -q "attached socket-LB program.*cil_sock_release"; then
  ok "socket-LB programs attached at the cgroup root"
else
  bad "socket-LB attach not observed"; $K -n kube-system logs "$POD" 2>/dev/null | tail -15
fi

echo "== workloads (TCP + UDP echo) =="
$K create deployment echo --image=registry.k8s.io/e2e-test-images/agnhost:2.45 -- /agnhost netexec --http-port=8080 --udp-port=8082 >/dev/null
$K scale deployment echo --replicas=2 >/dev/null
$K expose deployment echo --name=echo-tcp --port=80 --target-port=8080 >/dev/null
$K expose deployment echo --name=echo-udp --port=53 --target-port=8082 --protocol=UDP >/dev/null
$K wait --for=condition=Available deploy/echo --timeout=120s >/dev/null
$K run bb --image=busybox:1.36 --restart=Never --command -- sleep 3600 >/dev/null
$K wait --for=condition=Ready pod/bb --timeout=120s >/dev/null
TCPIP="$($K get svc echo-tcp -o jsonpath='{.spec.clusterIP}')"
UDPIP="$($K get svc echo-udp -o jsonpath='{.spec.clusterIP}')"

echo "== assertions (no kube-proxy: ClusterIP == socket-LB) =="
set +e  # assertions track their own pass/fail; a transient sample must not abort
LOOP='for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16'
# TCP ClusterIP from a pod, load-balanced across both backends.
uniqtcp="$($K exec bb -- sh -c "$LOOP; do wget -qO- -T3 http://$TCPIP:80/hostname; echo; done" 2>/dev/null | sort -u | grep -c echo- )"
[ "$uniqtcp" -ge 2 ] && ok "TCP ClusterIP resolves + load-balances ($uniqtcp backends)" || bad "TCP ClusterIP (unique=$uniqtcp)"
# UDP ClusterIP from a pod, load-balanced.
uniqudp="$($K exec bb -- sh -c "$LOOP; do echo hostname | nc -u -w1 $UDPIP 53; echo; done" 2>/dev/null | sort -u | grep -c echo- )"
[ "$uniqudp" -ge 2 ] && ok "UDP ClusterIP resolves + load-balances ($uniqudp backends)" || bad "UDP ClusterIP (unique=$uniqudp)"
# Cluster DNS (UDP request + reverse-translated reply) via the kube-dns ClusterIP.
$K exec bb -- nslookup -type=A kubernetes.default.svc.cluster.local 2>/dev/null | grep -q "10.96.0.1" \
  && ok "cluster DNS resolves via socket-LB (kubernetes.default -> 10.96.0.1)" || bad "cluster DNS"

echo "== result: $pass passed, $fail failed =="
[ "$fail" -eq 0 ]
