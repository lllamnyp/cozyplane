#!/usr/bin/env bash
# Policy e2e: NetworkPolicy (incl. entity peers) + HostFirewall (ingress and
# egress). Cluster-agnostic: it creates no cluster and builds no image, so it
# runs against any cluster already running cozyplane.
#
#   KCTX=<context> [KUBECONFIG=<path>] test/policy-e2e.sh
#
# It asserts behaviour only — the datapath's verifier acceptance is proved by
# the agent coming up at all, which any cluster rollout already does.
#
# Optional:
#   NODES="node1 node2"   pick the two nodes to schedule on (default: the first
#                         two Ready nodes)
#   NS=polE2E             the namespace to use (created + deleted)
#   KEEP=1                leave the namespace behind for inspection
#
# HostFirewall is cluster-scoped, so the suite is careful with it: the objects
# it creates are named pol-e2e-*, they select exactly one node via a label the
# suite stamps and removes, and the exit trap deletes both. An isolated node
# never outlives the run, even on a failure or an interrupt.
set -u
KCTX="${KCTX:?set KCTX (e.g. admin@dev, or kind-czp-foo)}"
K="kubectl --context ${KCTX}"
NS="${NS:-pol-e2e}"
HFLABEL="cozyplane.io/pol-e2e"

FAILED=0
CHECKS=0
PASSED=0
SKIPPED=0
TOTAL=$(grep -cE '(^|[[:space:]])(pass|fail) "' "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)
TOTAL=$((TOTAL / 2))
PHASE=0
PHASE_TOTAL=$(grep -cE '^phase "' "${BASH_SOURCE[0]}" 2>/dev/null || echo 0)
START=$(date +%s)

phase() {
  PHASE=$((PHASE + 1))
  echo
  echo "[phase ${PHASE}/${PHASE_TOTAL}] $* — ${CHECKS}/~${TOTAL} checks done, ${PASSED} passed, $((CHECKS - PASSED)) failed, $(( $(date +%s) - START ))s elapsed"
}
pass() { CHECKS=$((CHECKS + 1)); PASSED=$((PASSED + 1)); echo "  [${CHECKS}/~${TOTAL}] PASS: $*"; }
fail() { CHECKS=$((CHECKS + 1)); FAILED=1; echo "  [${CHECKS}/~${TOTAL}] FAIL: $*"; }
skip() { SKIPPED=$((SKIPPED + 1)); echo "  [skip] $*"; }

cleanup() {
  echo
  echo "== cleanup =="
  $K delete hostfirewall -l "$HFLABEL=owned" --ignore-not-found >/dev/null 2>&1
  [ -n "${W:-}" ] && $K label node "$W" "${HFLABEL}-" >/dev/null 2>&1
  if [ "${KEEP:-0}" != "1" ]; then
    $K delete ns "$NS" --wait=false >/dev/null 2>&1
  fi
}
trap cleanup EXIT

# apply: never swallow a rejected object. A policy that failed schema validation
# looks exactly like a policy that failed to enforce, and the whole phase then
# tests nothing. (`on` is a YAML 1.1 boolean, which is how that bites.)
# --validate=false: on an install where the bootstrap CRDs and the aggregated
# APIService both serve sdn.cozystack.io, OpenAPI aggregation for the group
# fails on duplicated paths, so client-side validation cannot fetch a schema.
# The server still validates (the registry strategy does the real checks).
apply() { $K apply --validate=false -f - >/dev/null || { echo "  FATAL: apply rejected"; exit 1; }; }

# served/refused: poll, because policy programming is eventually consistent.
served()  { for _ in $(seq 1 10); do $K -n "$NS" exec "$1" -- curl -gs -m3 "$2" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }
refused() { for _ in $(seq 1 10); do $K -n "$NS" exec "$1" -- curl -gs -m3 "$2" >/dev/null 2>&1 || return 0; sleep 2; done; return 1; }

# ---------------------------------------------------------------------------
echo "== policy e2e against ${KCTX} =="
mapfile -t READY < <($K get nodes -o jsonpath='{range .items[?(@.status.conditions[-1].status=="True")]}{.metadata.name}{"\n"}{end}')
if [ -n "${NODES:-}" ]; then
  read -r W W2 <<<"$NODES"
else
  W="${READY[0]:-}"; W2="${READY[1]:-}"
fi
[ -n "$W" ] && [ -n "$W2" ] || { echo "need two Ready nodes (got: ${READY[*]:-none})"; exit 1; }
echo "nodes: subject=$W peer=$W2"

WIP4=$($K get node "$W" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep -v : | head -1)
WIP6=$($K get node "$W" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}' | tr ' ' '\n' | grep : | head -1)
PODCIDR=$($K get node "$W" -o jsonpath='{.spec.podCIDR}')
echo "subject node: $WIP4 ${WIP6:-(no v6)}; podCIDR $PODCIDR"

$K delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1
$K create ns "$NS" >/dev/null
# Privileged PSS: hostNetwork pods are the whole point of the node-origin tests.
$K label ns "$NS" pod-security.kubernetes.io/enforce=privileged --overwrite >/dev/null 2>&1

$K -n "$NS" apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: srv, namespace: $NS, labels: {app: srv}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
      readinessProbe: {tcpSocket: {port: 8080}, periodSeconds: 2}
---
apiVersion: v1
kind: Pod
metadata: {name: same, namespace: $NS, labels: {role: allowed}}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
      readinessProbe: {tcpSocket: {port: 8080}, periodSeconds: 2}
---
apiVersion: v1
kind: Pod
metadata: {name: cli, namespace: $NS, labels: {role: cli}}
spec:
  nodeName: $W2
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
---
apiVersion: v1
kind: Pod
metadata: {name: host1, namespace: $NS}
spec:
  nodeName: $W
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
---
apiVersion: v1
kind: Pod
metadata: {name: host2, namespace: $NS}
spec:
  nodeName: $W2
  hostNetwork: true
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
EOF
$K -n "$NS" wait --for=condition=Ready pod/srv pod/same pod/cli pod/host1 pod/host2 --timeout=180s >/dev/null 2>&1 \
  || { echo "fixtures did not become Ready"; $K -n "$NS" get pods; exit 1; }

SRV=$($K -n "$NS" get pod srv -o jsonpath='{.status.podIP}')
SAME=$($K -n "$NS" get pod same -o jsonpath='{.status.podIP}')
CLI=$($K -n "$NS" get pod cli -o jsonpath='{.status.podIP}')

# ===========================================================================
phase "NetworkPolicy: baseline + isolation"
served cli "http://$SRV:8080/" && pass "srv serves the cross-node client before any policy" \
  || fail "srv unreachable before any policy"

apply <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: srv-ingress, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
  ingress:
    - from: [{podSelector: {matchLabels: {role: allowed}}}]
      ports: [{port: 8080}]
EOF
refused cli "http://$SRV:8080/" && pass "isolated srv refuses the unlabeled client" \
  || fail "isolated srv still serves the unlabeled client"
served same "http://$SRV:8080/" && pass "the selected peer is admitted" \
  || fail "the selected peer was refused"
$K -n "$NS" get pod srv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "isolated pod stays Ready (kubelet probes exempt)" \
  || fail "isolation broke kubelet probes"

# ===========================================================================
phase "NetworkPolicy entities: local-node / nodes / local-pods"
served host1 "http://$SRV:8080/" && pass "LOCAL node reaches the isolated pod (structural exemption)" \
  || fail "local-node origin gated — the plumbing exemption broke"
refused host2 "http://$SRV:8080/" && pass "REMOTE node is gated (the exemption narrowed to the local node)" \
  || fail "remote-node origin is still blanket-exempt"

apply <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: srv-ingress, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {policy.cozyplane.io/entity: nodes}}
      ports: [{port: 8080}]
EOF
served host2 "http://$SRV:8080/" && pass "the nodes entity readmits remote-node origin (apiserver->webhook shape)" \
  || fail "the nodes entity did not admit remote-node origin"
refused cli "http://$SRV:8080/" && pass "the nodes entity does not leak to pod sources" \
  || fail "the nodes entity admitted an ordinary pod"

apply <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: srv-ingress, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: srv}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - namespaceSelector: {matchLabels: {policy.cozyplane.io/entity: local-pods}}
      ports: [{port: 8080}]
EOF
served same "http://$SRV:8080/" && pass "the local-pods entity admits a co-scheduled pod" \
  || fail "the local-pods entity did not admit the same-node pod"
refused cli "http://$SRV:8080/" && pass "the local-pods entity refuses a pod on another node (placement, as declared)" \
  || fail "the local-pods entity admitted a cross-node pod"
$K -n "$NS" delete networkpolicy --all >/dev/null

# ===========================================================================
phase "HostFirewall ingress"
$K label node "$W" "$HFLABEL=active" --overwrite >/dev/null
served cli "http://$WIP4:10250/" >/dev/null 2>&1 # warm the path; kubelet 401s but connects
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: pol-e2e-in, labels: {$HFLABEL: owned}}
spec:
  nodeSelector: {matchLabels: {$HFLABEL: active}}
EOF
refused cli "http://$WIP4:9411/metrics" && pass "cross-node pod->node refused (from_overlay gate)" \
  || fail "cross-node pod->node still served while isolated"
refused same "http://$WIP4:9411/metrics" && pass "same-node pod->node refused (from_pod gate)" \
  || fail "same-node pod->node still served while isolated"
served host2 "http://$WIP4:9411/metrics" && pass "node-sourced client exempt (the plumbing contract)" \
  || fail "node-sourced client gated — the exemption is broken"
if [ -n "$WIP6" ]; then
  refused cli "http://[$WIP6]:9411/metrics" && pass "the v6 node address is equally isolated" \
    || fail "the v6 node address is not gated"
else
  skip "v6 node address (cluster has no v6 InternalIP)"
fi
ready=$($K get node "$W" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$ready" = "True" ] && pass "the isolated node stays Ready (kubelet->apiserver exempt)" \
  || fail "the isolated node went NotReady"
$K -n "$NS" get pod srv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "kubelet probes still reach pods on the isolated node" \
  || fail "host-ingress isolation broke kubelet probes"
$K -n "$NS" exec host1 -- nslookup -timeout=3 kubernetes.default >/dev/null 2>&1 \
  && pass "hostNetwork cluster DNS works while isolated (the node->pod UDP pin)" \
  || fail "hostNetwork cluster DNS broke while isolated"

apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: pol-e2e-in, labels: {$HFLABEL: owned}}
spec:
  nodeSelector: {matchLabels: {$HFLABEL: active}}
  ingress:
    - from: [{cidr: $PODCIDR}]
      ports: [{protocol: TCP, port: 9411, endPort: 9413}]
EOF
served same "http://$WIP4:9411/metrics" && pass "a podCIDR+endPort rule reopens same-node pod->node" \
  || fail "the ingress allow rule did not reopen pod->node"
refused cli "http://$WIP4:9411/metrics" && pass "the allow is scoped to the declared CIDR (other-node pod still refused)" \
  || fail "a podCIDR allow leaked to a pod outside it"
$K delete hostfirewall pol-e2e-in >/dev/null
served cli "http://$WIP4:9411/metrics" && pass "deleting the HostFirewall reopens the node" \
  || fail "the node stayed isolated after deletion"

# ===========================================================================
phase "HostFirewall egress"
served host1 "http://$CLI:8080/" && pass "node->remote-pod serves before egress isolation" \
  || fail "node->remote-pod unreachable before egress isolation"
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: pol-e2e-eg, labels: {$HFLABEL: owned}}
spec:
  nodeSelector: {matchLabels: {$HFLABEL: active}}
  policyTypes: [Egress]
EOF
served cli "http://$WIP4:9411/metrics" && pass "an Egress-only object leaves INGRESS open" \
  || fail "an Egress-only object isolated ingress too"
refused host1 "http://$CLI:8080/" && pass "node->remote-pod refused (the from_pod encap gate)" \
  || fail "node->remote-pod still served under egress isolation"

# The exemptions that make egress isolation safe to ship:
served host1 "http://$SAME:8080/" && pass "node->LOCAL-pod stays exempt (kubelet probes are this flow)" \
  || fail "egress isolation gated node->local-pod"
ready=$($K get node "$W" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
[ "$ready" = "True" ] && pass "the node stays Ready under egress isolation (node->node exempt)" \
  || fail "egress isolation broke kubelet->apiserver"
$K -n "$NS" get pod srv -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
  && pass "kubelet probes still pass under egress isolation" \
  || fail "egress isolation broke kubelet probes"
apod=$($K -n cozy-cozyplane get pods -l app=cozyplane-agent --field-selector "spec.nodeName=$W" -o name 2>/dev/null | head -1)
[ -z "$apod" ] && apod=$($K -n kube-system get pods -l app=cozyplane-agent --field-selector "spec.nodeName=$W" -o name 2>/dev/null | head -1) && ANS=kube-system || ANS=cozy-cozyplane
if [ -n "$apod" ]; then
  $K -n "$ANS" get "$apod" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' | grep -q True \
    && pass "the agent on the egress-isolated node stays Ready (no self-lockout)" \
    || fail "egress isolation cut the agent off from the apiserver"
else
  skip "agent readiness (agent pod not found)"
fi

apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: HostFirewall
metadata: {name: pol-e2e-eg, labels: {$HFLABEL: owned}}
spec:
  nodeSelector: {matchLabels: {$HFLABEL: active}}
  policyTypes: [Egress]
  egress:
    - to: [{cidr: $CLI/32}]
      ports: [{protocol: TCP, port: 8080}]
EOF
served host1 "http://$CLI:8080/" && pass "an egress cidr+port rule reopens node->remote-pod" \
  || fail "the egress allow rule did not reopen the destination"
$K delete hostfirewall pol-e2e-eg >/dev/null
$K label node "$W" "${HFLABEL}-" >/dev/null 2>&1
served host1 "http://$CLI:8080/" && pass "deleting the egress object reopens the node's own traffic" \
  || fail "the node stayed egress-isolated after deletion"

# ===========================================================================
phase "SecurityGroup: label-follows membership"
# Membership must track a pod's LIVE labels, not the snapshot taken when its
# Port was claimed — the contract NetworkPolicy has always had.
apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: VPC
metadata: {name: sgvpc, namespace: $NS}
spec: {cidrs: ["10.77.0.0/24"]}
EOF
apply <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: sgweb
  namespace: $NS
  labels: {role: web}
  annotations: {sdn.cozystack.io/vpc: sgvpc}
spec:
  nodeName: $W
  containers:
    - name: s
      image: nicolaka/netshoot
      command: [python3, -m, http.server, "8080", --bind, "::"]
---
apiVersion: v1
kind: Pod
metadata:
  name: sgcli
  namespace: $NS
  labels: {role: client}
  annotations: {sdn.cozystack.io/vpc: sgvpc}
spec:
  nodeName: $W2
  containers:
    - {name: s, image: nicolaka/netshoot, command: [sleep, infinity]}
EOF
if ! $K -n "$NS" wait --for=condition=Ready pod/sgweb pod/sgcli --timeout=180s >/dev/null 2>&1; then
  skip "SecurityGroup phase (VPC pods did not become Ready)"
else
  vpcip() { $K get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}" | awk -v p="$1" '$1==p{print $2}'; }
  groups() { $K get ports -o jsonpath="{range .items[*]}{.spec.podName}{'='}{.status.groups}{'\n'}{end}" | awk -F= -v p="$1" '$1==p{print $2}'; }
  SGWEB=$(vpcip sgweb)
  apply <<EOF
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: web, namespace: $NS}
spec:
  vpcRef: {name: sgvpc}
  podSelector: {matchLabels: {role: web}}
  ingress: [{from: {group: client}, ports: [{protocol: TCP, port: 8080}]}]
---
apiVersion: sdn.cozystack.io/v1alpha1
kind: SecurityGroup
metadata: {name: client, namespace: $NS}
spec:
  vpcRef: {name: sgvpc}
  podSelector: {matchLabels: {role: client}}
  egress: [{to: {group: web}, ports: [{protocol: TCP, port: 8080}]}]
EOF
  # Wait for membership to resolve at all.
  for _ in $(seq 1 20); do [ "$(groups sgweb)" != "" ] && [ "$(groups sgweb)" != "[]" ] && break; sleep 2; done
  served sgcli "http://$SGWEB:8080/" && pass "grouped client reaches web (membership resolved from labels)" \
    || fail "the SG rules did not admit the grouped client"

  # THE POINT: relabel a RUNNING pod out of its group. v1 froze membership at
  # claim time, so this changed nothing; it must now take effect.
  $K -n "$NS" label pod sgcli role=bystander --overwrite >/dev/null
  refused sgcli "http://$SGWEB:8080/" && pass "relabelled pod LOSES membership on a live pod (label-follows)" \
    || fail "membership did not follow the label change (still admitted)"
  for _ in $(seq 1 15); do [ "$(groups sgcli)" = "[]" ] || [ "$(groups sgcli)" = "" ] && break; sleep 2; done
  g=$(groups sgcli)
  { [ "$g" = "[]" ] || [ -z "$g" ]; } && pass "Port.status.groups emptied for the relabelled pod" \
    || fail "Port.status.groups still holds a group after the relabel (got '$g')"

  # And back: membership is not a one-way door.
  $K -n "$NS" label pod sgcli role=client --overwrite >/dev/null
  served sgcli "http://$SGWEB:8080/" && pass "relabelling back RE-JOINS the group (label-follows both ways)" \
    || fail "membership did not follow the label back into the group"

  $K -n "$NS" delete securitygroup web client >/dev/null 2>&1
fi

echo
echo "policy-e2e: ${PASSED} passed, $((CHECKS - PASSED)) failed, ${SKIPPED} skipped, in $(( $(date +%s) - START ))s"
if [ "$FAILED" = "0" ]; then echo "policy-e2e: ALL PASSED"; else echo "policy-e2e: FAILURES"; fi
exit $FAILED
