#!/usr/bin/env bash
# Explicit recovery action for the named disposable guest kind cluster only.
# Capture metadata first; this is cluster recreation, not successful SDN cleanup.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH=(bash "$ROOT/test/ipsec-vm-ssh.sh")
PUBLIC=/tmp/cozyplane-ipsec-test/public-reports/kernel-upgrade
mkdir -p "$PUBLIC"
"${SSH[@]}" 'KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig kubectl --context kind-cozyplane-ipsec-test get namespace ipsec-test-1791624009-25223 -o json' > "$PUBLIC/old-namespace-after-reboot.json" || true
"${SSH[@]}" 'KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig kubectl --context kind-cozyplane-ipsec-test -n kube-system get pods -o json' |
  jq '{items:[.items[]|{name:.metadata.name,uid:.metadata.uid,status:.status}]}' > "$PUBLIC/cluster-pod-status-after-reboot.json"
printf '%s own-kind-cluster-recreation-after-bounded-recovery\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$PUBLIC/reboot-events.txt"
# shellcheck disable=SC2016
"${SSH[@]}" 'test "$(hostname)" = ipsec-guest || exit 2; kind delete cluster --name cozyplane-ipsec-test'
bash "$ROOT/test/ipsec-vm-cluster.sh"
