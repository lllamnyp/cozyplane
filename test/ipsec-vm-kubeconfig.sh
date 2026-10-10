#!/usr/bin/env bash
# Repair only this guest's isolated kubeconfig for use from its Docker host.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
export KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig
mkdir -p /tmp/cozyplane-ipsec-test
ip=$(docker inspect cozyplane-ipsec-test-control-plane -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
kind get kubeconfig --name cozyplane-ipsec-test --internal | sed "s#https://cozyplane-ipsec-test-control-plane:6443#https://$ip:6443#" > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
kubectl --context kind-cozyplane-ipsec-test get nodes
