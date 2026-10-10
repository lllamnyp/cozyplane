#!/usr/bin/env bash
# Dedicated Docker Desktop fixture; never uses the current Kubernetes context.
set -euo pipefail
CLUSTER="${FIXTURE_CLUSTER:-cozyplane-wg-client}"
case "$CLUSTER" in cozyplane-wg-client|cozyplane-ipsec-test) ;; *) exit 2;; esac
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="/tmp/$CLUSTER/kubeconfig"
KIND_CONFIG="${FIXTURE_KIND_CONFIG:-$ROOT/test/wireguard-client-kind.yaml}"
ETCD_IMAGE="${FIXTURE_ETCD_IMAGE:-cozyplane-wg-client-etcd:local}"
mkdir -p "$(dirname "$KUBECONFIG")"
K=(kubectl --context "kind-$CLUSTER")
case "${1:-}" in
  create)
    if kind get clusters | grep -qx "$CLUSTER"; then
      echo "Dedicated cluster already exists; reuse only via install/run." >&2; exit 2
    fi
    kind create cluster --name "$CLUSTER" --image kindest/node:v1.34.3 --config "$KIND_CONFIG" --kubeconfig "$KUBECONFIG"
    # Linux tooling container reaches the API on kind's own private Docker network.
    if [[ "${FIXTURE_HOST_RUNNER:-0}" != 1 ]]; then
      docker network connect kind "${TOOLS_CONTAINER:-cozyplane-wg-client-tools}"
    fi
    kind get kubeconfig --name "$CLUSTER" --internal > "$KUBECONFIG"
    if [[ "${FIXTURE_HOST_RUNNER:-0}" == 1 ]]; then
      control_ip=$(docker inspect "$CLUSTER-control-plane" -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}')
      sed -i "s#https://$CLUSTER-control-plane:6443#https://$control_ip:6443#" "$KUBECONFIG"
    fi
    chmod 600 "$KUBECONFIG"
    ;;
  install)
    IMAGE="${IMAGE:?Set IMAGE to the new product image}"
    kind load docker-image "$IMAGE" --name "$CLUSTER"
    docker build --platform linux/amd64 -t "$ETCD_IMAGE" -f "$ROOT/test/wireguard-client-etcd.Dockerfile" "$ROOT/test"
    kind load docker-image "$ETCD_IMAGE" --name "$CLUSTER"
    "${K[@]}" apply -f "$ROOT/config/crd/"
    sed -e "s#ghcr.io/lllamnyp/cozyplane:dev#$IMAGE#g" -e "s#registry.k8s.io/etcd:3.5.16-0#$ETCD_IMAGE#g" "$ROOT/deploy/apiserver.yaml" | "${K[@]}" apply -f -
    # Agent's host-network init installs the CNI before the API's fabric pods
    # can schedule. Its tenant informers retry until the API comes online.
    for f in agent controller authz; do
      sed "s#ghcr.io/lllamnyp/cozyplane:dev#$IMAGE#g" "$ROOT/deploy/$f.yaml" | "${K[@]}" apply -f -
    done
    # A developer may rebuild the same local tag; restart after importing it so
    # existing pods also execute the new digest rather than retaining the old one.
    "${K[@]}" -n kube-system rollout restart deployment/cozyplane-apiserver deployment/cozyplane-controller daemonset/cozyplane-agent
    "${K[@]}" -n kube-system rollout status deployment/cozyplane-apiserver --timeout=300s
    "${K[@]}" -n kube-system rollout status daemonset/cozyplane-agent --timeout=300s
    "${K[@]}" -n kube-system rollout status deployment/cozyplane-controller --timeout=300s
    "${K[@]}" wait --for=condition=Ready nodes --all --timeout=180s
    ;;
  run)
    export KCTX="kind-$CLUSTER"
    exec bash "${FIXTURE_SUITE:-$ROOT/test/wireguard-client-e2e.sh}"
    ;;
  delete)
    # Only this fixed dedicated name may be destroyed.
    kind delete cluster --name "$CLUSTER"
    ;;
  *) echo "Usage: $0 create|install|run|delete" >&2; exit 2;;
esac
