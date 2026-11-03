#!/usr/bin/env bash
# Installation only inside the dedicated disposable Linux tooling container.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq clang llvm libbpf-dev docker.io iproute2 iputils-ping iperf3 jq strongswan strongswan-swanctl libstrongswan-extra-plugins libcharon-extra-plugins python3 tcpdump shellcheck curl ca-certificates procps qemu-system-x86 qemu-utils cloud-image-utils openssh-client genisoimage zstd git >/dev/null
curl -fsSL https://dl.k8s.io/release/v1.35.3/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl
curl -fsSL https://kind.sigs.k8s.io/dl/v0.31.0/kind-linux-amd64 -o /usr/local/bin/kind
curl -fsSL https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz | tar -xz -C /tmp
install /tmp/linux-amd64/helm /usr/local/bin/helm
chmod 755 /usr/local/bin/kubectl /usr/local/bin/kind
go version
kind version
kubectl version --client
