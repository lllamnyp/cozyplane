#!/usr/bin/env bash
# Lightweight continuation after importing images; avoids a repeated VM bootstrap.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH=(bash "$ROOT/test/ipsec-vm-ssh.sh")
IMAGE="${IMAGE:-cozyplane-ipsec:local}"
[[ "$IMAGE" == cozyplane-ipsec:local || "$IMAGE" == cozyplane-wireguard-client:local ]] || exit 2
tar -C "$ROOT" -cf - test deploy config | "${SSH[@]}" 'tar -xf - -C /src'
"${SSH[@]}" "cd /src; FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh create; IMAGE='$IMAGE' bash test/ipsec-local.sh install"
