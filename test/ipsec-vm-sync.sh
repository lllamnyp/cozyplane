#!/usr/bin/env bash
# Refresh harness/public deployment inputs only; root source remains the build source.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tar -C "$ROOT" -cf - test deploy config | bash "$ROOT/test/ipsec-vm-ssh.sh" 'tar -xf - -C /src'
tar -C "$ROOT" -cf - api bpf cmd config datapath deploy internal pkg chart Dockerfile go.mod go.sum | bash "$ROOT/test/ipsec-vm-ssh.sh" 'tar -xf - -C /src'
git -C "$ROOT" rev-parse HEAD | bash "$ROOT/test/ipsec-vm-ssh.sh" 'mkdir -p /tmp/cozyplane-ipsec-test; cat > /tmp/cozyplane-ipsec-test/source-revision.txt'
