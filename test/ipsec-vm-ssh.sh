#!/usr/bin/env bash
# Invoke guest commands from the fixed tooling container; no host credentials.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
VM=/tmp/cozyplane-ipsec-test/vm
exec ssh -i "$VM/ssh-key" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$VM/known_hosts" -o ConnectTimeout=10 -p 2222 root@cozyplane-ipsec-test-vm "$@"
