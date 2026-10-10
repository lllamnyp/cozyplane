#!/usr/bin/env bash
# Fixed isolated IPsec wrapper around the shared local provisioning workflow.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export FIXTURE_CLUSTER=cozyplane-ipsec-test
export TOOLS_CONTAINER=cozyplane-ipsec-test-tools
export FIXTURE_KIND_CONFIG="$ROOT/test/ipsec-kind.yaml"
export FIXTURE_ETCD_IMAGE=cozyplane-ipsec-test-etcd:local
export FIXTURE_SUITE="$ROOT/test/ipsec-e2e.sh"
exec bash "$ROOT/test/wireguard-client-local.sh" "$@"
