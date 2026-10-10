#!/usr/bin/env bash
# Export public reports only; never private fixtures, SSH keys or kubeconfigs.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/tmp/cozyplane-ipsec-test/public-reports
mkdir -p "$DEST"
bash "$ROOT/test/ipsec-vm-ssh.sh" 'cd /tmp/cozyplane-ipsec-test; find . -maxdepth 1 -type d -name "results-*" -print0 | tar --null -T - -cf -' | tar -xf - -C "$DEST"
for provenance in /tmp/cozyplane-ipsec-test/final-provenance /tmp/cozyplane-ipsec-test/final-provenance-*; do
  [[ -d "$provenance" ]] && cp -a "$provenance" "$DEST/"
done
echo "Public reports: $DEST"
