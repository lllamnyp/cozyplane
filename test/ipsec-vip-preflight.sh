#!/usr/bin/env bash
# Regression against the live public policy that exposed stale BYPASS matching.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
RUN=$1; [[ "$RUN" =~ ^[0-9]+-[0-9]+$ ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/tmp/cozyplane-ipsec-test/public-reports/results-$RUN
mkdir -p "$DEST"
bash "$ROOT/test/ipsec-vm-ssh.sh" "docker exec cozyplane-ipsec-peer-$RUN-5 ip xfrm policy" > "$DEST/vip-parser-real-policy.txt"
python3 "$ROOT/test/ipsec-vip-public.py" < "$DEST/vip-parser-real-policy.txt" | tee "$DEST/vip-parser-real-result.txt"
python3 "$ROOT/test/ipsec-vip-public-test.py" > "$DEST/vip-parser-regression.txt" 2>&1
