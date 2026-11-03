#!/usr/bin/env bash
# Install an exact checked local image in the isolated guest, without global changes.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
IMAGE="${IMAGE:-cozyplane-ipsec:local}"
[[ "$IMAGE" == cozyplane-ipsec:local || "$IMAGE" == cozyplane-wireguard-client:local ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH=(bash "$ROOT/test/ipsec-vm-ssh.sh")
tar -C "$ROOT" -cf - test deploy config | "${SSH[@]}" 'tar -xf - -C /src'
archive=$(mktemp /tmp/cozyplane-ipsec-test/install-image-XXXXXX.tar)
trap 'rm -f -- "$archive" "$archive.configs.json"' EXIT
docker save "$IMAGE" > "$archive"
python3 "$ROOT/test/ipsec-image-configs.py" "$archive" > "$archive.configs.json"
expected=$(jq -r --arg image "$IMAGE" '.[$image]' "$archive.configs.json")
if ! zstd -c -1 -T2 "$archive" | "${SSH[@]}" 'zstd -d | docker load'; then
  actual=$("${SSH[@]}" "docker image inspect '$IMAGE' --format '{{.Id}}'")
  [[ "$actual" == "$expected" ]] || exit 1
  echo 'Import metadata warning; image config ID matches exactly.'
fi
actual=$("${SSH[@]}" "docker image inspect '$IMAGE' --format '{{.Id}}'")
[[ "$actual" == "$expected" ]] || exit 1
"${SSH[@]}" "cd /src; IMAGE='$IMAGE' FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh install"
