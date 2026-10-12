#!/usr/bin/env bash
# Create only the named disposable VM; refuse to overwrite existing resources.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VM=/tmp/cozyplane-ipsec-test/vm
NAME=cozyplane-ipsec-test-vm
VOLUME=cozyplane-ipsec-test-vm-disk
[[ -f "$VM/debian-12-generic-amd64.qcow2" && -f "$VM/seed.iso" ]] || exit 2
if docker inspect "$NAME" >/dev/null 2>&1 || docker volume inspect "$VOLUME" >/dev/null 2>&1; then
  echo 'Dedicated VM/container volume already exists; refusing to overwrite it.' >&2; exit 2
fi
docker build -t cozyplane-ipsec-test-vm:local -f "$ROOT/test/ipsec-vm.Dockerfile" "$ROOT/test"
docker volume create --label cozyplane.test=ipsec "$VOLUME" >/dev/null
docker create --name "$NAME" --hostname "$NAME" --label cozyplane.test=ipsec --device /dev/kvm --memory 8g --cpus 4 --network kind --mount "type=volume,source=$VOLUME,target=/vm" cozyplane-ipsec-test-vm:local >/dev/null
docker cp "$VM/debian-12-generic-amd64.qcow2" "$NAME:/vm/"
docker cp "$VM/seed.iso" "$NAME:/vm/"
docker start "$NAME"
