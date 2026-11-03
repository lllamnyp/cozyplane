#!/usr/bin/env bash
# Transfer only source/public product images; private SSH material stays in tools.
# Remote shell expressions must expand in the guest.
# shellcheck disable=SC2016
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SSH=(bash "$ROOT/test/ipsec-vm-ssh.sh")
deadline=$((SECONDS+900))
until "${SSH[@]}" test -f /root/ipsec-guest-ready 2>/dev/null; do
  ((SECONDS<deadline)) || { echo 'Guest cloud-init did not finish in15minutes.' >&2; exit 1; }
  sleep 5
done
"${SSH[@]}" 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zstd git >/dev/null; mkdir -p /src /tmp/cozyplane-ipsec-test; uname -r; grep CONFIG_XFRM_INTERFACE /boot/config-$(uname -r); ip link add probe0 type xfrm if_id 99; ip link delete probe0'
tar -C "$ROOT" --exclude='./.*' --exclude=./bin --exclude=./cni --exclude=./kpr --exclude=node_modules --exclude=__pycache__ -cf - . | "${SSH[@]}" 'tar -xf - -C /src'
tar -C /usr/local/bin -cf - kubectl kind helm | "${SSH[@]}" 'tar -xf - -C /usr/local/bin'
tar -C /usr/local -cf - go | "${SSH[@]}" 'tar -xf - -C /usr/local; ln -sf /usr/local/go/bin/go /usr/local/bin/go'
git -C "$ROOT" rev-parse HEAD | "${SSH[@]}" 'cat > /tmp/cozyplane-ipsec-test/source-revision.txt'
IMAGE="${IMAGE:-cozyplane-ipsec:local}"
[[ "$IMAGE" == cozyplane-ipsec:local || "$IMAGE" == cozyplane-wireguard-client:local ]] || exit 2
images=(kindest/node:v1.34.3 "$IMAGE" cozyplane-ipsec-test-bench:local cozyplane-ipsec-test-etcd:local)
archive=$(mktemp /tmp/cozyplane-ipsec-test/provision-images-XXXXXX.tar)
trap 'rm -f -- "$archive" "$archive.configs.json"' EXIT
docker save "${images[@]}" > "$archive"
python3 "$ROOT/test/ipsec-image-configs.py" "$archive" > "$archive.configs.json"
if ! zstd -c -1 -T2 "$archive" | "${SSH[@]}" 'zstd -d | docker load'; then
  # Docker20.10 can import the actual single-platform image before complaining
  # about DockerDesktop's trailing OCI metadata. Accept only exact config IDs.
  for image in "${images[@]}"; do
    expected=$(jq -r --arg image "$image" '.[$image]' "$archive.configs.json")
    actual=$("${SSH[@]}" "docker image inspect '$image' --format '{{.Id}}'")
    [[ "$actual" == "$expected" ]] || exit 1
  done
  echo 'Guest image import metadata warning; every actual image config ID verified.'
fi
for image in "${images[@]}"; do
  expected=$(jq -r --arg image "$image" '.[$image]' "$archive.configs.json")
  actual=$("${SSH[@]}" "docker image inspect '$image' --format '{{.Id}}'")
  [[ "$actual" == "$expected" ]] || exit 1
done
kernel=$("${SSH[@]}" uname -r)
IFS=. read -r major minor _ <<< "$kernel"
if ((major<6 || (major==6 && minor<6))); then
  echo 'Guest source/images/tools ready. Upgrade this guest to >=6.6 for TCX, reboot, then run ipsec-vm-cluster.sh.'
  exit 0
fi
"${SSH[@]}" "cd /src; FIXTURE_HOST_RUNNER=1 bash test/ipsec-local.sh create; IMAGE='$IMAGE' bash test/ipsec-local.sh install"
echo 'Guest product cluster prepared; benchmark start still requires a frozen image.'
