#!/usr/bin/env bash
# Build a KubeVirt containerDisk image from a caller-pinned cloud image.
#
# Required host tools: docker, qemu-img and virt-customize (libguestfs-tools).
# The base image digest is an input rather than a floating URL: callers pin the
# guest OS release themselves and this script refuses a mismatched download.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  build-containerdisk.sh --base-url URL --base-sha256 SHA256 --tag IMAGE[:TAG] [options]

Options:
  --output DIR       Build context directory (default: ./out/vpn-containerdisk)
  --gateway-bin PATH Prebuilt WireGuard gateway binary
  --ipsec-bin PATH   Prebuilt IPsec gateway binary
  --check            Check host prerequisites and Containerfile syntax only

The generated image is a KubeVirt containerDisk. It contains no VPN peer
configuration or secret; cloud-init supplies /etc/cozyplane-vpn/config.json at
boot. The image starts the WireGuard backend by default; set VPN_BACKEND=ipsec
in that cloud-init configuration to select strongSwan/IPsec.
EOF
}

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
output="$root/out/vpn-containerdisk"
base_url=""
base_sha256=""
tag=""
gateway_bin=""
ipsec_bin=""
check=false

while (($#)); do
  case "$1" in
  --base-url) base_url=$2; shift 2 ;;
  --base-sha256) base_sha256=$2; shift 2 ;;
  --tag) tag=$2; shift 2 ;;
  --output) output=$2; shift 2 ;;
  --gateway-bin) gateway_bin=$2; shift 2 ;;
  --ipsec-bin) ipsec_bin=$2; shift 2 ;;
  --check) check=true; shift ;;
  -h|--help) usage; exit 0 ;;
  *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

for command in docker qemu-img virt-customize sha256sum; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 127; }
done
docker build --check -f "$root/images/vpn-appliance/Containerfile" "$root/images/vpn-appliance"
if $check; then
  exit 0
fi

[[ -n "$base_url" && -n "$base_sha256" && -n "$tag" ]] || { usage >&2; exit 64; }
[[ "$base_sha256" =~ ^[[:xdigit:]]{64}$ ]] || { echo "--base-sha256 must be a SHA-256 digest" >&2; exit 64; }

if [[ -z "$gateway_bin" ]]; then
  gateway_bin="$output/cozyplane-vpn-gateway"
  mkdir -p "$output"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$gateway_bin" ./cmd/vpn-gateway)
fi
if [[ -z "$ipsec_bin" ]]; then
  ipsec_bin="$output/cozyplane-vpn-gateway-ipsec"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$ipsec_bin" ./cmd/vpn-gateway-ipsec)
fi
[[ -x "$gateway_bin" && -x "$ipsec_bin" ]] || { echo "VPN binaries must be executable" >&2; exit 64; }

mkdir -p "$output"
base_disk="$output/base.qcow2"
disk="$output/disk.img"
curl --fail --location --retry 3 --output "$base_disk" "$base_url"
printf '%s  %s\n' "$base_sha256" "$base_disk" | sha256sum --check --status || { echo "base image checksum mismatch" >&2; exit 1; }

# The guest remains immutable except for the explicit service, dispatcher and
# binaries. The base image must already provide systemd, WireGuard support and
# strongSwan's charon binary for the IPsec backend.
virt-customize -a "$base_disk" \
  --mkdir /etc/cozyplane-vpn \
  --mkdir /usr/local/libexec \
  --upload "$gateway_bin:/usr/local/bin/cozyplane-vpn-gateway" \
  --upload "$ipsec_bin:/usr/local/bin/cozyplane-vpn-gateway-ipsec" \
  --upload "$root/images/vpn-appliance/vpn-appliance-start:/usr/local/libexec/cozyplane-vpn-appliance-start" \
  --upload "$root/images/vpn-appliance/vpn-appliance.service:/etc/systemd/system/cozyplane-vpn-appliance.service" \
  --chmod 0755:/usr/local/bin/cozyplane-vpn-gateway \
  --chmod 0755:/usr/local/bin/cozyplane-vpn-gateway-ipsec \
  --chmod 0755:/usr/local/libexec/cozyplane-vpn-appliance-start \
  --run-command 'systemctl enable cozyplane-vpn-appliance.service'
qemu-img convert -p -f qcow2 -O raw "$base_disk" "$disk"

# Use a dedicated, minimal build context so neither a secret nor a local binary
# can accidentally enter the OCI layer.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
cp "$root/images/vpn-appliance/Containerfile" "$stage/Containerfile"
cp "$disk" "$stage/disk.img"
docker build --file "$stage/Containerfile" --tag "$tag" "$stage"
docker image inspect "$tag" --format '{{index .Config.Labels "org.opencontainers.image.title"}}' >/dev/null || true
echo "built $tag; record the resulting digest before using it in a VirtualMachine"
