#!/usr/bin/env bash
# Prepare an isolated Debian guest; credentials stay outside public artifacts.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
VM=/tmp/cozyplane-ipsec-test/vm
mkdir -p "$VM"; chmod 700 "$VM"
url=https://cloud.debian.org/images/cloud/bookworm/latest
curl --retry 3 --connect-timeout 20 -fsSL "$url/SHA512SUMS" -o "$VM/SHA512SUMS"
curl --retry 3 --connect-timeout 20 -fsSL "$url/debian-12-generic-amd64.qcow2" -o "$VM/debian-12-generic-amd64.qcow2"
(cd "$VM"; grep ' debian-12-generic-amd64.qcow2$' SHA512SUMS | sha512sum -c -)
qemu-img resize "$VM/debian-12-generic-amd64.qcow2" 40G
ssh-keygen -q -t ed25519 -N '' -C ephemeral-ipsec-test -f "$VM/ssh-key"
cat > "$VM/user-data" <<EOF
#cloud-config
hostname: ipsec-guest
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$VM/ssh-key.pub")
package_update: true
packages:
  - docker.io
  - curl
  - ca-certificates
  - jq
  - python3
  - openssl
  - iproute2
  - iputils-ping
  - iperf3
  - strongswan-swanctl
runcmd:
  - [systemctl, enable, --now, docker]
  - [modprobe, xfrm_interface]
  - [sh, -c, "echo 1 > /proc/sys/net/ipv4/ip_forward"]
  - [sh, -c, "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"]
  - [sh, -c, "touch /root/ipsec-guest-ready"]
EOF
printf '%s\n' 'instance-id: cozyplane-ipsec-test-vm' 'local-hostname: ipsec-guest' > "$VM/meta-data"
cloud-localds "$VM/seed.iso" "$VM/user-data" "$VM/meta-data"
chmod 600 "$VM"/*
echo 'Dedicated guest disk, cloud-init seed and private SSH identity prepared.'
