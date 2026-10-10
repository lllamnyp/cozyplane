#!/usr/bin/env bash
# TCX plus the upstream XFRM deletion fix; isolated guest only, never WSL.
set -euo pipefail
[[ "$(hostname)" == ipsec-guest ]] || exit 2
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
candidate=$(apt-cache policy linux-image-6.12-amd64 | awk '/Candidate:/ {print $2}')
dpkg --compare-versions "$candidate" ge '6.12.101-1~deb12u1' || { echo 'Official security kernel lacks required XFRM fix' >&2; exit 1; }
apt-get install -y -qq --no-install-recommends linux-image-6.12-amd64 'linux-image-6.12.111+deb12-amd64=6.12.111-1~deb12u1'
dpkg-query -W -f='${Package} ${Version}\n' linux-image-6.12-amd64 linux-image-6.12.111+deb12-amd64
echo 'Official security kernel installed; restart only this dedicated guest.'
