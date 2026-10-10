#!/usr/bin/env bash
# Reboot only the named disposable VM; bounded force fallback for stuck guest tasks.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-tools ]] || exit 2
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NAME=cozyplane-ipsec-test-vm
docker inspect "$NAME" | jq -e '.[0].Config.Hostname=="cozyplane-ipsec-test-vm" and .[0].Config.Labels["cozyplane.test"]=="ipsec"' >/dev/null
PUBLIC=/tmp/cozyplane-ipsec-test/public-reports/kernel-upgrade
mkdir -p "$PUBLIC"
ssh_guest() { timeout -k 2 12 bash "$ROOT/test/ipsec-vm-ssh.sh" "$@"; }
old=$(ssh_guest 'cat /proc/sys/kernel/random/boot_id')
printf '%s normal-guest-reboot-request\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$PUBLIC/reboot-events.txt"
ssh_guest 'systemctl reboot' >/dev/null 2>&1 || true
rebooted() {
  local current; current=$(ssh_guest 'cat /proc/sys/kernel/random/boot_id' 2>/dev/null) || return 1
  [[ -n "$current" && "$current" != "$old" ]]
}
deadline=$((SECONDS+45))
while ((SECONDS<deadline)); do rebooted && break; sleep 2; done
if ! rebooted; then
  printf '%s bounded-guest-shutdown-timeout-force-only-vm-container\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$PUBLIC/reboot-events.txt"
  docker restart --time 5 "$NAME" >/dev/null
fi
deadline=$((SECONDS+180))
while ! rebooted; do ((SECONDS<deadline)) || exit 1; sleep 2; done
printf '%s new-guest-boot-confirmed\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" >> "$PUBLIC/reboot-events.txt"
ssh_guest 'uname -r; cat /src/ipsec-kernel-upgrade-public.log' > "$PUBLIC/kernel-package.txt"
deadline=$((SECONDS+180))
while ! bash "$ROOT/test/ipsec-vm-ssh.sh" 'bash /src/test/ipsec-vm-kubeconfig.sh; KUBECONFIG=/tmp/cozyplane-ipsec-test/kubeconfig kubectl --context kind-cozyplane-ipsec-test wait --for=condition=Ready nodes --all --timeout=15s'; do
  ((SECONDS<deadline)) || exit 1
  sleep 2
done
cat "$PUBLIC/reboot-events.txt"
