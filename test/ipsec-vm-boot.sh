#!/usr/bin/env bash
# Runs as PID1 only in the fixed disposable VM container.
set -euo pipefail
[[ "${HOSTNAME:-}" == cozyplane-ipsec-test-vm ]] || exit 2
[[ -f /vm/debian-12-generic-amd64.qcow2 && -f /vm/seed.iso ]] || exit 2
ACCEL="${VM_ACCEL:-kvm}"
case "$ACCEL" in kvm) CPU=host;; tcg) CPU=max;; *) exit 2;; esac
exec qemu-system-x86_64 -machine "q35,accel=$ACCEL" -cpu "$CPU" -smp 4 -m 6144 \
  -drive file=/vm/debian-12-generic-amd64.qcow2,format=qcow2,if=virtio \
  -drive file=/vm/seed.iso,media=cdrom \
  -nic user,model=virtio-net-pci,hostfwd=tcp:0.0.0.0:2222-:22 \
  -nographic -monitor none -serial file:/vm/console.log
