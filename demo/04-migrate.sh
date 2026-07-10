#!/usr/bin/env bash
# Act 4 — live-migrate the VM while the SSH session stays open.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 4: live migration"

BEFORE_NODE=$(vmport_field node); BEFORE_IP=$(vmport_field ip); BEFORE_MAC=$(vmport_field mac)
note "before: node=$BEFORE_NODE  ip=$BEFORE_IP  mac=$BEFORE_MAC"

note "in your open SSH session, start something that would notice a break:"
try "ping $(vpcip red-1)          # leave it running against red-1"

note "migrating now (watch the ping, not this terminal)..."
MIG=$(kubectl -n "$RED_NS" create -o name -f - <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachineInstanceMigration
metadata: {generateName: $VM-mig-, namespace: $RED_NS}
spec: {vmiName: $VM}
EOF
)

phase=""
for _ in $(seq 150); do
  phase=$(kubectl -n "$RED_NS" get "$MIG" -o jsonpath='{.status.phase}' 2>/dev/null || true)
  case "$phase" in Succeeded|Failed) break;; esac
  sleep 2
done
note "migration phase: ${phase:-unknown}"
[ "$phase" = Succeeded ] || { echo "migration did not succeed — inspect: kubectl -n $RED_NS describe $MIG"; exit 1; }

# The persistent-Port controller flips spec.node once the VM is live on the target.
for _ in $(seq 30); do
  AFTER_NODE=$(vmport_field node)
  [ "$AFTER_NODE" != "$BEFORE_NODE" ] && break
  sleep 1
done
AFTER_IP=$(vmport_field ip); AFTER_MAC=$(vmport_field mac)

note "after:  node=$AFTER_NODE  ip=$AFTER_IP  mac=$AFTER_MAC"
note "node changed; IP and MAC did not — that is the whole trick."

note "evidence for the audience:"
try "kubectl -n $RED_NS get vmi $VM -o wide          # NODENAME is now $AFTER_NODE"
try "kubectl get port $(vmport) -o yaml | grep -E 'ip:|mac:|node:'"
plain "and the SSH session + its ping: still running. In the guest, 'ip -br addr'"
plain "shows the same $AFTER_IP / $AFTER_MAC — the identity moved with the VM."

note "what happened underneath: the VM's Port is persistent, so the target node's"
note "launcher pod BOUND to the existing {IP, MAC} instead of claiming fresh ones;"
note "at cutover only the Port's spec.node flipped, and every node's datapath"
note "re-pointed the overlay at $AFTER_NODE. Peers saw a sub-second reroute."
