#!/usr/bin/env bash
# Act 6 — open the red VPC's door to the outside world (per-VPC NAT gateway).
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 6: internet egress for the red VPC"

note "right now the red VPC has NO egress — worth proving live from red-1:"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup example.com    # DNS WORKS (node-local resolver forwards upstream)"
try "kubectl -n $RED_NS exec -it red-1 -- wget -qO- -T4 http://example.com   # ...but the connection DIES (no route out)"
note "that split is the design: names are answered by a per-node resolver,"
note "but packets leave a VPC only through a door the tenant asked for."
echo
read -r -p "        [press Enter to open the door: one flag on the VPC]" || true

kubectl -n "$RED_NS" patch vpc "$RED_VPC" --type=merge -p '{"spec":{"egress":{"natGateway":true}}}' >/dev/null
note "patched: spec.egress.natGateway=true — the controller now spawns a gateway pod"

GWNS=""; GWPOD=""
for _ in $(seq 40); do
  read -r GWNS GWPOD <<<"$(kubectl get pods -A -l "app=cozyplane-gateway,sdn.cozystack.io/vpc=$RED_VPC" \
    --no-headers -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status' 2>/dev/null \
    | awk '$3=="True"{print $1, $2; exit}')"
  [ -n "$GWPOD" ] && break
  sleep 3
done
[ -n "$GWPOD" ] || { echo "gateway pod did not become Ready"; exit 1; }

GWIP=$(kubectl get ports -o jsonpath="{range .items[*]}{.spec.vpcRef.name}{' '}{.spec.gateway}{' '}{.spec.ip}{'\n'}{end}" \
  | awk -v v="$RED_VPC" '$1==v && $2=="true" {print $3; exit}')

note "the door, as objects:"
plain "gateway pod:  $GWNS/$GWPOD"
plain "gateway Port: $GWIP inside the VPC (the .1 — tenants route off-VPC traffic here)"
try "kubectl get ports | grep gateway    # or: kubectl -n $GWNS get pod $GWPOD -o wide"

note "same commands from red-1 — the wget that just died now works:"
try "kubectl -n $RED_NS exec -it red-1 -- wget -qO- -T4 http://example.com"
try "kubectl -n $RED_NS exec -it red-1 -- ping -c3 1.1.1.1"
try "kubectl -n $RED_NS exec -it red-1 -- curl -s ifconfig.me   # the public IP the world sees (the node's, via masquerade)"

note "worth saying out loud:"
plain "- the door is one-way and internet-only: the gateway refuses the cluster's"
plain "  pod/service/internal CIDRs, so it is never a side door INTO the cluster"
plain "  (cluster DNS :53 is the single exception)."
plain "- it is per-VPC and opt-in: blue still has no egress right now."
plain "- inbound is a different feature by design — nothing reaches these pods"
plain "  until someone hands them a FloatingIP."
