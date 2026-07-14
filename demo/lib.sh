# Shared plumbing for the live demo. Sourced, not executed.
# Every script acts on the cluster kubectl currently points at
# (KUBECONFIG + current-context) — nothing is hardcoded to a cluster.
set -euo pipefail

RED_NS=demo-red   RED_VPC=red   RED_CIDR=10.50.1.0/24
BLUE_NS=demo-blue BLUE_VPC=blue BLUE_CIDR=10.50.2.0/24
VM=demo-vm

MAGENTA=$'\e[1;35m'; CYAN=$'\e[1;36m'; YELLOW=$'\e[1;33m'; OFF=$'\e[0m'

banner() { printf '\n%s== %s ==%s\n' "$MAGENTA" "$*" "$OFF"; }
note()   { printf '%s  » %s%s\n' "$CYAN" "$*" "$OFF"; }
try()    { printf '%s        %s%s\n' "$YELLOW" "$*" "$OFF"; }  # a command for YOU, the presenter
plain()  { printf '        %s\n' "$*"; }

# Ports (cluster-scoped) are the source of truth for a pod's addresses.
vpcip()    { kubectl get ports -o jsonpath="{range .items[*]}{.spec.podName}{' '}{.spec.ip}{'\n'}{end}"       | awk -v p="$1" '$1==p {print $2; exit}'; }
# The fabric address lives in the FabricIP object (local.sdn.cozystack.io), not on
# the Port -- Port.spec.fabricIP was normalized away. status.podIP IS the fabric IP.
fabricip() { kubectl -n "${2:-$RED_NS}" get pod "$1" -o jsonpath='{.status.podIP}'; }
podnode()  { kubectl -n "$1" get pod "$2" -o jsonpath='{.spec.nodeName}'; }

# The VM's persistent Port carries the pinned identity; select it by VM name.
vmport()      { kubectl get ports -l "sdn.cozystack.io/vm-name=$VM" -o jsonpath='{.items[0].metadata.name}'; }
vmport_field(){ kubectl get ports -l "sdn.cozystack.io/vm-name=$VM" -o jsonpath="{.items[0].spec.$1}"; }

# Two distinct Ready nodes, for pinning pods so the overlay actually crosses nodes.
two_nodes() {
  kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
    | awk '$2=="True"{print $1}' | head -2
}

# kubectl apply with the warn-mode PodSecurity chatter filtered out.
quiet_apply() { kubectl apply -f - >/dev/null 2> >(grep -v 'PodSecurity' >&2 || true); }

netshoot_pod() { # netshoot_pod <ns> <name> <node> <vpc>
  quiet_apply <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $2
  namespace: $1
  annotations: {sdn.cozystack.io/vpc: $4}
spec:
  nodeName: $3
  containers:
    - name: net
      image: nicolaka/netshoot:latest
      command: ["sleep", "infinity"]
EOF
}
