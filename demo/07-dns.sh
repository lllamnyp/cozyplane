#!/usr/bin/env bash
# Act 7 — names inside a VPC: the split-horizon resolver at work.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 7: DNS inside the red VPC — same names, tenant answers"

# Self-sufficient: ensure act 5's web pod (idempotent re-apply), then attach
# two Services to the VPC — the same one annotation pods use.
quiet_apply <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: web
  namespace: $RED_NS
  labels: {app: web}
  annotations: {sdn.cozystack.io/vpc: $RED_VPC}
spec:
  containers:
    - name: nginx
      image: nginx:alpine
      ports: [{containerPort: 80}]
      readinessProbe:
        httpGet: {path: /, port: 80}
        periodSeconds: 2
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: $RED_NS
  annotations: {sdn.cozystack.io/vpc: $RED_VPC}
spec:
  selector: {app: web}
  ports: [{port: 80, targetPort: 80}]
---
apiVersion: v1
kind: Service
metadata:
  name: web-headless
  namespace: $RED_NS
  annotations: {sdn.cozystack.io/vpc: $RED_VPC}
spec:
  clusterIP: None
  selector: {app: web}
  ports: [{port: 80, targetPort: 80}]
EOF

kubectl -n "$RED_NS" wait --for=condition=Ready pod/web --timeout=120s >/dev/null

VIP=""
for _ in $(seq 30); do
  VIP=$(kubectl get servicevips -o jsonpath="{range .items[*]}{.spec.serviceRef.namespace}{'/'}{.spec.serviceRef.name}{' '}{.spec.ip}{'\n'}{end}" 2>/dev/null \
    | awk -v s="$RED_NS/web" '$1==s{print $2; exit}')
  [ -n "$VIP" ] && break
  sleep 2
done
[ -n "$VIP" ] || { echo "ServiceVIP for $RED_NS/web did not materialize"; exit 1; }

CLUSTER_IP=$(kubectl -n "$RED_NS" get svc web -o jsonpath='{.spec.clusterIP}')
WEB_VPC=$(vpcip web)
# The cluster domain (cluster.local, cozy.local, ...) — read it off a pod's
# own search path rather than assuming.
DOMAIN=$(kubectl -n "$RED_NS" exec red-1 -- sh -c \
  "sed -n 's/^search .*svc\.\([^ ]*\).*/\1/p' /etc/resolv.conf" 2>/dev/null)
DOMAIN=${DOMAIN:-cluster.local}

note "one annotation attached both Services to the VPC. The controller minted a"
note "VIP from the tenant's own space — compare the two views of the same name:"
plain "cluster's view:  web.$RED_NS.svc = $CLUSTER_IP   (kubectl get svc — the ClusterIP)"
plain "red VPC's view:  web.$RED_NS.svc = $VIP   (a ServiceVIP in 10.50.1.0/24)"
try "kubectl get servicevips"
echo
note "ask from inside the VPC — the resolver answers the tenant view:"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup web.$RED_NS.svc.$DOMAIN      # -> $VIP, never the ClusterIP"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup web-headless.$RED_NS.svc.$DOMAIN   # headless -> the pod's VPC IP, $WEB_VPC"
note "and the name is live — load-balanced in the datapath, per-flow pinned:"
try "kubectl -n $RED_NS exec -it red-1 -- curl -s http://web.$RED_NS/ | head -4"

note "the same tree is NOT the cluster's tree — everything a tenant may not see"
note "is authoritative NXDOMAIN, starting with the control plane itself:"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup kubernetes.default.svc.$DOMAIN   # NXDOMAIN"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup kube-dns.kube-system.svc.$DOMAIN  # NXDOMAIN"

note "while the rest of the world resolves as usual (forwarded upstream):"
try "kubectl -n $RED_NS exec -it red-1 -- nslookup example.com"

note "peering extends the view: blue consented to red (act 2), so blue-1 gets"
note "red's service names and can dial the VIP across the peering:"
try "kubectl -n $BLUE_NS exec -it blue-1 -- nslookup web.$RED_NS.svc.$DOMAIN"
try "kubectl -n $BLUE_NS exec -it blue-1 -- curl -s http://web.$RED_NS/ | head -4"

note "worth saying out loud:"
plain "- the pod's resolv.conf is stock Kubernetes; interception is in the"
plain "  datapath (dns_steer), so VMs get the same answers with zero config."
plain "- per-VPC views from ONE resolver: the query's rewritten source is the"
plain "  pod's identity handle — no per-tenant DNS pods."
plain "- an UNPEERED tenant sees none of this: red's names are NXDOMAIN there,"
plain "  and red's VIP lives in address space that may even overlap its own."
