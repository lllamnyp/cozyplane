#!/usr/bin/env bash
# Act 5 — an nginx pod in the VPC, and the HTTP check that reaches it.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 5: nginx in the red VPC — probed by kubelet, curled by peers"

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
EOF

kubectl -n "$RED_NS" wait --for=condition=Ready pod/web --timeout=120s >/dev/null

WEB_VPC=$(vpcip web); WEB_FABRIC=$(fabricip web); WEB_NODE=$(podnode "$RED_NS" web)

note "web is Ready on $WEB_NODE:"
try "kubectl -n $RED_NS get pod web -o wide"

note "READY 1/1 is itself the first demo: the readinessProbe is an HTTP GET"
note "made by KUBELET — a host process with no VPC membership at all. It probed"
note "status.podIP = $WEB_FABRIC, the pod's FABRIC address, and the node-side"
note "bridge translated that into the tenant interface. Two addresses, one pod:"
plain "fabric IP: $WEB_FABRIC   (the underlay handle — what Kubernetes sees)"
plain "VPC IP:    $WEB_VPC   (the tenant address — what VPC peers dial)"
try "kubectl get ports | grep web"

note "from inside the VPC, plain HTTP on the VPC IP:"
try "kubectl -n $RED_NS exec -it red-1 -- curl -s http://$WEB_VPC/ | head -4"

note "from the peered blue VPC — peering carries TCP, not just pings:"
try "kubectl -n $BLUE_NS exec -it blue-1 -- curl -s http://$WEB_VPC/ | head -4"

note "and from the VM, same thing (in your SSH session):"
try "curl -s http://$WEB_VPC/ | head -4"

note "so: kubelet probes keep working (Kubernetes stays happy), while the"
note "service itself is reachable only on tenant terms — VPC members and peers."
