#!/usr/bin/env bash
# Act 3 — a VM in the red VPC; SSH into it from a VPC pod.
cd "$(dirname "$0")" && . ./lib.sh

banner "Act 3: a VM joins the red VPC"

kubectl get crd virtualmachines.kubevirt.io >/dev/null 2>&1 \
  || { echo "KubeVirt is not installed on this cluster — acts 3 and 4 need it."; exit 1; }

kubectl apply -f - >/dev/null <<EOF
apiVersion: kubevirt.io/v1
kind: VirtualMachine
metadata:
  name: $VM
  namespace: $RED_NS
spec:
  runStrategy: Always
  template:
    metadata:
      labels: {app: $VM}
      annotations:
        sdn.cozystack.io/vpc: $RED_VPC
        kubevirt.io/allow-pod-bridge-network-live-migration: ""
    spec:
      domain:
        cpu: {cores: 1}
        memory: {guest: 2Gi}
        devices:
          disks:
            - {name: rootdisk, disk: {bus: virtio}}
            - {name: cloudinit, disk: {bus: virtio}}
          interfaces:
            - {name: default, bridge: {}}
      networks:
        - {name: default, pod: {}}
      volumes:
        - name: rootdisk
          containerDisk: {image: quay.io/containerdisks/fedora:42}
        - name: cloudinit
          cloudInitNoCloud:
            userData: |
              #cloud-config
              password: cozyplane
              chpasswd: {expire: false}
              ssh_pwauth: true
EOF

note "the VM attaches to the VPC exactly like a pod does — one annotation"
note "(sdn.cozystack.io/vpc: $RED_VPC) on the launcher pod template. Booting..."
kubectl -n "$RED_NS" wait vmi/"$VM" --for=condition=Ready --timeout=300s >/dev/null

VMIP=$(vmport_field ip); VMMAC=$(vmport_field mac); VMNODE=$(vmport_field node)
note "VM is up:"
plain "node:   $VMNODE"
plain "VPC IP: $VMIP"
plain "MAC:    $VMMAC   <- locally-administered, generated for THIS VM identity"

note "its network identity is a persistent Port — pinned to the VM, not to a pod:"
try "kubectl get port $(vmport) -o yaml | less   # spec.ip + spec.mac are the pinned pair"

note "SSH into it from red-1 (same VPC — no Ingress, no NodePort, no magic):"
try "kubectl -n $RED_NS exec -it red-1 -- ssh -o StrictHostKeyChecking=no fedora@$VMIP"
plain "password: cozyplane"

note "once in, look around — the guest sees only its tenant network:"
try "ip -br addr        # the VPC IP ($VMIP), MAC $VMMAC"
try "ping -c2 $(vpcip red-2)     # red-2, a container: VMs and pods are peers"

note "keep this SSH session open — act 4 migrates the VM under it."
