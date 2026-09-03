# KubeVirt VPN appliance example

This is a deployment baseline, not a migration claim. It uses a pod bridge
interface and KubeVirt's live-migration annotation, which lets Cozyplane retain
the VM's persistent Port identity across a move.

Before applying:

1. Replace the namespace, VPC, container image and RWX storage class in the
   manifests.
2. Create the `VPNGateway`/`VPNConnection` or equivalent route and forwarding
   objects for that VPC; this example does not create control-plane objects.
3. Create `vpn-appliance-cloud-init` in the same namespace. Its `userdata` must
   write `/etc/cozyplane-vpn/backend` (`VPN_BACKEND=wireguard` or `ipsec`) and
   `/etc/cozyplane-vpn/config.json` with the secret VPN configuration.
4. Apply `state-pvc.yaml`, wait for it to bind, then apply `vm.yaml`.

The PVC is explicitly RWX because source and target must both access it during a
live migration. The pod network uses bridge binding because masquerade binding
cannot preserve the guest's network identity. Validate `LiveMigratable=True`,
guest boot, the VPN service, and a real `virtctl migrate` on a KubeVirt cluster;
none of those are validated by this static example.
