# VPN appliance containerDisk

This directory builds a small KubeVirt `containerDisk` wrapper around a pinned,
bootable cloud image. The guest runs a systemd dispatcher that starts one of the
existing Cozyplane VPN binaries; it does not contain peer configuration, private
keys, or customer data.

The builder deliberately requires a base-image URL and SHA-256. Use an
internally mirrored, immutable cloud image that includes systemd, kernel
WireGuard support, and strongSwan's `charon` binary. This keeps operating-system
selection outside the source tree and makes the chosen guest release explicit.

```bash
images/vpn-appliance/build-containerdisk.sh \
  --base-url https://mirror.invalid/images/pinned-cloud.qcow2 \
  --base-sha256 REPLACE_WITH_64_HEX_SHA256 \
  --tag registry.example.invalid/cozyplane/vpn-appliance:REPLACE_ME
```

Before a production build, run `--check` to verify the local image-builder
dependencies. The VM manifest in
[`../../examples/kubevirt/vpn-appliance`](../../examples/kubevirt/vpn-appliance)
uses the resulting image. It requires a real KubeVirt cluster to validate boot
or live migration; a container build alone cannot validate either.
