# VPN operations scripts

`scripts/Test-ExpressVpnRoute.ps1` is a read-only Windows diagnostic. It checks
DNS resolution, the selected Windows route, and TCP reachability for the
Cozyplane ingress VIP. It never changes ExpressVPN configuration, Windows
routes, or application files.

```powershell
./scripts/Test-ExpressVpnRoute.ps1 -DnsName dashboard.example.internal,api.example.internal
./scripts/Test-ExpressVpnRoute.ps1 -DnsName dashboard.example.internal -AsJson
```

Provide the DNS names used in the target environment; no environment-specific
name is embedded in the script. It exits non-zero when a requested name does not
resolve, no route is selected, the selected route uses the known
VPN next hop (`10.0.8.1` by default), or TCP/443 is unavailable. Run it after
connecting the desktop VPN to capture its routing effect.

For the workstation fix, use ExpressVPN's split-tunneling/IP-subnet exclusion
to keep `172.16.0.0/16` outside the desktop tunnel, reconnect ExpressVPN, then
rerun the diagnostic. Prefer that application-owned exclusion over a persistent
Windows route: the VPN adapter and its metrics can change across reconnects.
The script intentionally stops at diagnosis because changing the signed-in VPN
client is a user-visible policy change.

For an explicitly requested, temporary Windows route, use
`scripts/Set-VpnBypassRoute.ps1`. It never changes VPN-client files or settings,
creates routes in `ActiveStore` only (they disappear at restart), and removes
only routes that exactly match the CIDR, interface, and gateway supplied.
Interface index, target gateway, excluded VPN gateway, and CIDRs are all
mandatory. Run the mutation from an elevated PowerShell session. Begin with
`-WhatIf`, which does not require elevation, then inspect its before/after
snapshots.

```powershell
./scripts/Set-VpnBypassRoute.ps1 -Mode Ensure -DestinationPrefix 172.16.0.0/16 `
  -InterfaceIndex 12 -NextHop 192.0.2.1 -ExcludedNextHop 198.51.100.1 -WhatIf

./scripts/Set-VpnBypassRoute.ps1 -Mode Remove -DestinationPrefix 172.16.0.0/16 `
  -InterfaceIndex 12 -NextHop 192.0.2.1 -ExcludedNextHop 198.51.100.1
```

Use the real adapter index and LAN gateway from the local machine; the addresses
above are documentation-only examples. The script refuses to use the excluded
VPN gateway and fails if Windows does not select the requested route after an
actual `Ensure` run. It does not remove competing routes it did not create.

`scripts/Invoke-VpnSoak.ps1` collects non-secret health, VPN resource state,
appliance metrics, and the result of a caller-provided traffic probe for 24
hours by default. `-Kctx` is mandatory; `-Kubeconfig` can pin a saved config,
and the script always passes both explicitly to `kubectl`. It creates only local result files and does not create cluster
resources unless an explicitly enabled setup script does so.

```powershell
./scripts/Invoke-VpnSoak.ps1 -Kctx lab-context `
  -Kubeconfig D:\path\to\lab-kubeconfig `
  -TrafficCommand kubectl,'--context','lab-context','-n','example','exec','probe','--','curl','--fail','http://10.0.0.10/'
```

The traffic command is an executable plus arguments, never a shell expression.
Use `-NoTraffic` only for an observability-only run. Results are JSON Lines in a
timestamped `vpn-soak-*` directory: `health.jsonl`, `metrics.jsonl`, and
`traffic.jsonl`, plus `summary.json`.

Setup and cleanup are opt-in. `-SetupScript` runs only with `-AllowSetup`;
`-CleanupScript` runs only with `-Cleanup`; `-Preserve` is mutually exclusive
with cleanup. Keep any resources created by a test setup by passing `-Preserve`
and omitting `-Cleanup`.
