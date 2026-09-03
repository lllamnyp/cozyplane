[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)][ValidateSet('Ensure', 'Remove')][string]$Mode,
    [Parameter(Mandatory)][string[]]$DestinationPrefix,
    [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$InterfaceIndex,
    [Parameter(Mandatory)][System.Net.IPAddress]$NextHop,
    [Parameter(Mandatory)][System.Net.IPAddress]$ExcludedNextHop,
    [ValidateRange(1, 9999)][int]$RouteMetric = 5,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module NetTCPIP -DisableNameChecking -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot 'VpnRoute.Common.psm1') -Force

Test-VpnRouteRequest -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex `
    -NextHop $NextHop -ExcludedNextHop $ExcludedNextHop -RouteMetric $RouteMetric

$before = @(Get-VpnRouteSnapshot -DestinationPrefix $DestinationPrefix)
$changes = @()
foreach ($prefix in $DestinationPrefix) {
    $matching = @(Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -eq $InterfaceIndex -and $_.NextHop -eq $NextHop.IPAddressToString })
    if ($Mode -eq 'Ensure' -and $matching.Count -eq 0) {
        if ($PSCmdlet.ShouldProcess("$prefix via $NextHop on interface $InterfaceIndex", 'Create active VPN bypass route')) {
            New-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -InterfaceIndex $InterfaceIndex `
                -NextHop $NextHop.IPAddressToString -RouteMetric $RouteMetric -ErrorAction Stop | Out-Null
            $changes += "created $prefix"
        } else { $changes += "would create $prefix" }
    } elseif ($Mode -eq 'Remove' -and $matching.Count -gt 0) {
        foreach ($route in $matching) {
            if ($PSCmdlet.ShouldProcess("$prefix via $NextHop on interface $InterfaceIndex", 'Remove active VPN bypass route')) {
                $route | Remove-NetRoute -Confirm:$false -ErrorAction Stop
                $changes += "removed $prefix"
            } else { $changes += "would remove $prefix" }
        }
    } else {
        $changes += "unchanged $prefix"
    }
}

$after = @(Get-VpnRouteSnapshot -DestinationPrefix $DestinationPrefix)
$selection = @(Get-VpnRouteSelection -DestinationPrefix $DestinationPrefix)
$result = [pscustomobject]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    Mode = $Mode
    WhatIf = [bool]$WhatIfPreference
    DestinationPrefix = $DestinationPrefix
    InterfaceIndex = $InterfaceIndex
    NextHop = $NextHop.IPAddressToString
    ExcludedNextHop = $ExcludedNextHop.IPAddressToString
    Before = $before
    Changes = $changes
    After = $after
    Selection = $selection
}
if ($AsJson) { $result | ConvertTo-Json -Depth 6 } else { $result }

if (-not $WhatIfPreference -and $Mode -eq 'Ensure') {
    foreach ($route in $selection) {
        if ($null -eq $route -or $route.NextHop -eq $ExcludedNextHop.IPAddressToString -or $route.InterfaceIndex -ne $InterfaceIndex) {
            throw 'The requested route was not selected after creation. Inspect the reported Before/After state and remove it explicitly if required.'
        }
    }
}
