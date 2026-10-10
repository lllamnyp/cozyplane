Set-StrictMode -Version Latest

function Test-VpnRouteRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$DestinationPrefix,
        [Parameter(Mandatory)][ValidateRange(1, [int]::MaxValue)][int]$InterfaceIndex,
        [Parameter(Mandatory)][System.Net.IPAddress]$NextHop,
        [Parameter(Mandatory)][System.Net.IPAddress]$ExcludedNextHop,
        [Parameter(Mandatory)][ValidateRange(1, 9999)][int]$RouteMetric
    )

    if ($NextHop.Equals($ExcludedNextHop)) {
        throw 'NextHop must not be the excluded VPN next hop.'
    }
    foreach ($prefix in $DestinationPrefix) {
        $parts = $prefix -split '/', 2
        if ($parts.Count -ne 2) { throw "Destination prefix '$prefix' must use CIDR notation." }
        $address = $null
        $length = 0
        if (-not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address) -or
            -not [int]::TryParse($parts[1], [ref]$length)) {
            throw "Destination prefix '$prefix' is invalid."
        }
        $maximumLength = if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        if ($length -lt 0 -or $length -gt $maximumLength) {
            throw "Destination prefix '$prefix' has an invalid prefix length."
        }
    }
}

function Get-VpnRouteSnapshot {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$DestinationPrefix)

    foreach ($prefix in $DestinationPrefix) {
        Get-NetRoute -PolicyStore ActiveStore -DestinationPrefix $prefix -ErrorAction SilentlyContinue |
            Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, InterfaceMetric, Protocol, State
    }
}

function Get-VpnRouteSelection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$DestinationPrefix)

    foreach ($prefix in $DestinationPrefix) {
        $address = ($prefix -split '/', 2)[0]
        Find-NetRoute -RemoteIPAddress $address -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric, InterfaceMetric |
            Select-Object -First 1 DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, InterfaceMetric
    }
}

Export-ModuleMember -Function Test-VpnRouteRequest, Get-VpnRouteSnapshot, Get-VpnRouteSelection
