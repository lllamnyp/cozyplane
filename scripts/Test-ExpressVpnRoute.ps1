[CmdletBinding()]
param(
    [string]$Destination = '172.16.255.253',
    [string[]]$DnsName = @(),
    [int]$Port = 443,
    [string]$UnexpectedNextHop = '10.0.8.1',
    [int]$TcpTimeoutSeconds = 5,
    [switch]$AsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-TcpEndpoint {
    param([string]$Address, [int]$TcpPort, [int]$TimeoutSeconds)

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connect = $client.BeginConnect($Address, $TcpPort, $null, $null)
        $connected = $connect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds))
        if ($connected) {
            $client.EndConnect($connect)
        }
        return $connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

$dnsResults = foreach ($name in $DnsName) {
    try {
        $addresses = Resolve-DnsName -Name $name -Type A -ErrorAction Stop |
            Where-Object { $_.IPAddress } |
            Select-Object -ExpandProperty IPAddress -Unique
        [pscustomobject]@{ Name = $name; Addresses = @($addresses); Error = $null }
    } catch {
        [pscustomobject]@{ Name = $name; Addresses = @(); Error = $_.Exception.Message }
    }
}

$route = Find-NetRoute -RemoteIPAddress $Destination -ErrorAction SilentlyContinue |
    Sort-Object -Property RouteMetric, InterfaceMetric |
    Select-Object -First 1

$routeResult = if ($route) {
    $interface = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily $route.AddressFamily -ErrorAction SilentlyContinue
    [pscustomobject]@{
        DestinationPrefix = $route.DestinationPrefix
        NextHop           = $route.NextHop
        InterfaceIndex    = $route.InterfaceIndex
        InterfaceAlias    = $interface.InterfaceAlias
        RouteMetric       = $route.RouteMetric
        InterfaceMetric   = $route.InterfaceMetric
        UsesUnexpectedHop = $route.NextHop -eq $UnexpectedNextHop
    }
} else {
    $null
}

$result = [pscustomobject]@{
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    Destination  = $Destination
    Port         = $Port
    Dns          = @($dnsResults)
    Route        = $routeResult
    TcpReachable = Test-TcpEndpoint -Address $Destination -TcpPort $Port -TimeoutSeconds $TcpTimeoutSeconds
}

if ($AsJson) {
    $result | ConvertTo-Json -Depth 5
} else {
    $result
}

if (-not $routeResult) {
    Write-Host "No Windows route was selected for $Destination." -ForegroundColor Red
    exit 2
}
if (@($dnsResults | Where-Object { $_.Error -or $_.Addresses.Count -eq 0 }).Count -gt 0) {
    Write-Host 'At least one requested DNS name did not resolve to an IPv4 address.' -ForegroundColor Red
    exit 1
}
if ($routeResult.UsesUnexpectedHop) {
    Write-Host "The selected route uses unexpected next hop $UnexpectedNextHop." -ForegroundColor Red
    exit 3
}
if (-not $result.TcpReachable) {
    Write-Host "TCP $Destination`:$Port is unreachable." -ForegroundColor Red
    exit 4
}
